package app

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
)

// mihomo binds the VPN's own connections to the network card (IP_UNICAST_IF)
// so that they leave by it and not by the tunnel. Windows honours that only
// while the card uses the strong host model. With forwarding or "weak host
// send" on — Internet Connection Sharing and the mobile hotspot switch
// forwarding on, so do some tweaks and programs — Windows picks the best
// route for every packet, and the best route is the tunnel: the VPN sends its
// own packets to itself, mihomo drops them ("reject loopback connection"),
// and nothing works, DNS and subscriptions included. WireGuard for Windows
// warns about exactly this. Лазейка switches those flags off on the network
// cards while the VPN is on and puts them back afterwards; the saved state is
// on disk, so after a crash the next start repairs it.

// hostFix is a card whose flags Лазейка switched off (true = was on).
type hostFix struct {
	Index      int    `json:"index"`
	Name       string `json:"name"`
	Forwarding bool   `json:"forwarding"`
	WeakSend   bool   `json:"weak_send"`
}

// netOps is what the fix needs from the system (replaced in tests).
type netOps struct {
	routes func() []platform.RouteIface
	model  func(idx int) (platform.HostModel, bool)
	set    func(idx int, forwarding, weakSend *bool) error
	byName func(name string) int
}

func systemNetOps() netOps {
	return netOps{
		routes: func() []platform.RouteIface { return platform.DefaultRoutes(TunName) },
		model:  platform.InterfaceHostModel,
		set:    platform.SetHostFlags,
		byName: func(name string) int {
			if ifc, err := net.InterfaceByName(name); err == nil {
				return ifc.Index
			}
			return 0
		},
	}
}

type netFix struct {
	mu     sync.Mutex
	ops    netOps
	path   string
	active bool // the VPN is on: keep the flags off
	saved  []hostFix
	loaded bool
	failed map[int]bool // could not switch off: not again this session
}

func newNetFix(path string, ops netOps) *netFix { return &netFix{path: path, ops: ops} }

// begin switches the flags off for a VPN session. It returns the cards it
// changed (as "«Ethernet»") and what failed.
func (f *netFix) begin() ([]string, []error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = true
	f.failed = map[int]bool{}
	return f.applyLocked()
}

// recheck repeats the fix during the session: sharing switches forwarding
// back on when the network changes.
func (f *netFix) recheck() ([]string, []error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.active {
		return nil, nil
	}
	return f.applyLocked()
}

// end puts the cards back as they were (also what a crashed run left).
func (f *netFix) end() ([]string, []error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = false
	return f.restoreLocked()
}

func (f *netFix) applyLocked() ([]string, []error) {
	f.loadLocked()
	var changed []string
	var errs []error
	for _, r := range f.ops.routes() {
		if !r.Bindable() || f.failed[r.Index] {
			continue
		}
		hm, ok := f.ops.model(r.Index)
		if !ok || (!hm.Forwarding && !hm.WeakSend) {
			continue
		}
		name := r.Name
		if name == "" {
			name = hm.Name
		}
		// remember the original state on disk before touching anything
		rec := f.findLocked(r.Index, name)
		if rec == nil {
			f.saved = append(f.saved, hostFix{Index: r.Index, Name: name})
			rec = &f.saved[len(f.saved)-1]
		}
		rec.Forwarding = rec.Forwarding || hm.Forwarding
		rec.WeakSend = rec.WeakSend || hm.WeakSend
		if err := f.saveLocked(); err != nil {
			errs = append(errs, fmt.Errorf("не удалось сохранить настройки сети: %w", err))
			continue
		}
		off := false
		var fw, ws *bool
		if hm.Forwarding {
			fw = &off
		}
		if hm.WeakSend {
			ws = &off
		}
		if err := f.ops.set(r.Index, fw, ws); err != nil {
			errs = append(errs, fmt.Errorf("не удалось выключить пересылку пакетов на «%s»: %w", name, err))
			if f.failed != nil {
				f.failed[r.Index] = true
			}
			continue
		}
		changed = append(changed, "«"+name+"»")
	}
	return changed, errs
}

func (f *netFix) restoreLocked() ([]string, []error) {
	f.loadLocked()
	if len(f.saved) == 0 {
		return nil, nil
	}
	var restored []string
	var errs []error
	var keep []hostFix // failed to set: try again at the next start
	for _, h := range f.saved {
		idx := h.Index
		if hm, ok := f.ops.model(idx); !ok || (h.Name != "" && hm.Name != "" && hm.Name != h.Name) {
			// the card got another number (or is gone)
			idx = 0
			if h.Name != "" {
				idx = f.ops.byName(h.Name)
			}
		}
		if idx == 0 {
			errs = append(errs, fmt.Errorf("не нашла сетевую карту «%s», чтобы вернуть ей пересылку пакетов", h.Name))
			continue
		}
		on := true
		var fw, ws *bool
		if h.Forwarding {
			fw = &on
		}
		if h.WeakSend {
			ws = &on
		}
		if err := f.ops.set(idx, fw, ws); err != nil {
			errs = append(errs, fmt.Errorf("не удалось вернуть пересылку пакетов на «%s»: %w", h.Name, err))
			keep = append(keep, h)
			continue
		}
		restored = append(restored, "«"+h.Name+"»")
	}
	f.saved = keep
	if len(keep) > 0 {
		if err := f.saveLocked(); err != nil {
			errs = append(errs, err)
		}
	} else if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	return restored, errs
}

func (f *netFix) findLocked(idx int, name string) *hostFix {
	for i := range f.saved {
		if f.saved[i].Index == idx && f.saved[i].Name == name {
			return &f.saved[i]
		}
	}
	return nil
}

// loadLocked reads what a previous run saved (once).
func (f *netFix) loadLocked() {
	if f.loaded {
		return
	}
	f.loaded = true
	b, err := os.ReadFile(f.path)
	if err != nil {
		return
	}
	var saved []hostFix
	if json.Unmarshal(b, &saved) == nil {
		f.saved = append(saved, f.saved...)
	}
}

func (f *netFix) saveLocked() error {
	b, err := json.MarshalIndent(f.saved, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// joinQuoted turns ["«a»", "«b»"] into "«a» и «b»".
func joinQuoted(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " и " + names[len(names)-1]
}

// --- the app side -------------------------------------------------------------

// beginNetFix runs before mihomo starts with the TUN.
func (a *App) beginNetFix() {
	if !platform.IsWindows || a.Dev {
		return
	}
	changed, errs := a.nf.begin()
	for _, err := range errs {
		logx.Warnf("%v", err)
	}
	if len(changed) == 0 {
		return
	}
	logx.Warnf("на %s была включена пересылка пакетов: с ней Windows отправляет соединения самого VPN обратно в туннель, и ничего не работает. "+
		"Пересылку включают общий доступ к интернету (ICS), мобильный хот-спот и некоторые программы. "+
		"Пока VPN включён, Лазейка держит её выключенной, а при отключении VPN вернёт как было", joinQuoted(changed))
	go a.explainForwarding()
}

// recheckNetFix: during the session (the watcher and the loop handler).
func (a *App) recheckNetFix() []string {
	if !platform.IsWindows || a.Dev {
		return nil
	}
	changed, errs := a.nf.recheck()
	for _, err := range errs {
		logx.Warnf("%v", err)
	}
	if len(changed) > 0 {
		// sharing may switch it back on again and again: say so now and then
		a.mu.Lock()
		say := time.Since(a.refixSaid) > 10*time.Minute
		if say {
			a.refixSaid = time.Now()
		}
		a.mu.Unlock()
		if say {
			logx.Warnf("пересылка пакетов на %s снова включилась (так делает общий доступ к интернету при смене сети) — снова выключила, пока работает VPN", joinQuoted(changed))
		}
	}
	return changed
}

// endNetFix puts the network cards back; why says why it happens now ("" =
// the VPN was switched off).
func (a *App) endNetFix(why string) {
	if !platform.IsWindows || a.Dev {
		return
	}
	restored, errs := a.nf.end()
	for _, err := range errs {
		logx.Warnf("%v", err)
	}
	if len(restored) == 0 {
		return
	}
	if why != "" {
		logx.Infof("%s: вернула пересылку пакетов на %s", why, joinQuoted(restored))
	} else {
		logx.Infof("VPN выключен: вернула пересылку пакетов на %s", joinQuoted(restored))
	}
}

// explainForwarding says who switched forwarding on, when it can tell.
func (a *App) explainForwarding() {
	pub, priv, err := platform.SharedConnections()
	if err != nil {
		logx.Debugf("общий доступ к интернету: %v", err)
	}
	if len(pub) > 0 || len(priv) > 0 {
		logx.Infof("общий доступ к интернету (ICS) включён: %s", describeSharing(pub, priv))
	}
	if platform.Service("icssvc").Running {
		logx.Infof("работает служба мобильного хот-спота")
	}
}

func describeSharing(pub, priv []string) string {
	q := func(names []string) string {
		out := make([]string, len(names))
		for i, n := range names {
			out[i] = "«" + n + "»"
		}
		return joinQuoted(out)
	}
	switch {
	case len(pub) > 0 && len(priv) > 0:
		return fmt.Sprintf("интернет %s раздаётся на %s", q(pub), q(priv))
	case len(pub) > 0:
		return "раздаётся интернет " + q(pub)
	default:
		return "раздача на " + q(priv)
	}
}

// checkOtherVPN notices another VPN that took the default route: two VPNs at
// once get in each other's way (its kill switch blocks Лазейка, or Лазейка's
// connections go into its tunnel).
func (a *App) checkOtherVPN(notify bool) {
	if !platform.IsWindows || a.Dev {
		return
	}
	var names []string
	for _, r := range platform.DefaultRoutes(TunName) {
		if r.OtherVPN() && r.Name != "" {
			names = append(names, "«"+r.Name+"»")
		}
	}
	msg := ""
	if len(names) > 0 {
		msg = fmt.Sprintf("Подключён другой VPN: %s. Отключите его в его приложении — два VPN одновременно мешают друг другу, и Лазейка может не работать.", joinQuoted(names))
	}
	a.mu.Lock()
	prev := a.otherVPN
	a.otherVPN = msg
	a.mu.Unlock()
	if msg != "" && msg != prev {
		logx.Warnf("%s", msg)
		if notify && a.tray != nil {
			a.tray.Notify("Лазейка: мешает другой VPN", msg, true)
		}
	} else if msg == "" && prev != "" {
		logx.Infof("другой VPN отключён")
	}
}

// loopHints tells what to switch off when the VPN's connections still come
// back into the tunnel and there is nothing left Лазейка can fix itself.
func (a *App) loopHints() string {
	var h []string
	if pub, priv, _ := platform.SharedConnections(); len(pub) > 0 || len(priv) > 0 {
		h = append(h, "выключите общий доступ к интернету ("+describeSharing(pub, priv)+"): Win+R → ncpa.cpl → правой кнопкой по подключению → Свойства → Доступ → снимите первую галочку")
	}
	if platform.Service("icssvc").Running {
		h = append(h, "выключите мобильный хот-спот (Параметры → Сеть и Интернет)")
	}
	a.mu.Lock()
	other := a.otherVPN
	a.mu.Unlock()
	if other != "" {
		h = append(h, "отключите другой VPN")
	}
	if c := a.zapretConflicts(); len(c) > 0 {
		h = append(h, "закройте другие программы обхода блокировок ("+strings.Join(c, ", ")+"): кнопка на вкладке zapret")
	}
	if len(h) == 0 {
		h = append(h, "проверьте, нет ли другого VPN или программы обхода блокировок, и выключите в антивирусе проверку защищённых соединений (Kaspersky, ESET, Dr.Web) или добавьте Лазейку в исключения")
	}
	return "Что сделать: " + strings.Join(h, "; ") + "."
}
