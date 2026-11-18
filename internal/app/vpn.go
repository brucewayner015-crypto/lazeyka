package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazeyka/internal/core"
	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
	"lazeyka/internal/update"
)

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (a *App) configPath() string { return filepath.Join(a.P.MihomoHome, "config.yaml") }

// Connect starts (or restarts) mihomo with the current settings.
func (a *App) Connect() error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	err := a.connectLocked()
	if err != nil {
		logx.Errorf("VPN: %v", err)
	}
	return err
}

func (a *App) connectLocked() error {
	if a.mihomo.Running() {
		a.stopTraffic()
		a.mihomo.Stop()
	}
	a.setVPN("connecting", "")
	a.mu.Lock()
	a.loop.reset(time.Now(), 0)
	a.loopMsg = ""
	a.autoTestAt = time.Time{} // a new mihomo knows no delays yet
	a.mu.Unlock()
	fail := func(err error) error {
		if platform.IsAndroid {
			a.releaseAndroidTun(true)
		}
		a.endNetFix("")
		a.setVPN("error", err.Error())
		return err
	}
	if a.Settings().Zapret.PauseWithVPN == "on" && a.zr.Running() {
		// this computer re-routes zapret's packets into the tunnel
		a.zr.Stop()
		a.setZapret("paused", pausedText)
	}
	if !a.Dev && !platform.IsElevated() {
		return fail(errors.New("нужны права администратора: запустите Лазейку через ярлык"))
	}
	if err := a.ensureMihomo(); err != nil {
		return fail(err)
	}
	s := a.Settings()
	rt := core.Runtime{
		APIPort:         freePort(),
		Secret:          s.Secret,
		DirectSocksPort: freePort(),
		VPNSocksPort:    freePort(),
		ExitSocksPort:   freePort(),
		SocksUser:       "lz",
		SocksPass:       settings.RandomHex(10),
		TunEnabled:      !a.Dev,
		TunName:         TunName,
		ZapretActive:    a.zr.Running(),
		HWID:            a.hwid(s.HWIDSalt),
	}
	if platform.IsAndroid {
		rt.Android, rt.TunFD, rt.TunName = true, 3, ""
		if a.dpiInstalled() && a.frontPort > 0 {
			rt.DPIPort = a.frontPort // mihomo talks to the front, the front to ByeDPI
		}
	}
	if rt.APIPort == 0 || rt.DirectSocksPort == 0 {
		return fail(errors.New("не удалось выделить локальные порты"))
	}
	b, err := core.Build(s, rt)
	if err != nil {
		return fail(err)
	}
	if err := a.writeConfig(b); err != nil {
		return fail(fmt.Errorf("не удалось записать конфиг: %w", err))
	}
	a.prefetchRules(s)
	if err := a.mihomo.Test(a.configPath()); err != nil {
		return fail(err)
	}
	if rt.TunEnabled && platform.IsAndroid {
		if err := a.openAndroidTun(s); err != nil {
			return fail(err)
		}
	} else if rt.TunEnabled {
		a.checkOtherVPN(true)
		a.beginNetFix()
	}
	if err := a.mihomo.Start(a.configPath()); err != nil {
		return fail(err)
	}
	if platform.IsAndroid {
		a.releaseAndroidTun(false) // mihomo holds the interface now
	}
	api := core.NewAPI(rt.APIPort, rt.Secret)
	if err := core.WaitReady(a.ctx, api, a.mihomo, 25*time.Second); err != nil {
		a.mihomo.Stop()
		return fail(err)
	}
	a.mu.Lock()
	a.built, a.rt, a.api = b, rt, api
	a.mu.Unlock()
	a.applySelections(s, b)
	_ = a.update(func(s *settings.Settings) error { s.App.WasConnected = true; return nil })
	a.setVPN("on", "")
	a.startTraffic(api)
	if !b.HasVPN {
		logx.Warnf("VPN включён без серверов: работает только маршрутизация и zapret")
	}
	if d := a.netDiag(); d != "" {
		logx.Infof("%s", d)
	}
	return nil
}

// Disconnect stops mihomo.
func (a *App) Disconnect() {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.disconnectLocked()
	_ = a.update(func(s *settings.Settings) error { s.App.WasConnected = false; return nil })
}

func (a *App) disconnectLocked() {
	a.stopTraffic()
	a.mihomo.Stop()
	if platform.IsAndroid {
		a.releaseAndroidTun(true)
	}
	a.endNetFix("")
	a.mu.Lock()
	a.api, a.built = nil, nil
	a.loopMsg, a.otherVPN = "", ""
	a.exit = exitState{}
	a.mu.Unlock()
	a.setVPN("off", "") // also brings a paused zapret back
}

// Connected reports whether mihomo is up.
func (a *App) Connected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.vpn == "on" || a.vpn == "connecting"
}

// Apply rebuilds and restarts mihomo if it is running.
func (a *App) Apply() error {
	if !a.Connected() {
		return nil
	}
	return a.Connect()
}

var (
	reapplyMu      sync.Mutex
	reapplyRunning bool // a goroutine is (about to be) applying
	reapplyDirty   bool // settings changed since it started
)

// ApplyAsync restarts mihomo in the background. Requests are coalesced: a
// burst of changes (or ones made while a restart waits for the lock) leads
// to one restart with the latest settings, not one per change — every
// restart drops all connections and, on Android, rebuilds the VPN interface.
func (a *App) ApplyAsync() {
	reapplyMu.Lock()
	reapplyDirty = true
	if reapplyRunning {
		reapplyMu.Unlock()
		return
	}
	reapplyRunning = true
	reapplyMu.Unlock()
	go func() {
		for {
			time.Sleep(400 * time.Millisecond)
			reapplyMu.Lock()
			if !reapplyDirty {
				reapplyRunning = false
				reapplyMu.Unlock()
				return
			}
			reapplyDirty = false
			reapplyMu.Unlock()
			if err := a.Apply(); err != nil {
				logx.Errorf("применение настроек: %v", err)
			}
		}
	}()
}

func (a *App) writeConfig(b *core.Built) error {
	if err := os.MkdirAll(filepath.Join(a.P.MihomoHome, "providers"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(a.P.MihomoHome, "rules"), 0o755); err != nil {
		return err
	}
	// drop provider files of removed servers
	if ents, err := os.ReadDir(filepath.Join(a.P.MihomoHome, "providers")); err == nil {
		for _, e := range ents {
			rel := "providers/" + e.Name()
			if strings.HasPrefix(e.Name(), "own-") {
				if _, keep := b.Files[rel]; !keep {
					os.Remove(filepath.Join(a.P.MihomoHome, "providers", e.Name()))
				}
			}
		}
	}
	for rel, data := range b.Files {
		if err := os.WriteFile(filepath.Join(a.P.MihomoHome, filepath.FromSlash(rel)), data, 0o600); err != nil {
			return err
		}
	}
	return os.WriteFile(a.configPath(), b.Config, 0o600)
}

// prefetchRules makes sure every rule set has a file before mihomo starts.
// Missing ones get the copy built into Лазейка, stamped with the snapshot
// date: mihomo then sees them as stale and fetches fresh lists by itself
// (through the VPN once it works). No waiting for GitHub here: from Russia
// it is often unreachable without a VPN.
func (a *App) prefetchRules(s *settings.Settings) {
	var copied, missing []string
	for name, u := range core.RuleURLs(s.Routing.HODCA) {
		p := filepath.Join(a.P.MihomoHome, filepath.FromSlash(core.RuleFilePath(name)))
		if st, err := os.Stat(p); err == nil && st.Size() > 0 {
			continue
		}
		if data, ok := core.RuleSnapshot(name); ok {
			if err := os.WriteFile(p, data, 0o644); err == nil {
				_ = os.Chtimes(p, core.RuleSnapshotDate, core.RuleSnapshotDate)
				copied = append(copied, name)
				continue
			}
		}
		// no built-in copy: try to download it now
		ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
		data, err := update.Fetch(ctx, directClient(15*time.Second), u, 32<<20)
		cancel()
		if err == nil && len(data) > 0 && os.WriteFile(p, data, 0o644) == nil {
			continue
		}
		missing = append(missing, name)
	}
	if len(copied) > 0 {
		sort.Strings(copied)
		logx.Infof("списки маршрутизации (%s): встроенная копия от %s, свежие mihomo скачает сам",
			strings.Join(copied, ", "), core.RuleSnapshotDate.Local().Format("02.01.2006"))
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		logx.Warnf("нет списков %s — mihomo попробует скачать их сам", strings.Join(missing, ", "))
	}
}

func directClient(timeout time.Duration) *http.Client {
	// a generous handshake timeout: some providers slow foreign TLS down a lot
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 25 * time.Second}}
}

func socksClient(u *url.URL, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: http.ProxyURL(u), TLSHandshakeTimeout: 25 * time.Second}}
}

// directProxyURL routes app traffic straight out (bypassing routing rules but
// still through zapret) while mihomo's TUN is up.
func (a *App) directProxyURL() *url.URL {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.api == nil || a.rt.DirectSocksPort == 0 {
		return nil
	}
	return &url.URL{Scheme: "socks5", User: url.UserPassword(a.rt.SocksUser, a.rt.SocksPass), Host: "127.0.0.1:" + strconv.Itoa(a.rt.DirectSocksPort)}
}

// vpnProxyURL routes app traffic through the VPN.
func (a *App) vpnProxyURL() *url.URL {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.api == nil || a.built == nil || !a.built.HasVPN || a.rt.VPNSocksPort == 0 {
		return nil
	}
	return &url.URL{Scheme: "socks5", User: url.UserPassword(a.rt.SocksUser, a.rt.SocksPass), Host: "127.0.0.1:" + strconv.Itoa(a.rt.VPNSocksPort)}
}

// exitProxyURL goes the way blocked sites go (the BLOCKED group).
func (a *App) exitProxyURL() *url.URL {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.api == nil || a.built == nil || !a.built.HasVPN || a.rt.ExitSocksPort == 0 {
		return nil
	}
	return &url.URL{Scheme: "socks5", User: url.UserPassword(a.rt.SocksUser, a.rt.SocksPass), Host: "127.0.0.1:" + strconv.Itoa(a.rt.ExitSocksPort)}
}

// downloadClients: direct first, then through the VPN if it is up.
func (a *App) downloadClients(timeout time.Duration) []*http.Client {
	cs := []*http.Client{directClient(timeout)}
	if u := a.vpnProxyURL(); u != nil {
		cs = append(cs, socksClient(u, timeout))
	}
	return cs
}

func (a *App) applySelections(s *settings.Settings, b *core.Built) {
	a.mu.Lock()
	api := a.api
	a.mu.Unlock()
	if api == nil {
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	for _, g := range []string{core.GYouTube, core.GDiscord, core.GMessengers, core.GAI, core.GOther} {
		if def, ok := b.Defaults[g]; ok {
			_ = api.Select(ctx, g, def)
		}
	}
	target := core.GAuto
	if s.Routing.BlockedSelect != "" {
		target = s.Routing.BlockedSelect
	}
	if err := api.Select(ctx, core.GBlocked, target); err != nil && target != core.GAuto {
		logx.Warnf("выбранный вручную сервер «%s» не найден, использую авто", target)
		_ = api.Select(ctx, core.GBlocked, core.GAuto)
	}
}

func (a *App) startTraffic(api *core.API) {
	ctx, cancel := context.WithCancel(a.ctx)
	a.mu.Lock()
	a.trafficCancel = cancel
	b := a.built
	a.mu.Unlock()
	if b != nil {
		go a.keepProviders(ctx, api, b)
	}
	go func() {
		for ctx.Err() == nil {
			_ = api.StreamTraffic(ctx, func(up, down int64) {
				a.mu.Lock()
				a.up, a.down = up, down
				a.mu.Unlock()
			})
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
}

// keepProviders retries what mihomo gives up on too easily. A subscription
// that did not load (its host blocked, the VPN not up yet) is retried every
// minute for the first ten minutes, then every 15; by then the fetch group
// has noticed the blocked direct path and goes through an own server.
// Routing lists older than two days (the built-in copy) are refreshed every
// half hour until mihomo manages to download them.
func (a *App) keepProviders(ctx context.Context, api *core.API, b *core.Built) {
	start := time.Now()
	wait := 20 * time.Second
	var lastRules time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if time.Since(start) > 10*time.Minute {
			wait = 15 * time.Minute
		} else {
			wait = time.Minute
		}
		c, cancel := context.WithTimeout(ctx, 90*time.Second)
		if len(b.SubProvider) > 0 {
			if provs, err := api.Providers(c); err == nil {
				names := a.subNames()
				for id, pname := range b.SubProvider {
					pv, ok := provs[pname]
					if !ok || len(pv.Proxies) > 0 {
						continue
					}
					if err := api.UpdateProvider(c, pname); err != nil {
						logx.Warnf("подписка «%s» не загрузилась: %v", names[id], err)
						continue
					}
					logx.Infof("подписка «%s» загружена", names[id])
					_ = api.HealthCheckProvider(c, pname)
				}
			}
		}
		if time.Since(lastRules) > 30*time.Minute {
			if rps, err := api.RuleProviders(c); err == nil {
				stale := 0
				for name, rp := range rps {
					t, err := time.Parse(time.RFC3339Nano, rp.UpdatedAt)
					if err == nil && time.Since(t) < 48*time.Hour {
						continue
					}
					stale++
					if err := api.UpdateRuleProvider(c, name); err == nil {
						logx.Infof("список %s обновлён", name)
					}
				}
				if stale > 0 {
					lastRules = time.Now()
				}
			}
		}
		cancel()
	}
}

func (a *App) subNames() map[string]string {
	m := map[string]string{}
	for _, sub := range a.Settings().Subscriptions {
		m[sub.ID] = sub.Name
	}
	return m
}

func (a *App) stopTraffic() {
	a.mu.Lock()
	c := a.trafficCancel
	a.trafficCancel = nil
	a.up, a.down = 0, 0
	a.mu.Unlock()
	if c != nil {
		c()
	}
}

func (a *App) onMihomoExit(err error, uptime time.Duration, lastErr string) {
	a.mu.Lock()
	state := a.vpn
	now := time.Now()
	var recent []time.Time
	for _, t := range a.reconnects {
		if now.Sub(t) < 3*time.Minute {
			recent = append(recent, t)
		}
	}
	a.reconnects = recent
	a.mu.Unlock()
	if state != "on" {
		return
	}
	msg := "mihomo неожиданно завершился"
	if lastErr != "" {
		msg += ": " + lastErr
	}
	if len(recent) >= 4 {
		a.stopTraffic()
		if platform.IsAndroid {
			a.releaseAndroidTun(true) // a dead interface would swallow all traffic
		}
		a.endNetFix("")
		a.setVPN("error", msg+" (несколько раз подряд)")
		return
	}
	a.mu.Lock()
	a.reconnects = append(a.reconnects, now)
	a.mu.Unlock()
	a.setVPN("connecting", msg)
	go func() {
		time.Sleep(2 * time.Second)
		a.mu.Lock()
		still := a.vpn == "connecting"
		a.mu.Unlock()
		if !still { // the user switched VPN off (or on) meanwhile
			return
		}
		_ = a.Connect() // logs its own errors
	}()
}

// --- views for the UI ---------------------------------------------------------

// OptionView is a selectable member of a group.
type OptionView struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // group | own | sub | direct | reject
	Delay int    `json:"delay"`
	Alive bool   `json:"alive"`
}

// GroupView is a routing group.
type GroupView struct {
	Name    string       `json:"name"`
	Label   string       `json:"label"`
	Type    string       `json:"type"`
	Now     string       `json:"now"`
	Exit    string       `json:"exit"` // final node after nested groups
	Options []OptionView `json:"options"`
}

func (a *App) apiOrErr() (*core.API, *core.Built, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.api == nil || a.built == nil {
		return nil, nil, errors.New("VPN выключен")
	}
	return a.api, a.built, nil
}

func labelOf(name string) string {
	if l, ok := core.GroupLabels[name]; ok {
		return l
	}
	return name
}

func kindOf(name string, p core.ProxyInfo, own map[string]bool) string {
	switch {
	case name == "DIRECT" || name == "COMPATIBLE":
		return "direct"
	case name == "REJECT":
		return "reject"
	case core.GroupLabels[name] != "" || len(p.All) > 0:
		return "group"
	case own[name]:
		return "own"
	}
	return "sub" // subscription names carry whatever label the user chose
}

// resolveExit follows nested groups to the real node.
func resolveExit(proxies map[string]core.ProxyInfo, name string) string {
	for i := 0; i < 8; i++ {
		p, ok := proxies[name]
		if !ok || p.Now == "" {
			return name
		}
		name = p.Now
	}
	return name
}

// Groups returns the user-facing routing groups with live state.
func (a *App) Groups() ([]GroupView, error) { return a.groups(5 * time.Second) }

func (a *App) groups(timeout time.Duration) ([]GroupView, error) {
	api, b, err := a.apiOrErr()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()
	proxies, err := api.Proxies(ctx)
	if err != nil {
		return nil, err
	}
	own := map[string]bool{}
	for _, n := range b.NodeName {
		own[n] = true
	}
	var out []GroupView
	untested := 0
	for _, g := range append([]string{core.GAuto}, b.Groups...) {
		p, ok := proxies[g]
		if !ok {
			continue
		}
		gv := GroupView{Name: g, Label: labelOf(g), Type: p.Type, Now: p.Now, Exit: resolveExit(proxies, g)}
		for _, m := range p.All {
			mp := proxies[m]
			o := OptionView{
				Name: m, Label: labelOf(m), Kind: kindOf(m, mp, own),
				Delay: mp.LastDelay(), Alive: mp.Alive,
			}
			if (o.Kind == "own" || o.Kind == "sub") && len(mp.History) == 0 {
				untested++
			}
			gv.Options = append(gv.Options, o)
		}
		out = append(out, gv)
	}
	if untested > 0 {
		a.autoTest()
	}
	return out, nil
}

// autoTest checks servers nobody has checked yet. mihomo checks the
// subscription only while it is in use, so its servers would show no delay
// at all; at most once every five minutes, in the background.
func (a *App) autoTest() {
	a.mu.Lock()
	if a.autoTesting || time.Since(a.autoTestAt) < 5*time.Minute {
		a.mu.Unlock()
		return
	}
	a.autoTesting, a.autoTestAt = true, time.Now()
	a.mu.Unlock()
	go func() {
		defer func() {
			a.mu.Lock()
			a.autoTesting = false
			a.mu.Unlock()
		}()
		_ = a.TestDelays()
	}()
}

// Select chooses an option in a group and remembers it in settings.
func (a *App) Select(group, name string) error {
	api, _, err := a.apiOrErr()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	if err := api.Select(ctx, group, name); err != nil {
		return err
	}
	_ = api.CloseConnections(ctx) // move existing connections to the new route
	return a.update(func(s *settings.Settings) error {
		r := &s.Routing
		direct := name == "DIRECT"
		switch group {
		case core.GYouTube:
			if direct {
				if r.YouTube != settings.ModeDirect {
					r.YouTube = settings.ModeZapret
				}
			} else {
				r.YouTube = settings.ModeVPN
			}
		case core.GDiscord:
			if direct {
				r.Discord = settings.ModeZapret
			} else {
				r.Discord = settings.ModeVPN
			}
		case core.GMessengers:
			if direct {
				r.Messengers = settings.ModeDirect
			} else {
				r.Messengers = settings.ModeVPN
			}
		case core.GOther:
			if direct {
				r.Other = settings.ModeDirect
			} else {
				r.Other = settings.ModeVPN
			}
		case core.GAI:
			if name == core.GOwn {
				r.AI = settings.ModeOwn
			} else {
				r.AI = settings.ModeVPN
			}
		case core.GBlocked:
			if name == core.GAuto {
				r.BlockedSelect = ""
			} else {
				r.BlockedSelect = name
			}
		}
		return nil
	})
}

// NodeView is a server node with health info.
type NodeView struct {
	ServerID string `json:"server_id,omitempty"`
	Name     string `json:"name"`
	Delay    int    `json:"delay"`
	Alive    bool   `json:"alive"`
	UDP      bool   `json:"udp"`
	Type     string `json:"type"`
}

// SubView is a subscription's live state.
type SubView struct {
	ID        string                 `json:"id"`
	Nodes     []NodeView             `json:"nodes"`
	UpdatedAt string                 `json:"updated_at"`
	Info      *core.SubscriptionInfo `json:"info,omitempty"`
}

// NodesView is returned by Nodes().
type NodesView struct {
	Own    map[string]NodeView `json:"own"` // by server id
	Subs   []SubView           `json:"subs"`
	Active string              `json:"active"`
}

// Nodes returns health of own servers and subscriptions.
func (a *App) Nodes() (NodesView, error) {
	api, b, err := a.apiOrErr()
	if err != nil {
		return NodesView{}, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 6*time.Second)
	defer cancel()
	proxies, err := api.Proxies(ctx)
	if err != nil {
		return NodesView{}, err
	}
	view := NodesView{Own: map[string]NodeView{}, Subs: []SubView{}, Active: resolveExit(proxies, core.GBlocked)}
	untested := false
	for id, name := range b.NodeName {
		p, ok := proxies[name]
		if !ok {
			continue
		}
		untested = untested || len(p.History) == 0
		view.Own[id] = NodeView{ServerID: id, Name: name, Delay: p.LastDelay(), Alive: p.Alive, UDP: p.UDP, Type: p.Type}
	}
	provs, err := api.Providers(ctx)
	if err == nil {
		for subID, pname := range b.SubProvider {
			pv, ok := provs[pname]
			if !ok {
				continue
			}
			sv := SubView{ID: subID, UpdatedAt: pv.UpdatedAt, Info: pv.SubscriptionInfo, Nodes: []NodeView{}}
			for _, n := range pv.Proxies {
				untested = untested || len(n.History) == 0
				sv.Nodes = append(sv.Nodes, NodeView{Name: n.Name, Delay: n.LastDelay(), Alive: n.Alive, UDP: n.UDP, Type: n.Type})
			}
			sort.SliceStable(sv.Nodes, func(i, j int) bool {
				di, dj := sv.Nodes[i].Delay, sv.Nodes[j].Delay
				if (di > 0) != (dj > 0) {
					return di > 0
				}
				return di < dj
			})
			view.Subs = append(view.Subs, sv)
		}
	}
	if untested {
		a.autoTest()
	}
	return view, nil
}

// TestDelays runs a health check on own servers and subscriptions.
func (a *App) TestDelays() error {
	api, b, err := a.apiOrErr()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, name := range b.NodeName {
		wg.Add(1)
		go func(n string) { defer wg.Done(); api.Delay(ctx, n, core.HealthURL, 5000) }(name)
	}
	for _, pname := range b.SubProvider {
		wg.Add(1)
		go func(n string) { defer wg.Done(); api.HealthCheckProvider(ctx, n) }(pname)
	}
	wg.Wait()
	return nil
}

// RefreshSubscription re-downloads a subscription now.
func (a *App) RefreshSubscription(id string) error {
	api, b, err := a.apiOrErr()
	if err != nil {
		return err
	}
	pname, ok := b.SubProvider[id]
	if !ok {
		return errors.New("подписка не включена")
	}
	ctx, cancel := context.WithTimeout(a.ctx, 40*time.Second)
	defer cancel()
	if err := api.UpdateProvider(ctx, pname); err != nil {
		return fmt.Errorf("не удалось обновить подписку: %w", err)
	}
	return api.HealthCheckProvider(ctx, pname)
}

// RefreshRules re-downloads all routing lists.
func (a *App) RefreshRules() error {
	api, _, err := a.apiOrErr()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 90*time.Second)
	defer cancel()
	rps, err := api.RuleProviders(ctx)
	if err != nil {
		return err
	}
	var failed []string
	for name := range rps {
		if err := api.UpdateRuleProvider(ctx, name); err != nil {
			failed = append(failed, name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("не обновились: %s", strings.Join(failed, ", "))
	}
	return nil
}

// RulesInfo lists rule sets with counts.
func (a *App) RulesInfo() (map[string]core.RuleProviderInfo, error) {
	api, _, err := a.apiOrErr()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	return api.RuleProviders(ctx)
}
