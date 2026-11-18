package app

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
)

// On some computers the VPN's own connections come back into the VPN tunnel.
// mihomo then drops them ("reject loopback connection") and nothing works:
// DNS, servers, subscriptions. Causes, in the order Лазейка deals with them:
//   - forwarding or weak host send on the network card (sharing, hotspot):
//     netfix.go switches it off for the session, also when it comes back;
//   - zapret: it re-sends intercepted packets, and Windows may route the
//     re-sent packet by its destination alone, into the tunnel — zapret then
//     stays paused while the VPN is on (YouTube and Discord go through a
//     server);
//   - something Лазейка cannot switch off itself (Internet Connection
//     Sharing, another VPN, an antivirus that checks traffic): the UI says
//     what to do.

const pausedText = "приостановлен, пока включён VPN: на этом компьютере zapret и VPN мешают друг другу. YouTube и Discord сейчас идут через сервер"

// loopMeter counts mihomo's "reject loopback connection" lines.
type loopMeter struct {
	start      time.Time
	n          int
	fired      bool
	quietUntil time.Time
}

const (
	loopWindow    = 20 * time.Second
	loopThreshold = 15
)

// hit records a loop line and reports whether that makes a storm.
func (m *loopMeter) hit(now time.Time) bool {
	if m.fired || now.Before(m.quietUntil) {
		return false
	}
	if now.Sub(m.start) > loopWindow {
		m.start, m.n = now, 0
	}
	m.n++
	if m.n >= loopThreshold {
		m.fired = true
		return true
	}
	return false
}

// reset starts counting again, ignoring lines for a while (connections that
// were already in flight still fail after the cause is gone).
func (m *loopMeter) reset(now time.Time, quiet time.Duration) {
	*m = loopMeter{quietUntil: now.Add(quiet)}
}

func (a *App) onMihomoLine(level, msg string) {
	if strings.Contains(msg, "provider sub-") && (strings.Contains(msg, "`<!doc") || strings.Contains(msg, "`<html") || strings.Contains(msg, "`<!DOC")) {
		go a.subscriptionIsWebPage(msg)
		return
	}
	if !strings.Contains(msg, "reject loopback connection") {
		return
	}
	now := time.Now()
	a.mu.Lock()
	a.lastLoop = now
	storm := a.loop.hit(now)
	a.mu.Unlock()
	if storm {
		go a.handleTunnelLoop()
	}
}

// zapretHeldForVPN: zapret must stay off while the VPN is on.
func (a *App) zapretHeldForVPN(s *settings.Settings) bool {
	return s.Zapret.PauseWithVPN == "on" && a.Connected()
}

func (a *App) handleTunnelLoop() {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	if !a.mihomo.Running() {
		return
	}
	quiet := func(d time.Duration) {
		a.mu.Lock()
		a.loop.reset(time.Now(), d)
		a.mu.Unlock()
	}
	// 1. forwarding came back on (sharing does that when the network changes)
	if changed := a.recheckNetFix(); len(changed) > 0 {
		quiet(15 * time.Second)
		go a.reloadSubscriptions()
		return
	}
	// 2. zapret re-sends the packets
	s := a.Settings()
	if a.zr.Running() {
		if s.Zapret.PauseWithVPN == "off" {
			a.setLoopMsg("Соединения VPN возвращаются в туннель, потому что их перехватывает zapret. " +
				"Включите на вкладке zapret «Выключать zapret, пока работает VPN».")
			return
		}
		_ = a.update(func(s *settings.Settings) error { s.Zapret.PauseWithVPN = "on"; return nil })
		a.zr.Stop()
		a.setZapret("paused", pausedText)
		a.syncZapretGroups(false)
		logx.Warnf("собственные соединения VPN возвращались в туннель: их перехватывал zapret. " +
			"Пока VPN включён, zapret на паузе, YouTube и Discord идут через сервер; при выключении VPN zapret включится сам")
		if a.tray != nil {
			a.tray.Notify("Лазейка", "zapret мешал VPN на этом компьютере: пока VPN включён, zapret на паузе", false)
		}
		quiet(15 * time.Second)
		go a.reloadSubscriptions()
		return
	}
	// 3. nothing left to switch off automatically: tell the user what to do
	a.setLoopMsg("Windows отправляет соединения самого VPN обратно в туннель, поэтому ничего не работает. " + a.loopHints())
	quiet(time.Minute) // look again later: the advice may change
}

// setLoopMsg shows why the VPN does not work (logged once per text).
func (a *App) setLoopMsg(msg string) {
	a.mu.Lock()
	prev := a.loopMsg
	a.loopMsg = msg
	a.mu.Unlock()
	if msg == prev {
		return
	}
	logx.Errorf("VPN не работает: %s %s", msg, a.netDiag())
	if a.tray != nil {
		a.tray.Notify("Лазейка: VPN не работает", msg, true)
	}
	a.refreshTray()
}

// loopHealed clears the message once the loop lines have stopped.
func (a *App) loopHealed(now time.Time) {
	a.mu.Lock()
	healed := a.loopMsg != "" && now.Sub(a.lastLoop) > 45*time.Second
	if healed {
		a.loopMsg = ""
		a.loop.reset(now, 0)
	}
	a.mu.Unlock()
	if healed {
		logx.Infof("соединения VPN больше не возвращаются в туннель")
		a.refreshTray()
	}
}

// resumeZapret starts zapret again after the VPN went off.
func (a *App) resumeZapret() {
	if !a.Settings().Zapret.Enabled {
		a.setZapret("off", "")
		return
	}
	if err := a.StartZapret(); err != nil {
		logx.Warnf("zapret: %v", err)
	}
}

// reloadSubscriptions retries the subscriptions right away instead of waiting
// for the next scheduled attempt.
func (a *App) reloadSubscriptions() {
	time.Sleep(2 * time.Second)
	for _, sub := range a.Settings().Subscriptions {
		if !sub.Enabled {
			continue
		}
		if err := a.RefreshSubscription(sub.ID); err != nil {
			logx.Warnf("подписка «%s»: %v", sub.Name, err)
		} else {
			logx.Infof("подписка «%s» загружена", sub.Name)
		}
	}
}

// NetDiag is netDiag for the diagnostics report.
func (a *App) NetDiag() string { return a.netDiag() }

// netDiag describes what decides where the VPN's packets go.
func (a *App) netDiag() string {
	if !platform.IsWindows {
		return ""
	}
	var parts []string
	onOff := func(b bool) string {
		if b {
			return "вкл."
		}
		return "выкл."
	}
	describe := func(idx int, what string) {
		hm, ok := platform.InterfaceHostModel(idx)
		if !ok {
			return
		}
		parts = append(parts, fmt.Sprintf("%s%s (№%d): пересылка %s, weak host %s/%s", what, hm.Name, hm.Index, onOff(hm.Forwarding), onOff(hm.WeakSend), onOff(hm.WeakRecv)))
	}
	for _, r := range platform.DefaultRoutes(TunName) {
		switch {
		case r.Bindable():
			describe(r.Index, "")
		case r.OtherVPN():
			describe(r.Index, "другой VPN ")
		}
	}
	if ifc, err := net.InterfaceByName(TunName); err == nil {
		describe(ifc.Index, "")
	}
	if v, ok := platform.IPEnableRouter(); ok {
		parts = append(parts, fmt.Sprintf("IPEnableRouter=%d", v))
	}
	if c := a.zapretConflicts(); len(c) > 0 {
		parts = append(parts, "другие программы обхода: "+strings.Join(c, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return "Сеть: " + strings.Join(parts, "; ") + "."
}

var webPageWarned sync.Map // provider name → struct{}

// subscriptionIsWebPage: a subscription address answers with a web page —
// usually the Связка panel's address pasted instead of its subscription link.
func (a *App) subscriptionIsWebPage(msg string) {
	i := strings.Index(msg, "sub-")
	if i < 0 {
		return
	}
	name := msg[i:]
	if j := strings.IndexAny(name, " :"); j > 0 {
		name = name[:j]
	}
	if _, dup := webPageWarned.LoadOrStore(name, struct{}{}); dup {
		return
	}
	title := "подписка"
	for _, sub := range a.Settings().Subscriptions {
		if "sub-"+sub.ID == name {
			title = "подписка «" + sub.Name + "»"
		}
	}
	text := "По адресу открывается веб-страница, а не список серверов. Если это адрес панели Связки, скопируйте на панели ссылку для Лазейки и телефона и добавьте её вместо этой."
	logx.Warnf("%s: %s", title, text)
	if a.tray != nil {
		a.tray.Notify("Лазейка: "+title+" не загрузилась", text, true)
	}
}
