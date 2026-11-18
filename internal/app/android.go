package app

// Android: the same core as on Windows, with three differences.
//   - The VPN interface comes from the Android app (VpnService) as a file
//     descriptor that mihomo inherits; apps on the bypass list skip it.
//   - ByeDPI, a local SOCKS5 proxy, does zapret's job: zapret needs root on
//     Android. mihomo sends YouTube and Discord to it.
//   - Notifications instead of the tray; the app's buttons and the quick
//     settings tile arrive as host events.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"lazeyka/internal/byedpi"
	"lazeyka/internal/core"
	"lazeyka/internal/host"
	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
	"lazeyka/internal/zapret"
)

// Android VPN interface: mihomo takes its address from the fake-ip range
// (198.18.0.1/30) and answers DNS on the next address.
const (
	androidAddr4 = "198.18.0.1/30"
	androidDNS   = "198.18.0.2"
	androidAddr6 = "fdfe:dcba:9876::1/126"
)

// ByeDPIExe is the bundled ByeDPI binary.
func byedpiExe() string { return os.Getenv("LAZEYKA_BYEDPI") }

// initAndroid prepares the ByeDPI runner and fixes settings that make no
// sense on a phone. Called from New.
func (a *App) initAndroid() {
	if !platform.IsAndroid {
		return
	}
	a.zr.Exe = byedpiExe()
	a.zr.Label = "ByeDPI"
	// mihomo's loop check lists network interfaces on every UDP connection,
	// and Android forbids that to apps (netlink): every UDP dial failed with
	// "route ip+net: netlinkrib: permission denied". A loop cannot happen
	// here anyway: the app (and so mihomo) is always outside the VPN.
	a.mihomo.Env = []string{"DISABLE_LOOPBACK_DETECTOR=true"}
	a.dpiPort = freePort()
	if a.dpiPort == 0 {
		a.dpiPort = 18081
	}
	// mihomo gives proxies the site's name; ByeDPI would ask the phone's DNS,
	// which in Russia says YouTube does not exist. The front resolves names
	// over TCP DNS and hands ByeDPI the address.
	var lastFrontLog time.Time
	a.front = &byedpi.Front{
		Upstream: "127.0.0.1:" + strconv.Itoa(a.dpiPort),
		Resolver: &byedpi.TCPResolver{},
		OnError: func(host string, err error) {
			if time.Since(lastFrontLog) > 10*time.Second { // not per connection
				lastFrontLog = time.Now()
				logx.Warnf("ByeDPI: %s: %v", host, err)
			}
		},
	}
	if p, err := a.front.Listen(0); err != nil {
		logx.Errorf("ByeDPI: не удалось открыть порт: %v", err)
	} else {
		a.frontPort = p
	}
	go a.dnsReport()
	_ = a.update(func(s *settings.Settings) error {
		if !byedpi.IsKey(s.Zapret.Strategy) {
			s.Zapret.Strategy = byedpi.Default
		}
		s.Zapret.PauseWithVPN = "off" // the Windows loop problem does not exist here
		s.App.Autostart = false       // Android: "Always-on VPN" in the system settings
		return nil
	})
}

// dpiInstalled: ByeDPI is part of the app.
func (a *App) dpiInstalled() bool {
	if !platform.IsAndroid {
		return a.zpaths().Installed()
	}
	_, err := os.Stat(byedpiExe())
	return err == nil
}

// strategyList: zapret's .bat files, or ByeDPI's built-in list.
func (a *App) strategyList() ([]zapret.Strategy, error) {
	if platform.IsAndroid {
		return byedpi.List(), nil
	}
	return zapret.ListStrategies(a.zpaths().Dir)
}

// dpiProxyURL: checks go through ByeDPI itself on Android (it is a proxy),
// through mihomo's direct port on Windows (zapret works on the packets).
func (a *App) checkProxyURL() *url.URL {
	if platform.IsAndroid {
		return &url.URL{Scheme: "socks5", Host: "127.0.0.1:" + strconv.Itoa(a.frontPort)}
	}
	return a.directProxyURL()
}

// dpiDirectTarget: what YouTube/Discord select when the bypass works.
func dpiDirectTarget() string {
	if platform.IsAndroid {
		return core.PByeDPI
	}
	return "DIRECT"
}

// startByeDPILocked: the caller holds opMu (the zapret API).
func (a *App) startByeDPILocked() error {
	a.dpiMu.Lock()
	defer a.dpiMu.Unlock()
	return a.startByeDPIRunner()
}

// startByeDPIRunner: the caller holds dpiMu.
func (a *App) startByeDPIRunner() error {
	if !a.dpiInstalled() {
		return errors.New("в приложении нет ByeDPI — переустановите Лазейку")
	}
	a.setZapret("starting", "")
	s := a.Settings()
	strategy := s.Zapret.Strategy
	args, err := byedpi.Args(strategy, a.dpiPort)
	if err != nil {
		logx.Warnf("стратегия %s: %v — беру %s", strategy, err, byedpi.Default)
		strategy = byedpi.Default
		args, _ = byedpi.Args(strategy, a.dpiPort)
	}
	a.zr.Stop()
	if err := a.zr.Start(zapret.Paths{}, strategy, args); err != nil {
		return err
	}
	time.Sleep(700 * time.Millisecond)
	if !a.zr.Running() {
		return fmt.Errorf("ByeDPI сразу завершился: %s", lastLine("zapret"))
	}
	a.mu.Lock()
	a.fastZapFails = 0
	a.mu.Unlock()
	a.setZapret("on", "")
	a.syncZapretGroups(true)
	if !s.Zapret.AutoTuned {
		go a.firstTune()
	}
	return nil
}

// runAutoSelectAndroid tries every ByeDPI strategy against YouTube and Discord.
// It holds dpiMu, not opMu: the VPN can be switched and reconfigured
// meanwhile, and YouTube/Discord go through the VPN until it is over.
func (a *App) runAutoSelectAndroid() {
	a.dpiMu.Lock()
	defer a.dpiMu.Unlock()
	strategies := byedpi.Strategies
	a.setZapret("starting", "")
	a.syncZapretGroups(false)
	checks := zapret.DefaultChecks()
	proxy := a.checkProxyURL()
	a.zr.Stop()
	a.jobSet("zapret-test", 0, "Проверка без обхода…")
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	base := zapret.RunChecks(ctx, nil, checks)
	cancel()
	baseline := zapret.StrategyScore{File: "", Summary: zapret.Summarize(base), Results: base}
	var scores []zapret.StrategyScore
	for i, st := range strategies {
		if a.ctx.Err() != nil {
			break
		}
		a.jobSet("zapret-test", float64(i+1)/float64(len(strategies)+1), fmt.Sprintf("Стратегия %d из %d: %s", i+1, len(strategies), st.Name))
		sc := zapret.StrategyScore{File: st.Key}
		args, _ := byedpi.Args(st.Key, a.dpiPort)
		if err := a.zr.Start(zapret.Paths{}, st.Key, args); err != nil {
			sc.Err = err.Error()
			scores = append(scores, sc)
			continue
		}
		time.Sleep(500 * time.Millisecond)
		if !a.zr.Running() {
			sc.Err = "ByeDPI завершился: " + lastLine("zapret")
			scores = append(scores, sc)
			continue
		}
		ctx, cancel := context.WithTimeout(a.ctx, 40*time.Second)
		sc.Results = zapret.RunChecks(ctx, proxy, checks)
		cancel()
		sc.Summary = zapret.Summarize(sc.Results)
		a.zr.Stop()
		scores = append(scores, sc)
		if sc.Summary.OK == sc.Summary.Total && sc.Summary.Total > 0 && i >= 2 {
			// everything opens: good enough, the phone's battery thanks us
			break
		}
	}
	a.zr.Stop()
	best, ok := zapret.Best(scores)
	a.setScores(append([]zapret.StrategyScore{baseline}, scores...))
	result := map[string]any{"baseline": baseline.Summary, "total": len(checks)}
	if ok {
		result["best"] = best.File
		result["best_summary"] = best.Summary
		_ = a.update(func(s *settings.Settings) error { s.Zapret.Strategy = best.File; return nil })
		logx.Infof("лучшая стратегия ByeDPI: %s (%d/%d)", best.File, best.Summary.OK, best.Summary.Total)
	}
	var restartErr error
	if a.Settings().Zapret.Enabled {
		restartErr = a.startByeDPIRunner()
		if restartErr != nil {
			a.setZapret("error", restartErr.Error())
		}
	} else {
		a.setZapret("off", "")
	}
	if !ok {
		a.jobDone("zapret-test", errors.New("ни одна стратегия не открыла YouTube/Discord: возможно, их блокируют по IP — переключите их на VPN"), result)
		return
	}
	a.jobDone("zapret-test", restartErr, result)
}

// openAndroidTun asks the app for the VPN interface and hands it to mihomo.
func (a *App) openAndroidTun(s *settings.Settings) error {
	if platform.Host == nil {
		return host.ErrNoHost
	}
	f, err := platform.Host.OpenTun(host.TunParams{
		Session:    "Лазейка",
		MTU:        core.AndroidMTU,
		Address4:   androidAddr4,
		Address6:   androidAddr6,
		DNS:        androidDNS,
		BypassApps: s.Routing.BypassApps,
	})
	if err != nil {
		return fmt.Errorf("VPN-интерфейс: %w", err)
	}
	a.mihomo.ExtraFiles = []*os.File{f}
	a.mu.Lock()
	old := a.tunFile
	a.tunFile = f
	a.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// releaseAndroidTun: mihomo has its own copy now (or is gone).
func (a *App) releaseAndroidTun(closeApp bool) {
	a.mu.Lock()
	f := a.tunFile
	a.tunFile = nil
	a.mu.Unlock()
	if f != nil {
		f.Close()
	}
	a.mihomo.ExtraFiles = nil
	if closeApp && platform.Host != nil {
		if err := platform.Host.CloseTun(); err != nil && !errors.Is(err, host.ErrNoHost) {
			logx.Warnf("VPN-интерфейс: %v", err)
		}
	}
}

// HandleHostEvent reacts to the app: buttons, the tile, the system.
func (a *App) HandleHostEvent(ev host.Event) {
	switch ev.Name {
	case "toggle_vpn":
		if a.Connected() {
			a.Disconnect()
		} else {
			_ = a.Connect()
		}
	case "connect":
		if !a.Connected() {
			_ = a.Connect()
		}
	case "disconnect":
		a.Disconnect()
	case "toggle_dpi":
		_ = a.SetZapretEnabled(!a.Settings().Zapret.Enabled)
	case "revoked":
		// another VPN took over, or the user switched us off in Android
		logx.Infof("Android отключил VPN Лазейки (другой VPN или системные настройки)")
		a.opMu.Lock()
		a.disconnectLocked()
		a.opMu.Unlock()
		_ = a.update(func(s *settings.Settings) error { s.App.WasConnected = false; return nil })
	case "network":
		var d struct {
			DNS []string `json:"dns"`
		}
		if json.Unmarshal(ev.Data, &d) == nil && len(d.DNS) > 0 {
			setAndroidDNS(d.DNS)
		}
	case "import":
		var d struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(ev.Data, &d) == nil && strings.TrimSpace(d.Text) != "" {
			res := a.Import(d.Text, "")
			n, err := a.AddItems(res.Items)
			switch {
			case err != nil:
				a.notify("Лазейка: не удалось добавить", err.Error(), true)
			case n > 0:
				a.notify("Лазейка", fmt.Sprintf("Добавлено: %d", n), false)
			case len(res.Errors) > 0:
				a.notify("Лазейка: ссылка не распознана", res.Errors[0], true)
			}
		}
	}
}

func (a *App) notify(title, text string, warn bool) {
	if a.tray != nil {
		a.tray.Notify(title, text, warn)
	}
}

// setAndroidDNS is replaced by main in the Android build.
var setAndroidDNS = func([]string) {}

// SetDNSHook lets main route DNS updates to the platform resolver.
func SetDNSHook(f func([]string)) { setAndroidDNS = f }

// AndroidApp is an installed app for the bypass list.
type AndroidApp struct {
	Package string `json:"package"`
	Label   string `json:"label"`
	System  bool   `json:"system"`
	Bypass  bool   `json:"bypass"`
}

// AndroidApps lists installed apps, those on the bypass list first.
func (a *App) AndroidApps() ([]AndroidApp, error) {
	if platform.Host == nil {
		return nil, host.ErrNoHost
	}
	list, err := platform.Host.Apps()
	if err != nil {
		return nil, err
	}
	on := map[string]bool{}
	for _, p := range a.Settings().Routing.BypassApps {
		on[p] = true
	}
	out := make([]AndroidApp, 0, len(list))
	for _, it := range list {
		out = append(out, AndroidApp{Package: it.Package, Label: it.Label, System: it.System, Bypass: on[it.Package]})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Bypass != out[j].Bypass {
			return out[i].Bypass
		}
		if out[i].System != out[j].System {
			return !out[i].System
		}
		return strings.ToLower(out[i].Label) < strings.ToLower(out[j].Label)
	})
	return out, nil
}

// SetBypassApps replaces the bypass list and rebuilds the VPN interface.
func (a *App) SetBypassApps(pkgs []string) error {
	seen := map[string]bool{}
	clean := []string{}
	for _, p := range pkgs {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] || strings.ContainsAny(p, " \t\n/\\") {
			continue
		}
		seen[p] = true
		clean = append(clean, p)
	}
	if err := a.update(func(s *settings.Settings) error { s.Routing.BypassApps = clean; return nil }); err != nil {
		return err
	}
	a.ApplyAsync()
	return nil
}

// dpiName: what the DPI bypass is called in messages.
func dpiName() string {
	if platform.IsAndroid {
		return "обход DPI"
	}
	return "zapret"
}

// dnsReport writes one line about the network's DNS: in Russia it often says
// YouTube does not exist, which is why Лазейка asks other servers over TCP.
func (a *App) dnsReport() {
	select {
	case <-a.ctx.Done():
		return
	case <-time.After(4 * time.Second):
	}
	const name = "www.youtube.com"
	ctx, cancel := context.WithTimeout(a.ctx, 12*time.Second)
	defer cancel()
	describe := func(ips []netip.Addr, err error) string {
		switch {
		case err != nil && strings.Contains(err.Error(), "no such host"):
			return "«такого сайта нет» (подмена)"
		case err != nil:
			return "нет ответа"
		case len(ips) == 0:
			return "пустой ответ"
		}
		return ips[0].String()
	}
	var netDNS string
	for _, s := range strings.Split(os.Getenv("LAZEYKA_DNS"), ",") {
		if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && ip.Is4() {
			netDNS = net.JoinHostPort(ip.String(), "53")
			break
		}
	}
	sysLine := "неизвестен"
	if netDNS != "" {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", netDNS)
		}}
		ips, err := r.LookupNetIP(ctx, "ip4", name)
		sysLine = describe(ips, err)
	}
	tips, terr := (&byedpi.TCPResolver{}).LookupIPv4(ctx, name)
	logx.Infof("DNS: %s у DNS сети (%s): %s; через TCP (1.1.1.1, 8.8.8.8, 9.9.9.9): %s", name, netDNS, sysLine, describe(tips, terr))
	if terr != nil {
		logx.Warnf("DNS через TCP не отвечает: без серверов YouTube и Discord не откроются (%v)", terr)
	}
}
