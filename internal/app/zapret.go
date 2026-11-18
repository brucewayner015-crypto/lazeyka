package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"lazeyka/internal/core"
	"lazeyka/internal/idna"
	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
	"lazeyka/internal/zapret"
)

func (a *App) zpaths() zapret.Paths { return zapret.Paths{Dir: a.P.Zapret} }

// StartZapret starts winws with the configured strategy.
func (a *App) StartZapret() error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	err := a.startZapretLocked()
	if err != nil {
		a.setZapret("error", err.Error())
		a.syncZapretGroups(false)
	}
	return err
}

func (a *App) startZapretLocked() error {
	if platform.IsAndroid {
		return a.startByeDPILocked()
	}
	if !platform.IsWindows {
		a.setZapret("missing", "zapret работает только в Windows")
		return nil
	}
	if !platform.IsElevated() {
		return errors.New("для zapret нужны права администратора")
	}
	if a.zapretHeldForVPN(a.Settings()) {
		a.zr.Stop()
		a.setZapret("paused", pausedText)
		a.syncZapretGroups(false)
		return nil
	}
	p := a.zpaths()
	if !p.Installed() {
		a.setZapret("starting", "")
		if err := a.installZapret(); err != nil {
			return err
		}
	}
	if miss := p.Missing(); len(miss) > 0 {
		return fmt.Errorf("не хватает файлов zapret: %s. %s", strings.Join(miss, ", "), a.avHint())
	}
	if c := a.zapretConflicts(); len(c) > 0 {
		return fmt.Errorf("мешает другой обход: %s — нажмите «Убрать конфликты» на вкладке zapret", strings.Join(c, ", "))
	}
	a.setZapret("starting", "")
	s := a.Settings()
	if err := zapret.EnsureUserLists(p); err != nil {
		return err
	}
	if err := zapret.SetExcludeIPs(p, a.ownServerIPs(s)); err != nil {
		logx.Warnf("zapret: не удалось записать исключения: %v", err)
	}
	if err := zapret.SetManagedHosts(p, appHosts(s)); err != nil {
		logx.Warnf("zapret: не удалось записать список сайтов: %v", err)
	}
	if err := zapret.SetIPSetMode(p, s.Zapret.IPSet); err != nil {
		logx.Warnf("zapret: %v", err)
	}
	ifIdx := 0
	if s.Zapret.BindPhysical {
		ifIdx = platform.DefaultRouteIfIndex(TunName)
	}
	a.mu.Lock()
	a.lastIfIndex = ifIdx
	a.mu.Unlock()
	strategy := s.Zapret.Strategy
	args, err := zapret.BuildArgs(p, strategy, s.Zapret.GameFilter, ifIdx)
	if err != nil && strategy != "general.bat" {
		logx.Warnf("стратегия %s: %v — беру general.bat", strategy, err)
		strategy = "general.bat"
		args, err = zapret.BuildArgs(p, strategy, s.Zapret.GameFilter, ifIdx)
	}
	if err != nil {
		return err
	}
	a.zr.Stop()
	if err := a.zr.Start(p, strategy, args); err != nil {
		return err
	}
	time.Sleep(1500 * time.Millisecond)
	if !a.zr.Running() {
		return fmt.Errorf("winws.exe сразу завершился: %s", lastLine("zapret"))
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

// firstTune runs once, after zapret first starts: if YouTube or Discord do
// not open with the default strategy, the best one is picked automatically.
func (a *App) firstTune() {
	if err := a.update(func(s *settings.Settings) error { s.Zapret.AutoTuned = true; return nil }); err != nil {
		return
	}
	select {
	case <-a.ctx.Done():
		return
	case <-time.After(8 * time.Second): // let the VPN come up first
	}
	if !a.zr.Running() {
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 40*time.Second)
	res := zapret.RunChecks(ctx, a.checkProxyURL(), zapret.DefaultChecks())
	cancel()
	sum := zapret.Summarize(res)
	if sum.YouTube >= 3 && sum.Discord >= 3 {
		logx.Infof("zapret: стратегия %s работает (%d из %d проверок)", a.Settings().Zapret.Strategy, sum.OK, sum.Total)
		return
	}
	logx.Infof("zapret: со стратегией по умолчанию открывается %d из %d — подбираю лучшую", sum.OK, sum.Total)
	if a.tray != nil {
		title := "Лазейка подбирает настройки zapret"
		if platform.IsAndroid {
			title = "Лазейка подбирает настройки обхода"
		}
		a.tray.Notify(title, "Пару минут YouTube и Discord могут подтормаживать.", false)
	}
	if err := a.AutoSelectZapret(); err != nil {
		logx.Warnf("zapret: %v", err)
	}
}

// avHint tells how to get WinDivert past the antivirus. The whole app folder
// is named because zapret is unpacked next to its own folder first.
func (a *App) avHint() string {
	return "Обычно их удаляет антивирус: добавьте папку " + a.P.Root + " в исключения Защитника Windows (Безопасность Windows → Защита от вирусов и угроз → Исключения) и нажмите «Переустановить zapret» на вкладке zapret"
}

func lastLine(src string) string {
	t := logx.Default().Tail(src, 3)
	if len(t) == 0 {
		return "подробностей нет — посмотрите журнал"
	}
	var parts []string
	for _, e := range t {
		parts = append(parts, e.Msg)
	}
	return strings.Join(parts, " / ")
}

// StopZapret stops winws.
func (a *App) StopZapret() {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.zr.Stop()
	a.setZapret("off", "")
	a.syncZapretGroups(false)
}

// SetZapretEnabled toggles zapret and remembers the choice.
func (a *App) SetZapretEnabled(on bool) error {
	if err := a.update(func(s *settings.Settings) error { s.Zapret.Enabled = on; return nil }); err != nil {
		return err
	}
	if platform.IsAndroid && a.Connected() {
		// the QUIC rule for YouTube depends on ByeDPI: rebuild the config
		defer a.ApplyAsync()
	}
	if on {
		err := a.StartZapret()
		if err == nil && platform.IsAndroid && !a.Connected() && !a.Dev {
			// ByeDPI only sees traffic that the VPN interface hands to mihomo
			go func() { _ = a.Connect() }()
		}
		return err
	}
	a.StopZapret()
	return nil
}

// SetZapretOptions changes strategy/filters and restarts zapret if running.
func (a *App) SetZapretOptions(strategy, gameFilter, ipset *string, bind *bool, pause *string) error {
	if err := a.update(func(s *settings.Settings) error {
		if pause != nil && (*pause == "on" || *pause == "off") {
			s.Zapret.PauseWithVPN = *pause
		}
		if strategy != nil && *strategy != "" {
			s.Zapret.Strategy = *strategy
		}
		if gameFilter != nil {
			s.Zapret.GameFilter = *gameFilter
		}
		if ipset != nil {
			s.Zapret.IPSet = *ipset
		}
		if bind != nil {
			s.Zapret.BindPhysical = *bind
		}
		return nil
	}); err != nil {
		return err
	}
	if a.zr.Running() || a.Settings().Zapret.Enabled {
		return a.StartZapret()
	}
	return nil
}

func (a *App) zapretPaused() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.zap == "paused"
}

var errPausedForVPN = errors.New("zapret на паузе, пока включён VPN: выключите VPN, чтобы проверить zapret")

// syncZapretGroups points YouTube/Discord at DIRECT when zapret works and at
// the VPN when it does not (only for groups in "zapret" mode).
func (a *App) syncZapretGroups(active bool) {
	a.mu.Lock()
	api, b := a.api, a.built
	r := a.s.Routing
	a.mu.Unlock()
	if api == nil || b == nil || (!b.HasVPN && !platform.IsAndroid) {
		return
	}
	ctx, cancel := context.WithTimeout(a.ctx, 4*time.Second)
	defer cancel()
	if r.YouTube == settings.ModeZapret {
		t := core.GAuto
		if active {
			t = dpiDirectTarget()
		}
		_ = api.Select(ctx, core.GYouTube, t)
	}
	if r.Discord == settings.ModeZapret {
		t := core.GVoice
		if active {
			t = dpiDirectTarget()
		}
		_ = api.Select(ctx, core.GDiscord, t)
	}
}

func (a *App) onZapretExit(err error, uptime time.Duration) {
	a.mu.Lock()
	enabled := a.s.Zapret.Enabled
	if uptime < 15*time.Second {
		a.fastZapFails++
	} else {
		a.fastZapFails = 0
	}
	fails := a.fastZapFails
	testing := a.jobs["zapret-test"] != nil && a.jobs["zapret-test"].Running
	a.mu.Unlock()
	if testing || !enabled {
		return
	}
	if fails >= 3 {
		name := "winws.exe"
		if platform.IsAndroid {
			name = "ByeDPI"
		}
		a.setZapret("error", name+" падает при запуске: "+lastLine("zapret"))
		a.syncZapretGroups(false)
		return
	}
	a.syncZapretGroups(false)
	go func() {
		time.Sleep(3 * time.Second)
		if err := a.StartZapret(); err != nil {
			logx.Errorf("перезапуск zapret: %v", err)
		}
	}()
}

// ownServerIPs resolves own servers so zapret can exclude them.
func (a *App) ownServerIPs(s *settings.Settings) []string {
	var out []string
	ctx, cancel := context.WithTimeout(a.ctx, 4*time.Second)
	defer cancel()
	for _, srv := range s.Servers {
		if !srv.Enabled || srv.Host == "" {
			continue
		}
		if ip, err := netip.ParseAddr(srv.Host); err == nil {
			out = append(out, ip.String())
			continue
		}
		addrs, err := net.DefaultResolver.LookupHost(ctx, srv.Host)
		if err != nil {
			continue
		}
		out = append(out, addrs...)
	}
	return out
}

// appHosts are the sites Лазейка itself has to reach directly: GitHub (engine
// and routing-list downloads) and the subscription servers. They go into
// zapret's host list, which gets them through when the provider blocks them
// by name.
func appHosts(s *settings.Settings) []string {
	hosts := []string{"githubusercontent.com"}
	for _, sub := range s.Subscriptions {
		if !sub.Enabled {
			continue
		}
		u, err := url.Parse(sub.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		if _, err := netip.ParseAddr(u.Hostname()); err == nil {
			continue // host lists hold names only
		}
		if h, err := idna.ToASCII(u.Hostname()); err == nil {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// RefreshZapretExcludes updates zapret's lists after servers or subscriptions
// changed: the site list in place (winws re-reads it), the server IPs with a
// restart.
func (a *App) RefreshZapretExcludes() {
	if !a.zr.Running() {
		return
	}
	p := a.zpaths()
	if err := zapret.SetManagedHosts(p, appHosts(a.Settings())); err != nil {
		logx.Warnf("zapret: не удалось записать список сайтов: %v", err)
	}
	old, _ := zapret.ReadManagedBlock(p)
	ips := a.ownServerIPs(a.Settings())
	if sameSet(old, ips) {
		return
	}
	if err := a.StartZapret(); err != nil {
		logx.Warnf("zapret: %v", err)
	}
}

func sameSet(a, b []string) bool {
	norm := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range l {
			x = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(x), "/32"), "/128")
			if x != "" {
				m[x] = true
			}
		}
		return m
	}
	x, y := norm(a), norm(b)
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if !y[k] {
			return false
		}
	}
	return true
}

// zapretConflicts lists other DPI-bypass tools that hold WinDivert.
func (a *App) zapretConflicts() []string {
	if !platform.IsWindows {
		return nil
	}
	var out []string
	for _, svc := range platform.ConflictingServices {
		if info := platform.Service(svc); info.Exists {
			out = append(out, "служба "+svc)
		}
	}
	own := a.zr.PID()
	for _, pid := range platform.ProcessPIDs("winws.exe") {
		if pid != own {
			out = append(out, fmt.Sprintf("winws.exe (pid %d)", pid))
		}
	}
	for _, pid := range platform.ProcessPIDs("goodbyedpi.exe") {
		out = append(out, fmt.Sprintf("goodbyedpi.exe (pid %d)", pid))
	}
	return out
}

// Conflicts is exported for the UI.
func (a *App) Conflicts() []string { return a.zapretConflicts() }

// FixZapretConflicts removes other bypass services and processes.
func (a *App) FixZapretConflicts() error {
	if !platform.IsWindows {
		return nil
	}
	a.opMu.Lock()
	defer a.opMu.Unlock()
	for _, svc := range platform.ConflictingServices {
		if platform.Service(svc).Exists {
			logx.Infof("удаляю службу %s", svc)
			platform.StopDeleteService(svc)
		}
	}
	own := a.zr.PID()
	for _, img := range []string{"winws.exe", "goodbyedpi.exe"} {
		for _, pid := range platform.ProcessPIDs(img) {
			if pid != own {
				logx.Infof("завершаю %s (pid %d)", img, pid)
				platform.KillPID(pid)
			}
		}
	}
	if own == 0 {
		for _, svc := range []string{"WinDivert", "WinDivert14"} {
			if platform.Service(svc).Exists {
				platform.StopDeleteService(svc)
			}
		}
	}
	if c := a.zapretConflicts(); len(c) > 0 {
		return fmt.Errorf("не удалось убрать: %s", strings.Join(c, ", "))
	}
	return nil
}

// watchNetwork restarts zapret when the physical interface changes.
func (a *App) watchNetwork() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
		if !platform.IsWindows {
			continue
		}
		a.mu.Lock()
		vpnOn := a.vpn == "on"
		a.mu.Unlock()
		if vpnOn {
			a.recheckNetFix()
			a.checkOtherVPN(true)
			a.loopHealed(time.Now())
		}
		if !a.zr.Running() {
			continue
		}
		s := a.Settings()
		if !s.Zapret.BindPhysical {
			continue
		}
		idx := platform.DefaultRouteIfIndex(TunName)
		a.mu.Lock()
		prev := a.lastIfIndex
		a.mu.Unlock()
		if idx != 0 && idx != prev {
			logx.Infof("сеть сменилась (интерфейс %d → %d), перезапускаю zapret", prev, idx)
			if err := a.StartZapret(); err != nil {
				logx.Errorf("zapret: %v", err)
			}
		}
	}
}

// ZapretView is the zapret tab state.
type ZapretView struct {
	Installed  bool                   `json:"installed"`
	Version    string                 `json:"version"`
	Running    bool                   `json:"running"`
	Strategy   string                 `json:"strategy"`
	Strategies []zapret.Strategy      `json:"strategies"`
	GameFilter string                 `json:"game_filter"`
	IPSet      string                 `json:"ipset"`
	Bind       bool                   `json:"bind_physical"`
	Enabled    bool                   `json:"enabled"`
	Conflicts  []string               `json:"conflicts"`
	Scores     []zapret.StrategyScore `json:"scores"`
	IfIndex    int                    `json:"if_index"`
	PauseVPN   string                 `json:"pause_with_vpn"`
	Paused     bool                   `json:"paused"`
}

// ZapretInfo returns the zapret tab state.
func (a *App) ZapretInfo() ZapretView {
	p := a.zpaths()
	s := a.Settings()
	v := ZapretView{
		Installed: a.dpiInstalled(), Version: s.Zapret.Version, Running: a.zr.Running(),
		Strategy: s.Zapret.Strategy, GameFilter: s.Zapret.GameFilter, IPSet: s.Zapret.IPSet,
		Bind: s.Zapret.BindPhysical, Enabled: s.Zapret.Enabled, PauseVPN: s.Zapret.PauseWithVPN, Paused: a.zapretPaused(),
	}
	if v.Installed {
		v.Strategies, _ = a.strategyList()
	}
	_ = p
	v.Conflicts = a.zapretConflicts()
	v.Scores = a.strategyScores()
	a.mu.Lock()
	v.IfIndex = a.lastIfIndex
	a.mu.Unlock()
	return v
}

// CheckZapret runs the reachability checks once with the current setup.
func (a *App) CheckZapret() error {
	if a.zapretPaused() {
		return errPausedForVPN
	}
	if !a.jobStart("zapret-check", "Проверка YouTube и Discord") {
		return errors.New("проверка уже идёт")
	}
	go func() {
		ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
		defer cancel()
		res := zapret.RunChecks(ctx, a.checkProxyURL(), zapret.DefaultChecks())
		sum := zapret.Summarize(res)
		if a.zr.Running() {
			a.recordScore(a.Settings().Zapret.Strategy, sum)
		}
		a.jobDone("zapret-check", nil, map[string]any{"results": res, "summary": sum})
	}()
	return nil
}

// AutoSelectZapret tries every strategy and keeps the best one.
func (a *App) AutoSelectZapret() error {
	if !platform.IsWindows && !platform.IsAndroid {
		return errors.New("подбор стратегии работает только в Windows")
	}
	if !a.dpiInstalled() {
		return errors.New("zapret ещё не установлен")
	}
	if a.zapretPaused() {
		return errPausedForVPN
	}
	if !a.jobStart("zapret-test", "Подбор стратегии zapret") {
		return errors.New("подбор уже идёт")
	}
	if platform.IsAndroid {
		go a.runAutoSelectAndroid()
		return nil
	}
	go a.runAutoSelect()
	return nil
}

func (a *App) runAutoSelect() {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	p := a.zpaths()
	s := a.Settings()
	strategies, err := zapret.ListStrategies(p.Dir)
	if err != nil || len(strategies) == 0 {
		a.jobDone("zapret-test", errors.New("стратегии не найдены"), nil)
		return
	}
	a.setZapret("starting", "")
	proxy := a.directProxyURL()
	checks := zapret.DefaultChecks()
	ifIdx := 0
	if s.Zapret.BindPhysical {
		ifIdx = platform.DefaultRouteIfIndex(TunName)
	}
	var scores []zapret.StrategyScore
	a.zr.Stop()
	a.jobSet("zapret-test", 0, "Проверка без zapret…")
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	base := zapret.RunChecks(ctx, proxy, checks)
	cancel()
	baseline := zapret.StrategyScore{File: "", Summary: zapret.Summarize(base), Results: base}
	for i, st := range strategies {
		if a.ctx.Err() != nil {
			break
		}
		a.jobSet("zapret-test", float64(i+1)/float64(len(strategies)+1), fmt.Sprintf("Стратегия %d из %d: %s", i+1, len(strategies), st.Name))
		sc := zapret.StrategyScore{File: st.File}
		args, err := zapret.BuildArgs(p, st.File, s.Zapret.GameFilter, ifIdx)
		if err != nil {
			sc.Err = err.Error()
			scores = append(scores, sc)
			continue
		}
		if err := a.zr.Start(p, st.File, args); err != nil {
			sc.Err = err.Error()
			scores = append(scores, sc)
			continue
		}
		time.Sleep(1800 * time.Millisecond)
		if !a.zr.Running() {
			sc.Err = "winws завершился: " + lastLine("zapret")
			scores = append(scores, sc)
			continue
		}
		ctx, cancel := context.WithTimeout(a.ctx, 40*time.Second)
		sc.Results = zapret.RunChecks(ctx, proxy, checks)
		cancel()
		sc.Summary = zapret.Summarize(sc.Results)
		a.zr.Stop()
		scores = append(scores, sc)
	}
	a.zr.Stop()
	best, ok := zapret.Best(scores)
	a.setScores(append([]zapret.StrategyScore{baseline}, scores...))
	result := map[string]any{"baseline": baseline.Summary, "total": len(checks)}
	if ok {
		result["best"] = best.File
		result["best_summary"] = best.Summary
		_ = a.update(func(s *settings.Settings) error { s.Zapret.Strategy = best.File; return nil })
		logx.Infof("лучшая стратегия zapret: %s (%d/%d)", best.File, best.Summary.OK, best.Summary.Total)
	}
	var restartErr error
	if a.Settings().Zapret.Enabled {
		restartErr = a.startZapretLocked()
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
