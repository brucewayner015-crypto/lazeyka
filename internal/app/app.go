// Package app wires settings, the mihomo core, zapret, engine downloads and
// the tray into one state machine the UI talks to.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"lazeyka/internal/byedpi"
	"lazeyka/internal/core"
	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
	"lazeyka/internal/update"
	"lazeyka/internal/zapret"
)

// Version of the app.
var Version = "0.2.4"

// TunName is the TUN adapter name.
const TunName = "Lazeyka"

// Paths of the installation.
type Paths struct {
	Root       string
	Exe        string
	Bin        string
	MihomoExe  string
	Zapret     string
	Data       string
	Settings   string
	MihomoHome string
	Logs       string
	Icon       string
	IconDir    string
	Instance   string
	Tmp        string
}

// NewPaths lays out everything under root.
func NewPaths(root string) Paths {
	data := filepath.Join(root, "data")
	mexe := "mihomo.exe"
	exe := "Lazeyka.exe"
	if runtime.GOOS != "windows" {
		mexe, exe = "mihomo", "lazeyka"
	}
	p := Paths{
		Root:       root,
		Exe:        filepath.Join(root, exe),
		Bin:        filepath.Join(root, "bin"),
		Zapret:     filepath.Join(root, "zapret"),
		Data:       data,
		Settings:   filepath.Join(data, "settings.json"),
		MihomoHome: filepath.Join(data, "mihomo"),
		Logs:       filepath.Join(data, "logs"),
		Icon:       filepath.Join(root, "lazeyka.ico"),
		IconDir:    filepath.Join(root, "icons"),
		Instance:   filepath.Join(data, "instance.json"),
		Tmp:        filepath.Join(data, "tmp"),
	}
	p.MihomoExe = filepath.Join(p.Bin, mexe)
	if env := os.Getenv("LAZEYKA_MIHOMO"); env != "" && runtime.GOOS != "windows" {
		p.MihomoExe = env
	}
	return p
}

// Job is a background task shown in the UI.
type Job struct {
	Title    string    `json:"title"`
	Running  bool      `json:"running"`
	Progress float64   `json:"progress"` // 0..1, -1 = unknown
	Message  string    `json:"message"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
	Result   any       `json:"result,omitempty"`
}

// App is the whole application state.
type App struct {
	P   Paths
	Dev bool // development mode (no TUN, no Windows bits)

	mu           sync.Mutex
	s            *settings.Settings
	vpn          string // off | connecting | on | error
	vpnErr       string
	vpnSince     time.Time
	zap          string // off | starting | on | error | missing | paused
	zapErr       string
	jobs         map[string]*Job
	up, down     int64
	built        *core.Built
	rt           core.Runtime
	api          *core.API
	fastZapFails int
	reconnects   []time.Time
	lastIfIndex  int
	lastOpen     time.Time
	scores       []zapret.StrategyScore
	loop         loopMeter
	lastLoop     time.Time // last "reject loopback connection" line
	loopMsg      string    // what the user has to switch off (VPN broken)
	otherVPN     string    // another VPN is connected
	nf           *netFix
	refixSaid    time.Time // last "forwarding came back" message
	exit         exitState // country of the blocked-sites exit
	autoTestAt   time.Time // last check of untested servers
	autoTesting  bool
	reach        map[string]reachInfo // why servers failed mihomo's check (reach.go)
	reachLogged  string
	defender     DefenderView
	defenderBusy bool
	self         SelfUpdateView // the last check for a newer Лазейка
	dpiPort      int            // Android: ByeDPI's own SOCKS port
	frontPort    int            // Android: the front that resolves names for ByeDPI (mihomo's ByeDPI proxy)
	front        *byedpi.Front
	dpiMu        sync.Mutex // Android: ByeDPI restarts (strategy selection) without blocking the VPN
	tunFile      *os.File   // Android: our copy of the VPN interface until mihomo has it

	opMu          sync.Mutex // serialises connect/disconnect/zapret operations
	mihomo        *core.Mihomo
	zr            *zapret.Runner
	tray          *platform.Tray
	trafficCancel context.CancelFunc

	ctx    context.Context
	cancel context.CancelFunc

	UIURL      string
	OpenUIHook func()
	QuitHook   func()
}

// New loads settings and prepares components (nothing is started yet).
func New(p Paths, dev bool) (*App, error) {
	for _, d := range []string{p.Root, p.Bin, p.Data, p.MihomoHome, p.Logs, p.Tmp, p.IconDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	_ = logx.Default().SetFile(filepath.Join(p.Logs, "lazeyka.log"))
	s, err := settings.Load(p.Settings)
	if err != nil {
		logx.Warnf("%v", err)
		if s == nil {
			return nil, err
		}
	}
	logx.Default().SetDebug(s.App.Verbose)
	ctx, cancel := context.WithCancel(context.Background())
	a := &App{
		P: p, Dev: dev, s: s, vpn: "off", zap: "off",
		jobs: map[string]*Job{}, ctx: ctx, cancel: cancel,
		mihomo: &core.Mihomo{Bin: p.MihomoExe, Home: p.MihomoHome},
		zr:     &zapret.Runner{},
		nf:     newNetFix(filepath.Join(p.Data, "netfix.json"), systemNetOps()),
	}
	a.mihomo.OnExit = a.onMihomoExit
	a.mihomo.OnLine = a.onMihomoLine
	a.zr.OnExit = a.onZapretExit
	a.initAndroid()
	if err := settings.Save(p.Settings, s); err != nil {
		logx.Warnf("не удалось сохранить настройки: %v", err)
	}
	return a, nil
}

// Settings returns a deep copy of the current settings.
func (a *App) Settings() *settings.Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.s.Clone()
}

// update mutates settings under lock and saves them.
func (a *App) update(fn func(s *settings.Settings) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.s.Clone()
	if err := fn(c); err != nil {
		return err
	}
	c.Normalize()
	if err := settings.Save(a.P.Settings, c); err != nil {
		return err
	}
	a.s = c
	return nil
}

// SetTray attaches the tray icon.
func (a *App) SetTray(t *platform.Tray) { a.tray = t }

// Start brings things up according to settings (non-blocking).
func (a *App) Start(autostart bool) {
	logx.Infof("Лазейка %s запущена (%s, админ: %v)", Version, platform.OSVersion(), platform.IsElevated())
	a.writeInstanceFile()
	a.endNetFix("в прошлый раз Лазейка закрылась, не выключив VPN")
	s := a.Settings()
	go func() {
		if s.Zapret.Enabled {
			if err := a.StartZapret(); err != nil {
				logx.Warnf("zapret: %v", err)
			}
		}
		// Android: ByeDPI alone needs the VPN interface too
		if s.App.AutoConnect && (len(s.Servers) > 0 || len(s.Subscriptions) > 0 || (platform.IsAndroid && s.Zapret.Enabled)) {
			if autostart {
				// give the network a moment after logon
				time.Sleep(3 * time.Second)
			}
			_ = a.Connect() // logs its own errors
		}
	}()
	go a.watchNetwork()
	if s.App.CheckUpdates && !platform.IsAndroid { // Android: engines come with the app
		go func() {
			time.Sleep(90 * time.Second)
			a.CheckEngineUpdates(false)
		}()
	}
	if platform.IsWindows && !a.Dev {
		go func() {
			time.Sleep(5 * time.Second)
			a.refreshDefender()
		}()
		go a.selfUpdateLoop()
	}
	a.refreshTray()
}

// Shutdown stops everything.
func (a *App) Shutdown() {
	a.cancel()
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.stopTraffic()
	a.mihomo.Stop()
	if platform.IsAndroid {
		a.releaseAndroidTun(true)
	}
	a.endNetFix("")
	a.zr.Stop()
	if a.front != nil {
		a.front.Close()
	}
	os.Remove(a.P.Instance)
	logx.Infof("Лазейка завершена")
	logx.Default().Close()
}

// Quit asks the main loop to exit.
func (a *App) Quit() {
	if a.QuitHook != nil {
		a.QuitHook()
	}
}

// OpenUI opens the window (debounced).
func (a *App) OpenUI() {
	a.mu.Lock()
	if time.Since(a.lastOpen) < 2*time.Second {
		a.mu.Unlock()
		return
	}
	a.lastOpen = time.Now()
	a.mu.Unlock()
	if a.OpenUIHook != nil {
		a.OpenUIHook()
	}
}

// --- instance file (lets a second launch ask us to show the window) --------

// InstanceInfo is written to data/instance.json.
type InstanceInfo struct {
	PID   int    `json:"pid"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

var instanceToken = settings.RandomHex(16)

// InstanceToken authenticates second-instance requests.
func InstanceToken() string { return instanceToken }

func (a *App) writeInstanceFile() {
	b, _ := json.Marshal(InstanceInfo{PID: os.Getpid(), URL: a.UIURL, Token: instanceToken})
	_ = os.WriteFile(a.P.Instance, b, 0o600)
}

// SignalInstance asks an already running instance to "show" its window or "quit".
func SignalInstance(p Paths, action string) error {
	b, err := os.ReadFile(p.Instance)
	if err != nil {
		return err
	}
	var info InstanceInfo
	if err := json.Unmarshal(b, &info); err != nil || info.URL == "" {
		return errors.New("нет данных о запущенной копии")
	}
	u, err := url.Parse(info.URL)
	if err != nil {
		return err
	}
	req, _ := http.NewRequest(http.MethodPost, u.Scheme+"://"+u.Host+"/api/instance/"+action, nil)
	req.Header.Set("X-Lz-Instance", info.Token)
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

// --- HWID -----------------------------------------------------------------

func (a *App) hwid(salt string) core.HWID {
	mid := platform.MachineID()
	h := sha256.Sum256([]byte("lazeyka|" + mid + "|" + salt))
	id := core.HWID{
		ID:    hex.EncodeToString(h[:])[:32],
		OS:    "Windows",
		OSVer: platform.OSVersion(),
		Model: "PC",
	}
	if platform.IsAndroid {
		id.OS, id.OSVer, id.Model = "Android", strings.TrimPrefix(platform.OSVersion(), "Android "), os.Getenv("LAZEYKA_MODEL")
		if id.Model == "" {
			id.Model = "Android"
		}
	}
	return id
}

// --- jobs -----------------------------------------------------------------

func (a *App) jobStart(id, title string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if j, ok := a.jobs[id]; ok && j.Running {
		return false
	}
	a.jobs[id] = &Job{Title: title, Running: true, Progress: -1, Started: time.Now()}
	return true
}

func (a *App) jobSet(id string, progress float64, msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if j, ok := a.jobs[id]; ok {
		j.Progress, j.Message = progress, msg
	}
}

func (a *App) jobDone(id string, err error, result any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if j, ok := a.jobs[id]; ok {
		j.Running = false
		j.Finished = time.Now()
		j.Result = result
		if err != nil {
			j.Error = logx.Redact(err.Error())
		} else {
			j.Progress = 1
		}
	}
}

// --- state for UI ---------------------------------------------------------

// Status is the snapshot returned to the UI.
type Status struct {
	Version     string          `json:"version"`
	Platform    string          `json:"platform"` // windows | android | dev
	Dev         bool            `json:"dev"`
	Admin       bool            `json:"admin"`
	VPN         string          `json:"vpn"`
	VPNError    string          `json:"vpn_error,omitempty"`
	VPNSince    time.Time       `json:"vpn_since"`
	Update      string          `json:"update,omitempty"`     // a newer Лазейка is out
	VPNWarn     string          `json:"vpn_warn,omitempty"`   // something on the computer gets in the way
	VPNBroken   bool            `json:"vpn_broken,omitempty"` // ...so badly that nothing works
	Zapret      string          `json:"zapret"`
	ZapretError string          `json:"zapret_error,omitempty"`
	Strategy    string          `json:"strategy"`
	Up          int64           `json:"up"`
	Down        int64           `json:"down"`
	HasVPN      bool            `json:"has_vpn"`
	Servers     int             `json:"servers"`
	Subs        int             `json:"subs"`
	Mihomo      bool            `json:"mihomo_installed"`
	ZapretInst  bool            `json:"zapret_installed"`
	Jobs        map[string]*Job `json:"jobs"`
	Onboarded   bool            `json:"onboarded"`
	ZapretOn    bool            `json:"zapret_enabled"`
}

// Status returns the current state.
func (a *App) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	jobs := map[string]*Job{}
	for k, v := range a.jobs {
		c := *v
		jobs[k] = &c
	}
	_, mErr := os.Stat(a.P.MihomoExe)
	st := Status{
		Version: Version, Dev: a.Dev, Admin: platform.IsElevated(),
		VPN: a.vpn, VPNError: a.vpnErr, VPNSince: a.vpnSince,
		Zapret: a.zap, ZapretError: a.zapErr, Strategy: a.s.Zapret.Strategy,
		Up: a.up, Down: a.down,
		Servers: len(a.s.Servers), Subs: len(a.s.Subscriptions),
		Mihomo: mErr == nil, ZapretInst: a.dpiInstalled(), Platform: platformName(a.Dev),
		Jobs: jobs, Onboarded: a.s.App.Onboarded, ZapretOn: a.s.Zapret.Enabled,
	}
	st.HasVPN = st.Servers > 0 || st.Subs > 0
	if a.self.Latest != "" && update.NewerVersion(Version, a.self.Latest) {
		st.Update = a.self.Latest
	}
	if a.vpn == "on" || a.vpn == "connecting" {
		switch {
		case a.loopMsg != "":
			st.VPNWarn, st.VPNBroken = a.loopMsg, true
		case a.otherVPN != "":
			st.VPNWarn = a.otherVPN
		}
	}
	return st
}

func (a *App) setVPN(state, errText string) {
	errText = logx.Redact(errText)
	a.mu.Lock()
	prev := a.vpn
	a.vpn, a.vpnErr = state, errText
	if state == "on" && prev != "on" {
		a.vpnSince = time.Now()
	}
	if state != "on" {
		a.up, a.down = 0, 0
	}
	// zapret waits while the VPN is on; without the VPN it comes back
	resume := (state == "off" || state == "error") && a.zap == "paused"
	a.mu.Unlock()
	if resume {
		go a.resumeZapret()
	}
	a.refreshTray()
	if a.tray != nil && prev != state {
		switch {
		case state == "error":
			a.tray.Notify("Лазейка: VPN не работает", errText, true)
		case state == "on" && prev == "error":
			a.tray.Notify("Лазейка", "VPN снова работает", false)
		}
	}
}

func (a *App) setZapret(state, errText string) {
	errText = logx.Redact(errText)
	a.mu.Lock()
	prev := a.zap
	a.zap, a.zapErr = state, errText
	a.mu.Unlock()
	a.refreshTray()
	if a.tray != nil && state == "error" && prev != "error" {
		a.tray.Notify("Лазейка: zapret не работает", errText, true)
	}
}

func (a *App) refreshTray() {
	if a.tray == nil {
		return
	}
	a.mu.Lock()
	vpn, zap, verr, broken := a.vpn, a.zap, a.vpnErr, a.loopMsg != ""
	a.mu.Unlock()
	st := platform.TrayState{VPNOn: vpn == "on" || vpn == "connecting", ZapretOn: zap == "on" || zap == "starting"}
	switch vpn {
	case "on":
		st.Mode, st.Status = "on", "VPN включён"
		if c := a.exitCountry(); c != "" {
			st.Status += ", выход: " + countryName(c)
		}
		if broken {
			st.Mode, st.Status = "err", "VPN не работает: подробности в окне"
		}
	case "connecting":
		st.Mode, st.Status = "busy", "Подключение…"
	case "error":
		st.Mode, st.Status = "err", "Ошибка VPN"
	default:
		st.Mode, st.Status = "off", "VPN выключен"
		if zap == "on" {
			st.Status = "Только " + dpiName()
		}
	}
	if zap == "error" && st.Mode != "err" {
		st.Mode = "err"
	}
	st.Tip = "Лазейка — " + st.Status
	if zap == "on" {
		st.Tip += " · " + dpiName()
	}
	if vpn == "error" && verr != "" {
		st.Tip += "\n" + verr
	}
	if len([]rune(st.Tip)) > 120 {
		st.Tip = string([]rune(st.Tip)[:120])
	}
	a.tray.Update(st)
}

func platformName(dev bool) string {
	switch {
	case platform.IsAndroid:
		return "android"
	case dev || !platform.IsWindows:
		return "dev"
	}
	return "windows"
}
