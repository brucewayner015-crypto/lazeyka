// Package settings holds the persistent user configuration.
package settings

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Server kinds.
const (
	KindLink = "link" // any share link mihomo understands (vless://, trojan://, hysteria2://, ss://, vmess://...)
	KindAWG  = "awg"  // AmneziaWG / WireGuard, stored as a ready mihomo proxy map
)

// Server is one of the user's own servers. Order in Settings.Servers is priority.
type Server struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Kind    string         `json:"kind"`
	Link    string         `json:"link,omitempty"`
	Proxy   map[string]any `json:"proxy,omitempty"`
	Enabled bool           `json:"enabled"`
	Source  string         `json:"source,omitempty"` // how it was imported, for display
	Info    string         `json:"info,omitempty"`   // short human summary: "VLESS · XHTTP · Reality"
	Host    string         `json:"host,omitempty"`
	Port    int            `json:"port,omitempty"`
	Added   time.Time      `json:"added"`
}

// UDPFriendly reports whether the server carries UDP natively (good for calls).
func (s Server) UDPFriendly() bool {
	if s.Kind == KindAWG {
		return true
	}
	l := strings.ToLower(s.Link)
	return strings.HasPrefix(l, "hysteria2://") || strings.HasPrefix(l, "hy2://") || strings.HasPrefix(l, "tuic://")
}

// Subscription is a third-party subscription URL.
type Subscription struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Enabled       bool      `json:"enabled"`
	UserAgent     string    `json:"user_agent"`
	HWID          bool      `json:"hwid"`
	ViaVPN        bool      `json:"via_vpn"`
	IntervalHours int       `json:"interval_hours"`
	ExcludeFilter string    `json:"exclude_filter,omitempty"` // legacy, replaced by Hide
	Added         time.Time `json:"added"`

	// Hide: servers whose name contains one of these words are not used on
	// this computer. Prefix and Rename are kept from 0.1.5 but no longer
	// applied: renaming lives in Связка, the user's subscription service.
	Prefix *string  `json:"prefix,omitempty"`
	Rename []Rename `json:"rename"`
	Hide   []string `json:"hide"`
}

// Rename replaces From with To in server names. From written as /…/ is a
// regular expression (To may then use $1); otherwise it is plain text.
type Rename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// DefaultSubPrefix marks subscription servers in lists.
const DefaultSubPrefix = "◇ "

// PrefixOrDefault is the label put before this subscription's server names.
func (s Subscription) PrefixOrDefault() string {
	if s.Prefix == nil {
		return DefaultSubPrefix
	}
	return *s.Prefix
}

// DefaultHide: informational pseudo-servers ("осталось 3 дня", "наш канал")
// and Russian exits, which make no sense for a VPN from Russia. Words of up
// to three Latin letters match whole words only ("RU" but not "Peru").
var DefaultHide = []string{"осталось", "истекает", "истёк", "expire", "traffic", "трафик", "сайт", "website",
	"канал", "telegram", "телеграм", "support", "поддержк", "продл", "обнов", "подписк", "RU", "🇷🇺",
	"росси", "russia", "москв", "moscow", "питер", "санкт"}

// Routing modes.
const (
	ModeZapret = "zapret" // direct, zapret handles DPI
	ModeDirect = "direct"
	ModeVPN    = "vpn"
	ModeOwn    = "own" // only own servers
)

// Routing controls where each kind of traffic goes.
type Routing struct {
	YouTube       string   `json:"youtube"`    // zapret | vpn
	Discord       string   `json:"discord"`    // zapret | vpn
	Messengers    string   `json:"messengers"` // vpn | direct
	AI            string   `json:"ai"`         // own | vpn
	Other         string   `json:"other"`      // direct | vpn
	HODCA         bool     `json:"hodca"`      // sites on Hetzner/OVH/DO/Cloudflare/AWS that break from RU
	BlockQUIC     bool     `json:"block_quic"` // force TCP for blocked sites going through VPN
	UDPDirect     bool     `json:"udp_direct"` // remaining UDP (games, calls) always direct
	CustomVPN     []string `json:"custom_vpn"`
	CustomDirect  []string `json:"custom_direct"`
	DirectApps    []string `json:"direct_apps"`  // process names that always go direct (Russian apps)
	DirectPaths   []string `json:"direct_paths"` // path fragments that always go direct
	TorrentApps   []string `json:"torrent_apps"`
	GameApps      []string `json:"game_apps"`
	BlockedSelect string   `json:"blocked_select"` // manual choice for blocked traffic ("" = auto)
	AISelect      string   `json:"ai_select"`
}

// Zapret settings.
type Zapret struct {
	Enabled      bool   `json:"enabled"`
	Strategy     string `json:"strategy"`    // file name, e.g. "general (ALT).bat"
	GameFilter   string `json:"game_filter"` // disabled | all | tcp | udp
	IPSet        string `json:"ipset"`       // none | loaded | any
	BindPhysical bool   `json:"bind_physical"`
	Version      string `json:"version"`
	AutoTuned    bool   `json:"auto_tuned"` // the one-time check after the first start was done
	// PauseWithVPN: on some computers packets that zapret re-sends end up in
	// the VPN tunnel, and the VPN's own connections loop back into it. ""
	// means "detect": Лазейка switches it to "on" when it sees that.
	PauseWithVPN string `json:"pause_with_vpn"` // "" | on | off
}

// App settings.
type App struct {
	Autostart      bool   `json:"autostart"`
	AutoConnect    bool   `json:"auto_connect"`
	StartMinimized bool   `json:"start_minimized"`
	CheckUpdates   bool   `json:"check_updates"`
	Verbose        bool   `json:"verbose"`
	MixedPort      int    `json:"mixed_port"` // 0 = disabled
	TunStack       string `json:"tun_stack"`  // mixed | system | gvisor
	MihomoVersion  string `json:"mihomo_version"`
	WasConnected   bool   `json:"was_connected"`
	Onboarded      bool   `json:"onboarded"`
}

// Settings is the whole persistent state.
type Settings struct {
	Version       int            `json:"version"`
	Servers       []Server       `json:"servers"`
	Subscriptions []Subscription `json:"subscriptions"`
	Routing       Routing        `json:"routing"`
	Zapret        Zapret         `json:"zapret"`
	App           App            `json:"app"`
	UI            UI             `json:"ui"`
	Secret        string         `json:"secret"`
	HWIDSalt      string         `json:"hwid_salt"`
}

// UI holds window preferences: what the panel on the left shows under the
// VPN and zapret switches (everything by default).
type UI struct {
	Collapsed    bool `json:"panel_collapsed"` // only the switches
	HideServer   bool `json:"hide_server"`
	HideStrategy bool `json:"hide_strategy"`
	HideCountry  bool `json:"hide_country"`
	HidePing     bool `json:"hide_ping"`
	HideSpeed    bool `json:"hide_speed"`
	HideUptime   bool `json:"hide_uptime"`
}

// DefaultUserAgent is sent to subscription servers. Panels such as Remnawave
// pick the output format by User-Agent; "clash"/"mihomo" yields full mihomo YAML.
const DefaultUserAgent = "clash.meta/mihomo Lazeyka/0.1"

// Default returns a fresh configuration.
func Default() *Settings {
	return &Settings{
		Version: 2,
		Routing: Routing{
			YouTube:      ModeZapret,
			Discord:      ModeZapret,
			Messengers:   ModeVPN,
			AI:           ModeOwn,
			Other:        ModeDirect,
			HODCA:        true,
			BlockQUIC:    true,
			UDPDirect:    true,
			CustomVPN:    []string{},
			CustomDirect: []string{},
			DirectApps: []string{
				"avp.exe", "avpui.exe", // Kaspersky
				"1cv8.exe", "1cv8c.exe", "1cv8s.exe", // 1С
				"YandexDisk2.exe",
			},
			DirectPaths: []string{
				`\Yandex\YandexBrowser\`,
				`\Programs\YandexMusic\`,
			},
			TorrentApps: []string{
				"qbittorrent.exe", "utorrent.exe", "utweb.exe", "bittorrent.exe", "transmission-qt.exe",
				"transmission-daemon.exe", "tixati.exe", "deluge.exe", "deluged.exe", "biglybt.exe",
				"bitcomet.exe", "aria2c.exe", "motrix.exe", "picotorrent.exe", "fdm.exe",
			},
			GameApps: []string{
				"steam.exe", "steamwebhelper.exe", "steamservice.exe", "EpicGamesLauncher.exe",
				"EpicWebHelper.exe", "Battle.net.exe", "RiotClientServices.exe", "RiotClientUx.exe",
				"LeagueClient.exe", "EADesktop.exe", "EABackgroundService.exe", "GalaxyClient.exe",
				"upc.exe", "UbisoftConnect.exe", "lgc.exe", "wgc.exe", "GameCenter.exe",
			},
		},
		Zapret: Zapret{
			Enabled:      true,
			Strategy:     "general.bat",
			GameFilter:   "disabled",
			IPSet:        "none",
			BindPhysical: true,
		},
		App: App{
			Autostart:      true,
			AutoConnect:    true,
			StartMinimized: true,
			CheckUpdates:   true,
			MixedPort:      0,
			TunStack:       "mixed",
		},
	}
}

// Normalize fills missing or invalid values (for files written by older versions).
func (s *Settings) Normalize() {
	d := Default()
	if s.Version == 0 {
		s.Version = 1
	}
	if s.Version < 2 {
		// 0.1.8 paused zapret for the VPN when the VPN's connections looped
		// back into the tunnel; the usual cause turned out to be forwarding
		// on the network card, which 0.1.9 switches off. Let zapret and the
		// VPN work together again (the pause comes back if still needed).
		if s.Zapret.PauseWithVPN == "on" {
			s.Zapret.PauseWithVPN = ""
		}
		s.Version = 2
	}
	if s.Servers == nil {
		s.Servers = []Server{}
	}
	if s.Subscriptions == nil {
		s.Subscriptions = []Subscription{}
	}
	r := &s.Routing
	pick := func(v *string, def string, allowed ...string) {
		for _, a := range allowed {
			if *v == a {
				return
			}
		}
		*v = def
	}
	pick(&r.YouTube, d.Routing.YouTube, ModeZapret, ModeVPN, ModeDirect)
	pick(&r.Discord, d.Routing.Discord, ModeZapret, ModeVPN)
	pick(&r.Messengers, d.Routing.Messengers, ModeVPN, ModeDirect)
	pick(&r.AI, d.Routing.AI, ModeOwn, ModeVPN)
	pick(&r.Other, d.Routing.Other, ModeDirect, ModeVPN)
	if r.CustomVPN == nil {
		r.CustomVPN = []string{}
	}
	if r.CustomDirect == nil {
		r.CustomDirect = []string{}
	}
	if r.DirectApps == nil {
		r.DirectApps = d.Routing.DirectApps
	}
	if r.DirectPaths == nil {
		r.DirectPaths = d.Routing.DirectPaths
	}
	if r.TorrentApps == nil {
		r.TorrentApps = d.Routing.TorrentApps
	}
	if r.GameApps == nil {
		r.GameApps = d.Routing.GameApps
	}
	z := &s.Zapret
	if z.Strategy == "" {
		z.Strategy = d.Zapret.Strategy
	}
	pick(&z.GameFilter, "disabled", "disabled", "all", "tcp", "udp")
	pick(&z.IPSet, "none", "none", "loaded", "any")
	pick(&s.App.TunStack, "mixed", "mixed", "system", "gvisor")
	if s.App.MixedPort < 0 || s.App.MixedPort > 65535 {
		s.App.MixedPort = 0
	}
	if s.Secret == "" {
		s.Secret = RandomHex(24)
	}
	if s.HWIDSalt == "" {
		s.HWIDSalt = RandomHex(8)
	}
	for i := range s.Subscriptions {
		sub := &s.Subscriptions[i]
		if sub.ID == "" {
			sub.ID = RandomHex(4)
		}
		if sub.UserAgent == "" {
			sub.UserAgent = DefaultUserAgent
		}
		if sub.IntervalHours <= 0 {
			sub.IntervalHours = 6
		}
		if sub.Hide == nil { // older settings had only the fixed filter
			sub.Hide = append([]string{}, DefaultHide...)
			sub.ExcludeFilter = ""
		}
		if sub.Rename == nil {
			sub.Rename = []Rename{}
		}
	}
	for i := range s.Servers {
		if s.Servers[i].ID == "" {
			s.Servers[i].ID = RandomHex(4)
		}
	}
}

// Load reads settings from path; a missing file yields defaults.
func Load(path string) (*Settings, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s := Default()
		s.Normalize()
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	s := Default()
	// Start from defaults so new fields get sane values, but lists from the
	// file replace defaults entirely.
	s.Routing.DirectApps, s.Routing.DirectPaths, s.Routing.TorrentApps, s.Routing.GameApps = nil, nil, nil, nil
	s.Routing.CustomDirect = nil
	if err := json.Unmarshal(b, s); err != nil {
		// keep a copy of the broken file for diagnostics and start clean
		_ = os.WriteFile(path+".broken", b, 0o600)
		d := Default()
		d.Normalize()
		return d, errors.New("файл настроек повреждён, загружены значения по умолчанию")
	}
	s.Normalize()
	return s, nil
}

// Save writes settings atomically.
func Save(path string, s *Settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Clone returns a deep copy (via JSON).
func (s *Settings) Clone() *Settings {
	b, _ := json.Marshal(s)
	c := &Settings{}
	_ = json.Unmarshal(b, c)
	return c
}

// RandomHex returns n random bytes hex-encoded.
func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ServerByID returns a pointer to the server with id.
func (s *Settings) ServerByID(id string) *Server {
	for i := range s.Servers {
		if s.Servers[i].ID == id {
			return &s.Servers[i]
		}
	}
	return nil
}

// SubscriptionByID returns a pointer to the subscription with id.
func (s *Settings) SubscriptionByID(id string) *Subscription {
	for i := range s.Subscriptions {
		if s.Subscriptions[i].ID == id {
			return &s.Subscriptions[i]
		}
	}
	return nil
}
