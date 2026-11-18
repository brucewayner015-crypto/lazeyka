package app

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"lazeyka/internal/core"
	"lazeyka/internal/importer"
	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
	"lazeyka/internal/zapret"
)

// Import parses pasted text or a file (does not save anything).
func (a *App) Import(text, filename string) importer.Result {
	r := importer.Parse(text, filename)
	if r.Items == nil {
		r.Items = []importer.Item{}
	}
	if r.Errors == nil {
		r.Errors = []string{}
	}
	return r
}

// AddItems stores imported servers and subscriptions, skipping duplicates.
func (a *App) AddItems(items []importer.Item) (int, error) {
	added := 0
	hadVPN := false
	err := a.update(func(s *settings.Settings) error {
		hadVPN = len(s.Servers) > 0 || len(s.Subscriptions) > 0
		for _, it := range items {
			switch {
			case it.Server != nil:
				srv := *it.Server
				dup := false
				for _, e := range s.Servers {
					if (srv.Kind == settings.KindLink && e.Link == srv.Link) ||
						(srv.Kind == settings.KindAWG && e.Kind == settings.KindAWG && e.Host == srv.Host && e.Port == srv.Port && fmt.Sprint(e.Proxy["private-key"]) == fmt.Sprint(srv.Proxy["private-key"])) {
						dup = true
					}
				}
				if dup {
					continue
				}
				if srv.ID == "" || s.ServerByID(srv.ID) != nil {
					srv.ID = settings.RandomHex(4)
				}
				if srv.Added.IsZero() {
					srv.Added = time.Now()
				}
				srv.Enabled = true
				s.Servers = append(s.Servers, srv)
				added++
			case it.Subscription != nil:
				sub := *it.Subscription
				dup := false
				for _, e := range s.Subscriptions {
					if e.URL == sub.URL {
						dup = true
					}
				}
				if dup {
					continue
				}
				if sub.ID == "" || s.SubscriptionByID(sub.ID) != nil {
					sub.ID = settings.RandomHex(4)
				}
				sub.Enabled = true
				s.Subscriptions = append(s.Subscriptions, sub)
				added++
			}
		}
		if added > 0 {
			s.App.Onboarded = true
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if added > 0 {
		logx.Infof("добавлено: %d", added)
		a.afterServersChanged()
		// the very first servers: switch the VPN on right away
		if !hadVPN && !a.Connected() && a.Settings().App.AutoConnect {
			go a.Connect() // logs its own errors
		}
	}
	return added, nil
}

func (a *App) afterServersChanged() {
	if a.Connected() {
		a.ApplyAsync()
	}
	go a.RefreshZapretExcludes()
}

// ServerPatch changes a server.
type ServerPatch struct {
	ID      string  `json:"id"`
	Name    *string `json:"name"`
	Enabled *bool   `json:"enabled"`
	Move    int     `json:"move"` // -1 up, +1 down
	Delete  bool    `json:"delete"`
}

// PatchServer applies a change to one server.
func (a *App) PatchServer(p ServerPatch) error {
	var forget *settings.AmneziaRef
	err := a.update(func(s *settings.Settings) error {
		idx := -1
		for i := range s.Servers {
			if s.Servers[i].ID == p.ID {
				idx = i
			}
		}
		if idx < 0 {
			return errors.New("сервер не найден")
		}
		if p.Delete {
			forget = s.Servers[idx].Amnezia
			s.Servers = append(s.Servers[:idx], s.Servers[idx+1:]...)
			return nil
		}
		if p.Name != nil {
			n := strings.TrimSpace(*p.Name)
			if n == "" {
				return errors.New("имя не может быть пустым")
			}
			s.Servers[idx].Name = n
		}
		if p.Enabled != nil {
			s.Servers[idx].Enabled = *p.Enabled
		}
		if p.Move != 0 {
			j := idx + p.Move
			if j >= 0 && j < len(s.Servers) {
				s.Servers[idx], s.Servers[j] = s.Servers[j], s.Servers[idx]
			}
		}
		return nil
	})
	if err == nil {
		a.afterServersChanged()
		if forget != nil { // an Amnezia Premium location: free its slot
			go a.amneziaForget(*forget)
		}
	}
	return err
}

// SubPatch changes a subscription.
type SubPatch struct {
	ID            string  `json:"id"`
	Name          *string `json:"name"`
	URL           *string `json:"url"`
	Enabled       *bool   `json:"enabled"`
	HWID          *bool   `json:"hwid"`
	ViaVPN        *bool   `json:"via_vpn"`
	UserAgent     *string `json:"user_agent"`
	IntervalHours *int    `json:"interval_hours"`
	Prefix        *string `json:"prefix"`
	RenameText    *string `json:"rename_text"` // "что → на что", one rule per line
	HideText      *string `json:"hide_text"`   // words, one per line or comma-separated
	Delete        bool    `json:"delete"`
}

// ParseRenameText reads rename rules written one per line as "что → на что"
// ("->" and "=>" work too; an empty right side deletes the text).
func ParseRenameText(text string) ([]settings.Rename, error) {
	rules := []settings.Rename{}
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cut := -1
		var sep string
		for _, s := range []string{"→", "=>", "->"} {
			if j := strings.Index(line, s); j >= 0 && (cut < 0 || j < cut) {
				cut, sep = j, s
			}
		}
		if cut < 0 {
			return nil, fmt.Errorf("строка %d («%s»): нужна стрелка, например: Netherlands → Нидерланды", i+1, line)
		}
		from := strings.TrimSpace(line[:cut])
		to := strings.TrimSpace(line[cut+len(sep):])
		if from == "" {
			return nil, fmt.Errorf("строка %d: слева от стрелки пусто", i+1)
		}
		rules = append(rules, settings.Rename{From: from, To: to})
	}
	if _, err := core.RenameRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// ParseHideText reads hide words (one per line or comma-separated).
func ParseHideText(text string) []string {
	words := []string{}
	seen := map[string]bool{}
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		w = strings.TrimSpace(w)
		if w == "" || seen[strings.ToLower(w)] {
			continue
		}
		seen[strings.ToLower(w)] = true
		words = append(words, w)
	}
	return words
}

// PatchSubscription applies a change to one subscription.
func (a *App) PatchSubscription(p SubPatch) error {
	err := a.update(func(s *settings.Settings) error {
		idx := -1
		for i := range s.Subscriptions {
			if s.Subscriptions[i].ID == p.ID {
				idx = i
			}
		}
		if idx < 0 {
			return errors.New("подписка не найдена")
		}
		if p.Delete {
			s.Subscriptions = append(s.Subscriptions[:idx], s.Subscriptions[idx+1:]...)
			return nil
		}
		sub := &s.Subscriptions[idx]
		if p.Name != nil && strings.TrimSpace(*p.Name) != "" {
			sub.Name = strings.TrimSpace(*p.Name)
		}
		if p.URL != nil {
			u := strings.TrimSpace(*p.URL)
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				return errors.New("адрес подписки должен начинаться с https://")
			}
			sub.URL = u
		}
		if p.Enabled != nil {
			sub.Enabled = *p.Enabled
		}
		if p.HWID != nil {
			sub.HWID = *p.HWID
		}
		if p.ViaVPN != nil {
			sub.ViaVPN = *p.ViaVPN
		}
		if p.UserAgent != nil && strings.TrimSpace(*p.UserAgent) != "" {
			sub.UserAgent = strings.TrimSpace(*p.UserAgent)
		}
		if p.IntervalHours != nil && *p.IntervalHours > 0 && *p.IntervalHours <= 168 {
			sub.IntervalHours = *p.IntervalHours
		}
		if p.Prefix != nil {
			pre := *p.Prefix
			if len([]rune(pre)) > 24 {
				return errors.New("метка слишком длинная (до 24 символов)")
			}
			sub.Prefix = &pre
		}
		if p.RenameText != nil {
			rules, err := ParseRenameText(*p.RenameText)
			if err != nil {
				return err
			}
			sub.Rename = rules
		}
		if p.HideText != nil {
			sub.Hide = ParseHideText(*p.HideText)
		}
		return nil
	})
	if err == nil && a.Connected() {
		a.ApplyAsync()
	}
	return err
}

// SetRouting replaces routing settings and re-applies.
func (a *App) SetRouting(r settings.Routing) error {
	clean := func(l []string) []string {
		var out []string
		seen := map[string]bool{}
		for _, x := range l {
			x = strings.TrimSpace(x)
			if x == "" || strings.HasPrefix(x, "#") || seen[strings.ToLower(x)] {
				continue
			}
			seen[strings.ToLower(x)] = true
			out = append(out, x)
		}
		if out == nil {
			out = []string{}
		}
		return out
	}
	r.CustomVPN, r.CustomDirect = clean(r.CustomVPN), clean(r.CustomDirect)
	r.DirectApps, r.DirectPaths = clean(r.DirectApps), clean(r.DirectPaths)
	r.TorrentApps, r.GameApps = clean(r.TorrentApps), clean(r.GameApps)
	if bad := append(core.BadCustomEntries(r.CustomVPN), core.BadCustomEntries(r.CustomDirect)...); len(bad) > 0 {
		return fmt.Errorf("не понял строки: %s. В каждой строке нужен домен, адрес сайта, IP или подсеть", zapret.QuoteList(bad, 5))
	}
	for _, list := range [][]string{r.DirectApps, r.TorrentApps, r.GameApps} {
		for _, n := range list {
			if strings.ContainsAny(n, `\/:*?"<>|`) {
				return fmt.Errorf("«%s» — нужно только имя файла программы, например steam.exe", n)
			}
		}
	}
	err := a.update(func(s *settings.Settings) error {
		r.BlockedSelect, r.AISelect = s.Routing.BlockedSelect, s.Routing.AISelect
		s.Routing = r
		return nil
	})
	if err != nil {
		return err
	}
	return a.Apply()
}

// AppPatch changes app settings.
type AppPatch struct {
	Autostart      *bool   `json:"autostart"`
	AutoConnect    *bool   `json:"auto_connect"`
	StartMinimized *bool   `json:"start_minimized"`
	CheckUpdates   *bool   `json:"check_updates"`
	Verbose        *bool   `json:"verbose"`
	MixedPort      *int    `json:"mixed_port"`
	TunStack       *string `json:"tun_stack"`
	Onboarded      *bool   `json:"onboarded"`
}

// UIPatch changes window preferences (nil = keep).
type UIPatch struct {
	Collapsed    *bool `json:"panel_collapsed"`
	HideServer   *bool `json:"hide_server"`
	HideStrategy *bool `json:"hide_strategy"`
	HideCountry  *bool `json:"hide_country"`
	HidePing     *bool `json:"hide_ping"`
	HideSpeed    *bool `json:"hide_speed"`
	HideUptime   *bool `json:"hide_uptime"`
}

// SetUI saves window preferences.
func (a *App) SetUI(p UIPatch) error {
	return a.update(func(s *settings.Settings) error {
		for _, f := range []struct {
			v   *bool
			dst *bool
		}{
			{p.Collapsed, &s.UI.Collapsed}, {p.HideServer, &s.UI.HideServer}, {p.HideStrategy, &s.UI.HideStrategy},
			{p.HideCountry, &s.UI.HideCountry}, {p.HidePing, &s.UI.HidePing}, {p.HideSpeed, &s.UI.HideSpeed},
			{p.HideUptime, &s.UI.HideUptime},
		} {
			if f.v != nil {
				*f.dst = *f.v
			}
		}
		return nil
	})
}

// SetApp applies app settings.
func (a *App) SetApp(p AppPatch) error {
	var autostartChanged, needApply bool
	var autostart bool
	err := a.update(func(s *settings.Settings) error {
		if p.Autostart != nil && *p.Autostart != s.App.Autostart {
			s.App.Autostart, autostartChanged, autostart = *p.Autostart, true, *p.Autostart
		}
		if p.AutoConnect != nil {
			s.App.AutoConnect = *p.AutoConnect
		}
		if p.StartMinimized != nil {
			s.App.StartMinimized = *p.StartMinimized
		}
		if p.CheckUpdates != nil {
			s.App.CheckUpdates = *p.CheckUpdates
		}
		if p.Verbose != nil && *p.Verbose != s.App.Verbose {
			s.App.Verbose, needApply = *p.Verbose, true
		}
		if p.MixedPort != nil && *p.MixedPort != s.App.MixedPort {
			if *p.MixedPort != 0 && (*p.MixedPort < 1024 || *p.MixedPort > 65535) {
				return errors.New("порт должен быть от 1024 до 65535 или 0")
			}
			s.App.MixedPort, needApply = *p.MixedPort, true
		}
		if p.TunStack != nil && *p.TunStack != s.App.TunStack {
			s.App.TunStack, needApply = *p.TunStack, true
		}
		if p.Onboarded != nil {
			s.App.Onboarded = *p.Onboarded
		}
		return nil
	})
	if err != nil {
		return err
	}
	logxSetDebug(a.Settings().App.Verbose)
	if autostartChanged && platform.IsWindows && !a.Dev {
		if err := platform.SetAutostart(a.P.Exe, autostart, a.P.Tmp); err != nil {
			return fmt.Errorf("автозапуск: %w", err)
		}
	}
	if needApply {
		return a.Apply()
	}
	return nil
}

func logxSetDebug(on bool) { logx.Default().SetDebug(on) }
