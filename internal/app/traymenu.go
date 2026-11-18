package app

import (
	"fmt"
	"time"

	"lazeyka/internal/core"
	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
)

// The tray menu's "server" and "strategy" submenus.

// TrayChoices fills the submenus. The tray waits for it while the menu
// opens, so it takes at most a moment.
func (a *App) TrayChoices() platform.TrayChoices {
	var c platform.TrayChoices
	a.mu.Lock()
	vpn := a.vpn
	a.mu.Unlock()
	if vpn != "on" {
		c.ServersNote = "Включите VPN, чтобы выбрать сервер"
	} else if gs, err := a.groups(1500 * time.Millisecond); err != nil {
		c.ServersNote = "Список серверов не загрузился"
	} else {
		for _, g := range gs {
			if g.Name == core.GBlocked {
				c.Servers = serverItems(g)
			}
		}
		if len(c.Servers) == 0 {
			c.ServersNote = "Серверов нет"
		}
	}

	if u := a.SelfUpdate(); u.Available {
		c.Update = u.Latest
	}

	v := a.RankedStrategies()
	switch {
	case !platform.IsWindows:
		c.StrategiesNote = "zapret работает только в Windows"
	case !v.Installed:
		c.StrategiesNote = "zapret ещё не скачан: включите его"
	default:
		c.Strategies = strategyItems(v)
		a.mu.Lock()
		testing := a.jobs["zapret-test"] != nil && a.jobs["zapret-test"].Running
		a.mu.Unlock()
		c.CanAutoPick = !testing && !a.zapretPaused()
	}
	return c
}

// serverItems: the general choices, then own servers, then the
// subscription's, each with its delay.
func serverItems(g GroupView) []platform.TrayItem {
	var fixed, own, sub []platform.TrayItem
	for _, o := range g.Options {
		it := platform.TrayItem{Key: o.Name, Label: o.Name, Checked: o.Name == g.Now}
		switch o.Kind {
		case "reject":
			continue
		case "own", "sub":
			it.Note = delayNote(o.Delay, o.Alive)
			if o.Kind == "own" {
				own = append(own, it)
			} else {
				sub = append(sub, it)
			}
			continue
		}
		if l := choiceLabel(o.Name); l != "" {
			it.Label = l
		}
		fixed = append(fixed, it)
	}
	out := fixed
	for _, part := range []struct {
		title string
		items []platform.TrayItem
	}{{"Свои серверы", own}, {"Подписка", sub}} {
		if len(part.items) == 0 {
			continue
		}
		if len(out) > 0 {
			out = append(out, platform.TrayItem{Separator: true})
		}
		out = append(out, platform.TrayItem{Caption: true, Label: part.title})
		out = append(out, part.items...)
	}
	return out
}

// choiceLabel names the general choices of the "blocked" group (as the window does).
func choiceLabel(name string) string {
	switch name {
	case core.GAuto:
		return "Авто: свои, затем подписка"
	case core.GOwn:
		return "Любой свой сервер"
	case core.GSub:
		return "Любой из подписки"
	case "DIRECT":
		return "Напрямую (не обходить)"
	}
	return ""
}

func delayNote(d int, alive bool) string {
	switch {
	case d > 0:
		return fmt.Sprintf("%d мс", d)
	case !alive:
		return "нет ответа"
	}
	return ""
}

// strategyItems: the strategies that worked first, with their result.
func strategyItems(v StrategiesView) []platform.TrayItem {
	var out []platform.TrayItem
	worked := false
	for i, r := range v.List {
		if i > 0 && worked && !r.Works() {
			out = append(out, platform.TrayItem{Separator: true})
			worked = false
		}
		if r.Works() {
			worked = true
		}
		it := platform.TrayItem{Key: r.File, Label: r.Name, Checked: r.File == v.Current}
		switch {
		case r.Works():
			it.Note = fmt.Sprintf("%d из %d", r.OK, r.Total)
		case r.Checked:
			it.Note = "не помогла"
		}
		out = append(out, it)
	}
	return out
}

// TrayServer: a server picked in the tray menu.
func (a *App) TrayServer(name string) {
	if err := a.Select(core.GBlocked, name); err != nil {
		logx.Warnf("сервер из меню: %v", err)
		if a.tray != nil {
			a.tray.Notify("Лазейка", "Не удалось выбрать сервер: "+err.Error(), true)
		}
	}
}

// TrayStrategy: a strategy picked in the tray menu ("" = pick automatically).
func (a *App) TrayStrategy(file string) {
	var err error
	if file == "" {
		err = a.AutoSelectZapret()
		if err == nil && a.tray != nil {
			a.tray.Notify("Лазейка", "Подбираю стратегию zapret: это займёт пару минут", false)
		}
	} else {
		err = a.SetZapretOptions(&file, nil, nil, nil, nil)
	}
	if err != nil {
		logx.Warnf("стратегия из меню: %v", err)
		if a.tray != nil {
			a.tray.Notify("Лазейка", err.Error(), true)
		}
	}
}

// countryNames: Russian names of the likely exit countries (the rest show
// their code).
var countryNames = map[string]string{
	"AE": "ОАЭ", "AM": "Армения", "AT": "Австрия", "AU": "Австралия", "AZ": "Азербайджан",
	"BE": "Бельгия", "BG": "Болгария", "BR": "Бразилия", "BY": "Беларусь", "CA": "Канада",
	"CH": "Швейцария", "CN": "Китай", "CY": "Кипр", "CZ": "Чехия", "DE": "Германия",
	"DK": "Дания", "EE": "Эстония", "ES": "Испания", "FI": "Финляндия", "FR": "Франция",
	"GB": "Великобритания", "GE": "Грузия", "GR": "Греция", "HK": "Гонконг", "HR": "Хорватия",
	"HU": "Венгрия", "IE": "Ирландия", "IL": "Израиль", "IN": "Индия", "IS": "Исландия",
	"IT": "Италия", "JP": "Япония", "KG": "Киргизия", "KR": "Южная Корея", "KZ": "Казахстан",
	"LT": "Литва", "LU": "Люксембург", "LV": "Латвия", "MD": "Молдова", "MN": "Монголия",
	"NL": "Нидерланды", "NO": "Норвегия", "PL": "Польша", "PT": "Португалия", "RO": "Румыния",
	"RS": "Сербия", "RU": "Россия", "SE": "Швеция", "SG": "Сингапур", "SI": "Словения",
	"SK": "Словакия", "TH": "Таиланд", "TR": "Турция", "TW": "Тайвань", "UA": "Украина",
	"US": "США", "UZ": "Узбекистан", "VN": "Вьетнам", "ZA": "ЮАР",
}

func countryName(code string) string {
	if n, ok := countryNames[code]; ok {
		return n
	}
	return code
}

// TrayUpdate: "update Лазейка" in the tray menu.
func (a *App) TrayUpdate() {
	if err := a.InstallSelfUpdate(); err != nil && a.tray != nil {
		a.tray.Notify("Лазейка", err.Error(), true)
	}
}
