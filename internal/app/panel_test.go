package app

import (
	"strings"
	"testing"

	"lazeyka/internal/zapret"
)

func TestParseTrace(t *testing.T) {
	c, ip, err := parseTrace(strings.NewReader("fl=123\nh=www.cloudflare.com\nip=203.0.113.7\nts=1.2\nloc=de\ncolo=FRA\n"))
	if err != nil || c != "DE" || ip != "203.0.113.7" {
		t.Fatalf("got %q %q %v", c, ip, err)
	}
	for _, bad := range []string{"ip=1.2.3.4\n", "loc=XX\n", "loc=T1\n", "loc=deu\n", ""} {
		if c, _, err := parseTrace(strings.NewReader(bad)); err == nil {
			t.Errorf("%q: country %q accepted", bad, c)
		}
	}
}

func TestRankStrategies(t *testing.T) {
	list := []zapret.Strategy{
		{File: "general.bat", Name: "general"}, {File: "a.bat", Name: "a"}, {File: "b.bat", Name: "b"},
		{File: "c.bat", Name: "c"}, {File: "d.bat", Name: "d"}, {File: "e.bat", Name: "e"},
	}
	scores := []zapret.StrategyScore{
		{File: "", Summary: zapret.Summary{OK: 2, Total: 8}}, // without zapret
		{File: "a.bat", Summary: zapret.Summary{OK: 5, Total: 8, AvgMs: 300}},
		{File: "b.bat", Summary: zapret.Summary{OK: 8, Total: 8, AvgMs: 400}},
		{File: "c.bat", Summary: zapret.Summary{OK: 8, Total: 8, AvgMs: 250}},
		{File: "d.bat", Err: "winws завершился"},
		{File: "general.bat", Summary: zapret.Summary{OK: 0, Total: 8}},
		{File: "gone.bat", Summary: zapret.Summary{OK: 8, Total: 8}}, // removed in a zapret update
	}
	got := rankStrategies(list, scores)
	var order []string
	for _, r := range got {
		order = append(order, r.Name)
	}
	if strings.Join(order, " ") != "c b a general d e" {
		t.Fatalf("order: %v", order)
	}
	if !got[0].Works() || got[3].Works() || got[4].Failed == "" || got[5].Checked {
		t.Fatalf("flags: %+v", got)
	}
}

func TestTrayServerItems(t *testing.T) {
	g := GroupView{Name: "BLOCKED", Now: "Мой AWG", Options: []OptionView{
		{Name: "AUTO", Kind: "group"}, {Name: "OWN", Kind: "group"}, {Name: "SUB", Kind: "group"},
		{Name: "DIRECT", Kind: "direct"}, {Name: "REJECT", Kind: "reject"},
		{Name: "Мой AWG", Kind: "own", Delay: 38, Alive: true},
		{Name: "Германия & Ко", Kind: "sub", Delay: 0, Alive: false},
	}}
	items := serverItems(g)
	var b strings.Builder
	for _, it := range items {
		switch {
		case it.Separator:
			b.WriteString("|")
		case it.Caption:
			b.WriteString("[" + it.Label + "]")
		default:
			mark := ""
			if it.Checked {
				mark = "*"
			}
			b.WriteString(mark + it.Label + "(" + it.Note + ");")
		}
	}
	want := "Авто: свои, затем подписка();Любой свой сервер();Любой из подписки();Напрямую (не обходить)();|[Свои серверы]*Мой AWG(38 мс);|[Подписка]Германия & Ко(нет ответа);"
	if b.String() != want {
		t.Fatalf("got  %s\nwant %s", b.String(), want)
	}
	if items[6].Key != "Мой AWG" {
		t.Fatalf("key: %+v", items[6])
	}
}

func TestTrayStrategyItems(t *testing.T) {
	v := StrategiesView{Installed: true, Current: "b.bat", List: []RankedStrategy{
		{File: "a.bat", Name: "a", Checked: true, OK: 8, Total: 8},
		{File: "b.bat", Name: "b", Checked: true, OK: 3, Total: 8},
		{File: "c.bat", Name: "c", Checked: true},
		{File: "d.bat", Name: "d"},
	}}
	items := strategyItems(v)
	var parts []string
	for _, it := range items {
		if it.Separator {
			parts = append(parts, "|")
			continue
		}
		s := it.Label + ":" + it.Note
		if it.Checked {
			s = "*" + s
		}
		parts = append(parts, s)
	}
	if got := strings.Join(parts, " "); got != "a:8 из 8 *b:3 из 8 | c:не помогла d:" {
		t.Fatalf("got %q", got)
	}
	// nothing checked yet: no separator
	v.List = []RankedStrategy{{File: "a.bat", Name: "a"}, {File: "b.bat", Name: "b"}}
	for _, it := range strategyItems(v) {
		if it.Separator {
			t.Fatal("separator without results")
		}
	}
}

func TestCountryName(t *testing.T) {
	if countryName("DE") != "Германия" || countryName("QQ") != "QQ" {
		t.Fatal(countryName("DE"), countryName("QQ"))
	}
}

func TestUIAndScoresPersist(t *testing.T) {
	p := NewPaths(t.TempDir())
	a, err := New(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if ui := a.Settings().UI; ui.Collapsed || ui.HideSpeed || ui.HideCountry {
		t.Fatalf("defaults: %+v", ui)
	}
	yes, no := true, false
	if err := a.SetUI(UIPatch{Collapsed: &yes, HideSpeed: &yes, HidePing: &no}); err != nil {
		t.Fatal(err)
	}
	a.setScores([]zapret.StrategyScore{{File: "a.bat", Summary: zapret.Summary{OK: 7, Total: 8}, Results: []zapret.CheckResult{{Name: "x", OK: true}}}})
	a.recordScore("b.bat", zapret.Summary{OK: 8, Total: 8})
	a.recordScore("a.bat", zapret.Summary{OK: 2, Total: 8})

	b, err := New(p, true) // the next start
	if err != nil {
		t.Fatal(err)
	}
	if ui := b.Settings().UI; !ui.Collapsed || !ui.HideSpeed || ui.HidePing {
		t.Fatalf("ui after restart: %+v", ui)
	}
	got := b.strategyScores()
	if len(got) != 2 || got[0].File != "a.bat" || got[0].Summary.OK != 2 || got[1].File != "b.bat" || got[0].Results != nil {
		t.Fatalf("scores after restart: %+v", got)
	}
}
