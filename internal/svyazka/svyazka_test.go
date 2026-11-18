package svyazka

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"lazeyka/internal/importer"
)

const (
	vlessNL = "vless://11111111-2222-3333-4444-555555555555@nl.example.net:443?type=xhttp&security=reality&pbk=abc&sni=www.example.com#%F0%9F%87%B3%F0%9F%87%B1%20Netherlands%201"
	vlessDE = "vless://11111111-2222-3333-4444-666666666666@de.example.net:443?type=tcp&security=reality&pbk=abc#Germany"
	trojRU  = "trojan://pass@ru.example.net:443#%F0%9F%87%B7%F0%9F%87%BA%20RU%20Moscow"
	info    = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1#%D0%9E%D1%81%D1%82%D0%B0%D0%BB%D0%BE%D1%81%D1%8C%203%20%D0%B4%D0%BD%D1%8F"
)

func TestParseBody(t *testing.T) {
	plain := strings.Join([]string{vlessNL, "garbage", vlessDE}, "\r\n")
	links, err := ParseBody([]byte(plain))
	if err != nil || len(links) != 2 {
		t.Fatal(links, err)
	}
	// base64, wrapped at 76 columns like some panels do
	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := min(i+76, len(b64))
		wrapped.WriteString(b64[i:end] + "\n")
	}
	links, err = ParseBody([]byte(wrapped.String()))
	if err != nil || len(links) != 2 {
		t.Fatal(links, err)
	}
	if _, err := ParseBody([]byte("proxies:\n  - name: x\n")); err == nil || !strings.Contains(err.Error(), "Clash") {
		t.Fatal(err)
	}
}

func TestCompose(t *testing.T) {
	st := &State{}
	st.normalize()
	st.Upstreams = []Upstream{
		{ID: "a", Enabled: true, Prefix: "A · "},
		{ID: "b", Enabled: true, Prefix: "B · "},
		{ID: "c", Enabled: false},
	}
	st.Rename = []Rename{{From: "Netherlands", To: "Нидерланды"}, {From: "/^(A · )🇩🇪?\\s*Germany$/", To: "${1}🇩🇪 Германия"}}
	st.Hide = append(st.Hide, "RU")
	cache := map[string]*Fetched{
		"a": {Links: []string{vlessNL, info, trojRU}, Userinfo: "upload=1; download=2; total=100; expire=2000"},
		"b": {Links: []string{vlessDE, vlessNL}, Userinfo: "upload=10; download=20; total=50; expire=1000"},
		"c": {Links: []string{vlessDE}},
	}
	snap, err := Compose(st, cache)
	if err != nil {
		t.Fatal(err)
	}
	var shown, hidden []string
	for _, s := range snap.Servers {
		if s.Hidden == "" {
			shown = append(shown, s.Name)
		} else {
			hidden = append(hidden, s.Original+" ("+s.Hidden+")")
		}
	}
	want := []string{"A · 🇳🇱 Нидерланды 1", "B · Germany"}
	if strings.Join(shown, "|") != strings.Join(want, "|") {
		t.Fatalf("shown %q", shown)
	}
	if len(hidden) != 3 { // info by word, RU by word, NL again from b as duplicate
		t.Fatalf("hidden %q", hidden)
	}
	if snap.Userinfo != "upload=11; download=22; total=150; expire=1000" {
		t.Fatal(snap.Userinfo)
	}
	// the served link carries the new name
	if LinkName(snap.Links[0]) != "A · 🇳🇱 Нидерланды 1" {
		t.Fatal(snap.Links[0])
	}
	// hiding by hand survives a rename
	st.Hidden = []string{ServerKey(vlessNL)}
	st.Rename = nil
	snap, _ = Compose(st, cache)
	for _, s := range snap.Servers {
		if s.Key == ServerKey(vlessNL) && s.Source == "a" && s.Hidden != "скрыт вручную" {
			t.Fatal(s)
		}
	}
	// regex group in the rule
	st.Rename = []Rename{{From: "/^B · (.*)$/", To: "$1 (B)"}}
	st.Hidden = nil
	snap, _ = Compose(st, cache)
	found := false
	for _, s := range snap.Servers {
		if s.Name == "Germany (B)" {
			found = true
		}
	}
	if !found {
		t.Fatal(snap.Servers)
	}
}

func TestDuplicateNamesAndVMess(t *testing.T) {
	vm := `{"v":"2","ps":"Same","add":"vm.example.net","port":"443","id":"7777","net":"ws","tls":"tls"}`
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vm))
	other := strings.Replace(vlessDE, "#Germany", "#Same", 1)
	st := &State{}
	st.normalize()
	st.Upstreams = []Upstream{{ID: "a", Enabled: true}}
	snap, err := Compose(st, map[string]*Fetched{"a": {Links: []string{vmess, other}}})
	if err != nil || len(snap.Links) != 2 {
		t.Fatal(snap, err)
	}
	if LinkName(snap.Links[0]) != "Same" || LinkName(snap.Links[1]) != "Same 2" {
		t.Fatal(LinkName(snap.Links[0]), LinkName(snap.Links[1]))
	}
	// vmess key ignores the name
	vm2 := strings.Replace(vm, `"ps":"Same"`, `"ps":"Other"`, 1)
	if ServerKey(vmess) != ServerKey("vmess://"+base64.StdEncoding.EncodeToString([]byte(vm2))) {
		t.Fatal("vmess key depends on the name")
	}
}

func TestRenameText(t *testing.T) {
	r, err := ParseRenameText("Netherlands → Нидерланды\n# comment\n\n🇷🇺 =>\n/x(\\d)/ -> y$1")
	if err != nil || len(r) != 3 || r[1].To != "" {
		t.Fatal(r, err)
	}
	if _, err := ParseRenameText("без стрелки"); err == nil {
		t.Fatal("accepted")
	}
	if _, err := ParseRenameText("/(/ → x"); err == nil {
		t.Fatal("bad regex accepted")
	}
	if w := ParseWords("a, b\nA,,c "); strings.Join(w, "|") != "a|b|c" {
		t.Fatal(w)
	}
}

func TestFetchUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != DefaultUA || r.Header.Get("x-hwid") != "hw1" {
			http.Error(w, "who are you", http.StatusForbidden)
			return
		}
		w.Header().Set("subscription-userinfo", "upload=1; download=2; total=3; expire=4")
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(vlessNL + "\n" + vlessDE))))
	}))
	defer srv.Close()
	f, err := FetchUpstream(context.Background(), srv.Client(), Upstream{URL: srv.URL + "/sub/SECRET", HWID: "hw1"})
	if err != nil || len(f.Links) != 2 || f.Userinfo == "" {
		t.Fatal(f, err)
	}
	_, err = FetchUpstream(context.Background(), srv.Client(), Upstream{URL: srv.URL + "/sub/SECRET"})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
}

func TestStoreAndPassword(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	hash := HashPassword("abcd-efgh")
	if err := s.Update(func(st *State) error { st.PasswordHash = hash; return nil }); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	st := s2.Get()
	if !CheckPassword(st.PasswordHash, "abcd-efgh") || CheckPassword(st.PasswordHash, "abcd-efgx") {
		t.Fatal("password check")
	}
	if st.SubToken == "" || st.AdminPath == "" || len(st.Hide) == 0 {
		t.Fatal(st)
	}
	if pw := RandomPassword(); len(pw) != 19 {
		t.Fatal(pw)
	}
	_ = importer.IsShareLink
}

func TestRenameQuotes(t *testing.T) {
	rules, err := ParseRenameText(`" | " → ", "` + "\n" + `Germany → Германия`)
	if err != nil || len(rules) != 2 || rules[0].From != " | " || rules[0].To != ", " {
		t.Fatal(rules, err)
	}
	if QuoteRuleSide(rules[0].From) != `" | "` || QuoteRuleSide("Германия") != "Германия" {
		t.Fatal("quoting")
	}
	compiled, _ := CompileRules(rules)
	if got := applyRules("🇩🇪 Germany | Frankfurt", compiled); got != "🇩🇪 Германия, Frankfurt" {
		t.Fatal(got)
	}
}
