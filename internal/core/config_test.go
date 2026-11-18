package core

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"lazeyka/internal/importer"
	"lazeyka/internal/omap"
	"lazeyka/internal/settings"
)

const testAWG = `[Interface]
Address = 10.8.1.2/32
DNS = 1.1.1.1
PrivateKey = bGF6ZXlrYS10ZXN0LWtleS1ub3QtYS1yZWFsLWtleSE=
Jc = 3
Jmin = 64
Jmax = 406
S1 = 20
S2 = 21
S3 = 22
S4 = 15
H1 = 123456-123500
H2 = 223456-223500
H3 = 323456-323500
H4 = 423456-423500
I1 = <rc 17><t><r 1000><r 57>
HeaderProtectionKey = bGF6ZXlrYS10ZXN0LWtleS1ub3QtYS1yZWFsLWtleSE=
ContentPaddingAddition = 10-60
RekeyAfterTime = 110-130
RandomTrailers = true
[Peer]
PublicKey = bGF6ZXlrYS10ZXN0LWtleS1ub3QtYS1yZWFsLWtleSE=
PresharedKey = bGF6ZXlrYS10ZXN0LWtleS1ub3QtYS1yZWFsLWtleSE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.10:51820
PersistentKeepalive = 25
`

func sampleSettings(t *testing.T) *settings.Settings {
	s := settings.Default()
	s.Normalize()
	add := func(text string) {
		r := importer.Parse(text, "")
		if len(r.Errors) > 0 {
			t.Fatalf("import: %v", r.Errors)
		}
		for _, it := range r.Items {
			if it.Server != nil {
				s.Servers = append(s.Servers, *it.Server)
			}
			if it.Subscription != nil {
				s.Subscriptions = append(s.Subscriptions, *it.Subscription)
			}
		}
	}
	add("vless://11111111-2222-3333-4444-555555555555@198.51.100.7:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=ab12&path=%2Fx&mode=auto#NL%20XHTTP")
	add(testAWG)
	add("hysteria2://pass@198.51.100.8:8443?sni=h.example.com#HY2")
	add("https://sub.example.com/api/sub/abcdef")
	s.Routing.CustomVPN = []string{"example.org", "1.2.3.0/24", "chatgpt"}
	s.Routing.CustomDirect = []string{"https://bank.example.ru/path"}
	return s
}

func testRuntime() Runtime {
	return Runtime{
		APIPort: 19090, Secret: "s3cret", DirectSocksPort: 17891, VPNSocksPort: 17892, ExitSocksPort: 17893,
		SocksUser: "lz", SocksPass: "pw", TunEnabled: false, TunName: "Lazeyka", ZapretActive: true,
		HWID: HWID{ID: "abc", OS: "Windows", OSVer: "10.0.22631", Model: "PC"},
	}
}

func TestBuild(t *testing.T) {
	s := sampleSettings(t)
	b, err := Build(s, testRuntime())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	if !b.HasOwn || !b.HasSub || !b.HasVoice {
		t.Fatalf("flags %+v", b)
	}
	if b.Defaults[GYouTube] != "DIRECT" || b.Defaults[GDiscord] != "DIRECT" || b.Defaults[GAI] != GOwn || b.Defaults[GOther] != "DIRECT" {
		t.Fatalf("defaults %+v", b.Defaults)
	}
	rules := cfg["rules"].([]any)
	if rules[len(rules)-1] != "MATCH,OTHER" {
		t.Fatal("last rule")
	}
	joined := ""
	for _, r := range rules {
		joined += r.(string) + "\n"
	}
	for _, want := range []string{
		"DOMAIN-SUFFIX,example.org,BLOCKED", "IP-CIDR,1.2.3.0/24,BLOCKED,no-resolve", "DOMAIN-KEYWORD,chatgpt,BLOCKED",
		"DOMAIN-SUFFIX,bank.example.ru,DIRECT", "RULE-SET,youtube,YOUTUBE", "PROCESS-NAME-REGEX,(?i)^(qbittorrent\\.exe",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing rule %q in\n%s", want, joined)
		}
	}
	if len(b.Files) != 2 {
		t.Fatalf("files %v", b.Files)
	}

	// Zapret off: YouTube and Discord fall back to VPN automatically.
	rt := testRuntime()
	rt.ZapretActive = false
	b2, _ := Build(s, rt)
	if b2.Defaults[GYouTube] != GAuto || b2.Defaults[GDiscord] != GVoice {
		t.Fatalf("fallback defaults %+v", b2.Defaults)
	}

	// No servers at all: still a valid zapret-only config.
	empty := settings.Default()
	empty.Normalize()
	b3, err := Build(empty, testRuntime())
	if err != nil || b3.HasVPN {
		t.Fatalf("empty: %v %+v", err, b3)
	}

	mihomoCheck(t, b)
	mihomoCheck(t, b3)
	tun := testRuntime()
	tun.TunEnabled = true
	b4, _ := Build(s, tun)
	mihomoCheck(t, b4)
}

// mihomoCheck runs "mihomo -t" on the config if MIHOMO_BIN points to a binary.
func mihomoCheck(t *testing.T, b *Built) {
	bin := os.Getenv("MIHOMO_BIN")
	if bin == "" {
		t.Log("MIHOMO_BIN not set, skipping real mihomo validation")
		return
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), b.Config, 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, data := range b.Files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, data, 0o644)
	}
	out, err := exec.Command(bin, "-t", "-d", dir, "-f", filepath.Join(dir, "config.yaml")).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "successful") {
		t.Fatalf("mihomo -t failed: %v\n%s\nconfig:\n%s", err, out, b.Config)
	}
	t.Logf("mihomo -t ok")
}

// TestConsistency checks every cross-reference inside the generated config,
// since mihomo itself refuses configs with dangling names.
func TestConsistency(t *testing.T) {
	s := sampleSettings(t)
	for _, zap := range []bool{true, false} {
		rt := testRuntime()
		rt.ZapretActive = zap
		b, err := Build(s, rt)
		if err != nil {
			t.Fatal(err)
		}
		checkRefs(t, b.Config)
	}
	empty := settings.Default()
	empty.Normalize()
	b, _ := Build(empty, testRuntime())
	checkRefs(t, b.Config)
}

func checkRefs(t *testing.T, raw []byte) {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	targets := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true}
	providers := map[string]bool{}
	if pp, ok := cfg["proxy-providers"].(map[string]any); ok {
		for k := range pp {
			providers[k] = true
		}
	}
	ruleSets := map[string]bool{}
	for k := range cfg["rule-providers"].(map[string]any) {
		ruleSets[k] = true
	}
	groups := cfg["proxy-groups"].([]any)
	for _, g := range groups {
		targets[g.(map[string]any)["name"].(string)] = true
	}
	for _, g := range groups {
		gm := g.(map[string]any)
		for _, p := range asList(gm["proxies"]) {
			if !targets[p] {
				t.Fatalf("group %v references unknown %q", gm["name"], p)
			}
		}
		for _, u := range asList(gm["use"]) {
			if !providers[u] {
				t.Fatalf("group %v uses unknown provider %q", gm["name"], u)
			}
		}
		if len(asList(gm["proxies"])) == 0 && len(asList(gm["use"])) == 0 {
			t.Fatalf("group %v is empty", gm["name"])
		}
	}
	if pp, ok := cfg["proxy-providers"].(map[string]any); ok {
		for name, p := range pp {
			pm := p.(map[string]any)
			if via, ok := pm["proxy"].(string); ok && !targets[via] {
				t.Fatalf("provider %s fetches via unknown %q", name, via)
			}
		}
	}
	for name, p := range cfg["rule-providers"].(map[string]any) {
		if via := p.(map[string]any)["proxy"].(string); !targets[via] {
			t.Fatalf("rule provider %s fetches via unknown %q", name, via)
		}
	}
	for _, l := range cfg["listeners"].([]any) {
		if via := l.(map[string]any)["proxy"].(string); !targets[via] {
			t.Fatalf("listener uses unknown %q", via)
		}
	}
	dns := cfg["dns"].(map[string]any)
	for _, ns := range asList(dns["nameserver"]) {
		if i := strings.Index(ns, "#"); i >= 0 && !targets[ns[i+1:]] {
			t.Fatalf("nameserver via unknown %q", ns)
		}
	}
	for k := range dns["nameserver-policy"].(map[string]any) {
		if strings.HasPrefix(k, "rule-set:") {
			for _, rs := range strings.Split(strings.TrimPrefix(k, "rule-set:"), ",") {
				if !ruleSets[rs] {
					t.Fatalf("dns policy unknown rule-set %q", rs)
				}
			}
		}
	}
	for _, r := range cfg["rules"].([]any) {
		rule := r.(string)
		parts := strings.Split(rule, ",")
		target := parts[len(parts)-1]
		if target == "no-resolve" {
			target = parts[len(parts)-2]
		}
		if !targets[target] {
			t.Fatalf("rule %q targets unknown %q", rule, target)
		}
		if strings.Count(rule, "(") != strings.Count(rule, ")") {
			t.Fatalf("unbalanced rule %q", rule)
		}
		for i := 0; ; {
			j := strings.Index(rule[i:], "RULE-SET,")
			if j < 0 {
				break
			}
			rest := rule[i+j+len("RULE-SET,"):]
			name := rest
			if k := strings.IndexAny(rest, ",)"); k >= 0 {
				name = rest[:k]
			}
			if !ruleSets[name] {
				t.Fatalf("rule %q uses unknown rule-set %q", rule, name)
			}
			i += j + len("RULE-SET,")
		}
	}
}

func asList(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func TestParseCustom(t *testing.T) {
	cases := map[string]string{
		"example.org":                   "DOMAIN-SUFFIX,example.org",
		"*.Example.org":                 "DOMAIN-SUFFIX,example.org",
		"+.example.org.":                "DOMAIN-SUFFIX,example.org",
		"https://bank.example.ru/path":  "DOMAIN-SUFFIX,bank.example.ru",
		"https://site.example:8443/a?b": "DOMAIN-SUFFIX,site.example",
		"site.example:8443/a":           "DOMAIN-SUFFIX,site.example",
		"президент.рф":                  "DOMAIN-SUFFIX,xn--d1abbgf6aiiy.xn--p1ai",
		"https://президент.рф/":         "DOMAIN-SUFFIX,xn--d1abbgf6aiiy.xn--p1ai",
		"chatgpt":                       "DOMAIN-KEYWORD,chatgpt",
		"1.2.3.4":                       "IP-CIDR,1.2.3.4/32",
		"1.2.3.4:443":                   "IP-CIDR,1.2.3.4/32",
		"10.20.3.4/16":                  "IP-CIDR,10.20.0.0/16",
		"2001:db8::1":                   "IP-CIDR6,2001:db8::1/128",
		"[2001:db8::1]:443":             "IP-CIDR6,2001:db8::1/128",
		"2001:db8::/32":                 "IP-CIDR6,2001:db8::/32",
	}
	for in, want := range cases {
		k, v, ok := ParseCustom(in)
		if got := k + "," + v; !ok || got != want {
			t.Errorf("ParseCustom(%q) = %q %v; want %q", in, got, ok, want)
		}
	}
	bad := BadCustomEntries([]string{"ok.com", "бред домен", "a,b", "# comment", "", "http://", "x..y"})
	if len(bad) != 4 {
		t.Errorf("BadCustomEntries = %q", bad)
	}
}

func TestRuleSnapshotComplete(t *testing.T) {
	for _, p := range RuleProviders(true) {
		b, ok := RuleSnapshot(p.name)
		if !ok {
			t.Errorf("no built-in copy of %s", p.name)
			continue
		}
		if len(b) < 4 || b[0] != 0x28 || b[1] != 0xb5 || b[2] != 0x2f || b[3] != 0xfd {
			t.Errorf("%s is not a zstd-compressed MRS file", p.name)
		}
	}
}

func TestHideAndRename(t *testing.T) {
	f := HideFilter([]string{"осталось", "RU", "a.b", " "})
	re := regexp.MustCompile(f)
	for name, hide := range map[string]bool{
		"Осталось 3 дня": true, "🇷🇺 RU-1": true, "Peru 2": false, "axb": false, "a.b": true, "🇳🇱 NL": false,
	} {
		if re.MatchString(name) != hide {
			t.Errorf("%q hidden=%v, want %v (%s)", name, !hide, hide, f)
		}
	}
	rules, err := RenameRules([]settings.Rename{{From: "Netherlands", To: "🇳🇱 Нидерланды"}, {From: "/^(\\d+)-(.*)$/", To: "$2 #$1"}, {From: "x$", To: "$5"}})
	if err != nil || len(rules) != 3 {
		t.Fatal(err, rules)
	}
	r0 := rules[0].(omap.M)
	if p, _ := r0.Get("pattern"); p != "(?i)Netherlands" {
		t.Error(p)
	}
	r2 := rules[2].(omap.M)
	if p, _ := r2.Get("pattern"); p != `(?i)x\$` {
		t.Error(p)
	}
	if tg, _ := r2.Get("target"); tg != "$$5" {
		t.Error(tg)
	}
	if _, err := RenameRules([]settings.Rename{{From: "/(/", To: ""}}); err == nil {
		t.Error("bad regex accepted")
	}
}

// The exit listener follows the blocked-sites route, so the country it shows
// is the one blocked sites leave from.
func TestExitListener(t *testing.T) {
	b, err := Build(sampleSettings(t), testRuntime())
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range cfg["listeners"].([]any) {
		m := l.(map[string]any)
		if m["name"] == "lz-exit" {
			found = true
			if m["proxy"] != GBlocked || m["listen"] != "127.0.0.1" || m["port"] != float64(17893) || m["users"] == nil {
				t.Fatalf("lz-exit: %v", m)
			}
		}
	}
	if !found {
		t.Fatal("no lz-exit listener")
	}
}

func TestBuildAndroid(t *testing.T) {
	s := sampleSettings(t)
	rt := testRuntime()
	rt.Android, rt.TunEnabled, rt.TunFD, rt.DPIPort = true, true, 3, 18081
	b, err := Build(s, rt)
	if err != nil {
		t.Fatal(err)
	}
	if b.Defaults[GYouTube] != PByeDPI || b.Defaults[GDiscord] != PByeDPI {
		t.Fatalf("defaults %+v", b.Defaults)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	tun := cfg["tun"].(map[string]any)
	if tun["file-descriptor"].(float64) != 3 || tun["auto-route"] != false || tun["device"] != nil {
		t.Fatalf("tun %v", tun)
	}
	if cfg["find-process-mode"] != "off" {
		t.Fatal("process mode")
	}
	px := cfg["proxies"].([]any)[0].(map[string]any)
	if px["name"] != PByeDPI || px["port"].(float64) != 18081 {
		t.Fatalf("proxy %v", px)
	}
	joined := ""
	for _, r := range cfg["rules"].([]any) {
		joined += r.(string) + "\n"
	}
	if strings.Contains(joined, "PROCESS-") {
		t.Fatalf("process rules on Android:\n%s", joined)
	}
	if !strings.Contains(joined, "AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET,youtube)),REJECT") {
		t.Fatal("YouTube QUIC must be rejected so it goes through ByeDPI")
	}
	// ByeDPI not running: YouTube falls back to the VPN, ByeDPI stays selectable
	rt.ZapretActive = false
	b2, _ := Build(s, rt)
	if b2.Defaults[GYouTube] != GAuto {
		t.Fatalf("fallback %+v", b2.Defaults)
	}
	mihomoCheck(t, b)
	// no servers: only ByeDPI and direct
	empty := settings.Default()
	empty.Normalize()
	b3, err := Build(empty, rt)
	if err != nil || b3.Defaults[GYouTube] != "DIRECT" {
		t.Fatalf("empty: %v %+v", err, b3.Defaults)
	}
	mihomoCheck(t, b3)
}
