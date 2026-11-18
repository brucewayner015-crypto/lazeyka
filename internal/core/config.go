// Package core builds the mihomo configuration and runs the mihomo process.
package core

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"lazeyka/internal/idna"
	"lazeyka/internal/importer"
	"lazeyka/internal/omap"
	"lazeyka/internal/settings"
)

// Internal proxy-group names (ASCII so they are safe in URLs and logs).
const (
	GOwn        = "OWN"
	GSub        = "SUB"
	GAuto       = "AUTO"
	GVoiceUDP   = "VOICE-UDP"
	GVoice      = "VOICE"
	GYouTube    = "YOUTUBE"
	GDiscord    = "DISCORD"
	GMessengers = "MESSENGERS"
	GAI         = "AI"
	GBlocked    = "BLOCKED"
	GOther      = "OTHER"
	// PByeDPI is the local ByeDPI proxy (Android's stand-in for zapret).
	PByeDPI = "ByeDPI"
)

// GroupLabels are shown in the UI.
var GroupLabels = map[string]string{
	GOwn:        "Свои серверы",
	GSub:        "Подписка",
	GAuto:       "Авто: свои, затем подписка",
	GVoiceUDP:   "Свои UDP-серверы",
	GVoice:      "Звонки и голос",
	GYouTube:    "YouTube",
	GDiscord:    "Discord",
	GMessengers: "Telegram и WhatsApp",
	GAI:         "ИИ-сервисы",
	GBlocked:    "Заблокированное",
	GOther:      "Всё остальное",
	"DIRECT":    "Напрямую",
	"REJECT":    "Блокировать",
}

var reservedNames = map[string]bool{
	GOwn: true, GSub: true, GAuto: true, GVoiceUDP: true, GVoice: true, GYouTube: true, GDiscord: true,
	GMessengers: true, GAI: true, GBlocked: true, GOther: true,
	"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true,
}

// HealthURL is used by every group and provider health check.
const HealthURL = "https://www.gstatic.com/generate_204"

// HealthTimeout (ms) for checking one server. Generous: on mobile networks
// in Russia the first connection through a server often takes 3–5 s
// (throttled handshakes), and 4 s marked working servers dead.
const HealthTimeout = 6000

// SubPrefix is the default label before subscription server names, so they
// do not collide with the user's own server names.
const SubPrefix = settings.DefaultSubPrefix

// HideFilter turns "hide" words into one case-insensitive expression for
// mihomo's exclude-filter. Words of up to three Latin letters or digits match
// whole words only ("RU" hides "RU-1", not "Peru").
func HideFilter(words []string) string {
	var parts []string
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		q := regexp.QuoteMeta(w)
		if shortLatin(w) {
			q = `\b` + q + `\b`
		}
		parts = append(parts, q)
	}
	if len(parts) == 0 {
		return ""
	}
	return "(?i)(" + strings.Join(parts, "|") + ")"
}

func shortLatin(w string) bool {
	if len(w) > 3 {
		return false
	}
	for _, c := range w {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// RenameRules turns rename rules into mihomo's override "proxy-name" list.
// Plain text is replaced as is, ignoring case; /…/ is a regular expression
// and its replacement may use $1, $2.
func RenameRules(rules []settings.Rename) ([]any, error) {
	var out []any
	for i, r := range rules {
		from, to := r.From, r.To
		if strings.TrimSpace(from) == "" {
			continue
		}
		var pattern string
		if len(from) >= 3 && strings.HasPrefix(from, "/") && strings.HasSuffix(from, "/") {
			pattern = from[1 : len(from)-1]
			if _, err := regexp.Compile(pattern); err != nil {
				return nil, fmt.Errorf("правило %d («%s»): неверное выражение", i+1, from)
			}
		} else {
			pattern = "(?i)" + regexp.QuoteMeta(from)
			to = strings.ReplaceAll(to, "$", "$$")
		}
		out = append(out, omap.New("pattern", pattern, "target", to))
	}
	return out, nil
}

// Runtime carries per-launch parameters.
type Runtime struct {
	APIPort         int
	Secret          string
	DirectSocksPort int
	VPNSocksPort    int
	ExitSocksPort   int // goes the way blocked sites go: shows the exit country
	SocksUser       string
	SocksPass       string
	TunEnabled      bool
	TunName         string
	ZapretActive    bool
	// Android: mihomo gets the VPN interface from VpnService as an inherited
	// descriptor; YouTube and Discord go through the local ByeDPI proxy
	// instead of DIRECT (zapret needs root there).
	Android bool
	TunFD   int
	DPIPort int
	HWID    HWID
}

// HWID headers sent to subscription panels that bind devices.
type HWID struct {
	ID    string
	OS    string
	OSVer string
	Model string
}

// Built is the generated configuration.
type Built struct {
	Config      []byte            // JSON (valid YAML), written as config.yaml
	Files       map[string][]byte // provider files, relative to the mihomo home
	NodeName    map[string]string // server ID -> mihomo proxy name
	Provider    map[string]string // server ID -> provider name
	SubProvider map[string]string // subscription ID -> provider name
	HasVPN      bool
	HasOwn      bool
	HasSub      bool
	HasVoice    bool
	Groups      []string // groups shown to the user, in order
	Defaults    map[string]string
}

type ruleProvider struct {
	name, behavior, url string
	interval            int
}

const (
	itdog   = "https://github.com/itdoginfo/allow-domains/releases/latest/download/"
	metaGeo = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/"
)

// RuleProviders lists every rule set the config may reference.
func RuleProviders(hodca bool) []ruleProvider {
	day := 86400
	rp := []ruleProvider{
		{"ru-blocked", "domain", itdog + "russia_inside_domain.mrs", day},
		{"ru-outside", "domain", itdog + "russia_outside_domain.mrs", day},
		{"geoblock", "domain", itdog + "geoblock_domain.mrs", day},
		{"youtube", "domain", itdog + "youtube_domain.mrs", day},
		{"discord", "domain", itdog + "discord_domain.mrs", day},
		{"discord-ip", "ipcidr", itdog + "discord_ipcidr.mrs", day},
		{"telegram", "domain", itdog + "telegram_domain.mrs", day},
		{"telegram-ip", "ipcidr", itdog + "telegram_ipcidr.mrs", day},
		{"meta", "domain", itdog + "meta_domain.mrs", day},
		{"meta-ip", "ipcidr", itdog + "meta_ipcidr.mrs", day},
		{"twitter-ip", "ipcidr", itdog + "twitter_ipcidr.mrs", day},
		{"ai", "domain", metaGeo + "geosite/category-ai-%21cn.mrs", 3 * day},
		{"ru-domains", "domain", metaGeo + "geosite/category-ru.mrs", 3 * day},
		{"ru-ip", "ipcidr", metaGeo + "geoip/ru.mrs", 3 * day},
	}
	if hodca {
		rp = append(rp, ruleProvider{"hodca", "domain", itdog + "hodca_domain.mrs", day})
	}
	return rp
}

// RuleURLs maps rule-set names to their download URLs.
func RuleURLs(hodca bool) map[string]string {
	m := map[string]string{}
	for _, p := range RuleProviders(hodca) {
		m[p.name] = p.url
	}
	return m
}

// RuleFilePath is where mihomo caches a rule set (relative to its home).
func RuleFilePath(name string) string { return "rules/" + name + ".mrs" }

// Build generates the mihomo configuration from settings.
func Build(s *settings.Settings, rt Runtime) (*Built, error) {
	b := &Built{
		Files:       map[string][]byte{},
		NodeName:    map[string]string{},
		Provider:    map[string]string{},
		SubProvider: map[string]string{},
		Defaults:    map[string]string{},
	}
	r := s.Routing

	// --- proxy providers -------------------------------------------------
	providers := omap.M{}
	var ownProviders, udpProviders, subProviders []string
	used := map[string]bool{}
	uniq := func(name string) string {
		name = strings.TrimSpace(strings.ReplaceAll(name, ",", " "))
		if name == "" {
			name = "Сервер"
		}
		if strings.HasPrefix(name, SubPrefix) {
			name = strings.TrimPrefix(name, SubPrefix)
		}
		base, n := name, 1
		for used[name] || reservedNames[strings.ToUpper(name)] {
			n++
			name = fmt.Sprintf("%s (%d)", base, n)
		}
		used[name] = true
		return name
	}
	hc := func(interval int, lazy bool) omap.M {
		return omap.New("enable", true, "url", HealthURL, "interval", interval, "timeout", HealthTimeout, "lazy", lazy, "expected-status", "204")
	}
	idx := 0
	for _, srv := range s.Servers {
		if !srv.Enabled {
			continue
		}
		idx++
		pname := fmt.Sprintf("own-%02d", idx)
		name := uniq(srv.Name)
		switch srv.Kind {
		case settings.KindLink:
			if !importer.IsShareLink(srv.Link) {
				return nil, fmt.Errorf("сервер «%s»: неподдерживаемая ссылка", srv.Name)
			}
			path := "providers/" + pname + ".txt"
			b.Files[path] = []byte(importer.RenameLink(strings.TrimSpace(srv.Link), name) + "\n")
			providers = append(providers, omap.KV{K: pname, V: omap.New(
				"type", "file",
				"path", "./"+path,
				"health-check", hc(120, false),
			)})
		case settings.KindAWG:
			if len(srv.Proxy) == 0 {
				return nil, fmt.Errorf("сервер «%s»: пустой конфиг AmneziaWG", srv.Name)
			}
			p := map[string]any{}
			for k, v := range srv.Proxy {
				p[k] = v
			}
			p["name"] = name
			p["udp"] = true
			providers = append(providers, omap.KV{K: pname, V: omap.New(
				"type", "inline",
				"payload", []any{p},
				"health-check", hc(120, false),
			)})
		default:
			return nil, fmt.Errorf("сервер «%s»: неизвестный тип %q", srv.Name, srv.Kind)
		}
		b.NodeName[srv.ID] = name
		b.Provider[srv.ID] = pname
		ownProviders = append(ownProviders, pname)
		if srv.UDPFriendly() {
			udpProviders = append(udpProviders, pname)
		}
	}
	var fetchGroups []any
	for _, sub := range s.Subscriptions {
		if !sub.Enabled || sub.URL == "" {
			continue
		}
		pname := "sub-" + sub.ID
		header := omap.New("User-Agent", []string{sub.UserAgent})
		if sub.HWID && rt.HWID.ID != "" {
			header = append(header,
				omap.KV{K: "x-hwid", V: []string{rt.HWID.ID}},
				omap.KV{K: "x-device-os", V: []string{rt.HWID.OS}},
				omap.KV{K: "x-ver-os", V: []string{rt.HWID.OSVer}},
				omap.KV{K: "x-device-model", V: []string{rt.HWID.Model}},
			)
		}
		// How the subscription itself is downloaded. Many subscription hosts
		// (vercel.app and the like) are blocked in Russia: with own servers
		// the download falls back to them when the direct path fails.
		via := "DIRECT"
		switch {
		case sub.ViaVPN && len(ownProviders) > 0:
			via = GOwn
		case len(ownProviders) > 0:
			via = "FETCH-" + sub.ID
			fetchGroups = append(fetchGroups, omap.New(
				"name", via, "type", "fallback",
				"proxies", []string{"DIRECT", GOwn},
				"url", sub.URL, // a HEAD request: any HTTP answer means the path works
				"interval", 300, "timeout", 6000, "max-failed-times", 2,
				"lazy", false, "hidden", true,
			))
		}
		// names come as the subscription gives them: renaming lives in
		// Связка, the user's own aggregator, so every device sees the same
		ovr := omap.New("udp", true)
		prov := omap.New(
			"type", "http",
			"url", sub.URL,
			"interval", sub.IntervalHours*3600,
			"path", "./providers/"+pname+".yaml",
			"proxy", via,
			"header", header,
			"health-check", hc(900, true),
			"override", ovr,
		)
		if f := HideFilter(sub.Hide); f != "" {
			prov = append(prov, omap.KV{K: "exclude-filter", V: f})
		}
		providers = append(providers, omap.KV{K: pname, V: prov})
		subProviders = append(subProviders, pname)
		b.SubProvider[sub.ID] = pname
	}
	b.HasOwn = len(ownProviders) > 0
	b.HasSub = len(subProviders) > 0
	b.HasVPN = b.HasOwn || b.HasSub
	b.HasVoice = len(udpProviders) > 0

	// --- proxy groups -----------------------------------------------------
	var groups []any
	fallback := func(name string, proxies, use []string, interval int, lazy bool) omap.M {
		g := omap.New("name", name, "type", "fallback")
		if len(proxies) > 0 {
			g = append(g, omap.KV{K: "proxies", V: proxies})
		}
		if len(use) > 0 {
			g = append(g, omap.KV{K: "use", V: use})
		}
		return append(g,
			omap.KV{K: "url", V: HealthURL},
			omap.KV{K: "expected-status", V: "204"},
			omap.KV{K: "interval", V: interval},
			omap.KV{K: "timeout", V: 4000},
			omap.KV{K: "max-failed-times", V: 3},
			omap.KV{K: "lazy", V: lazy},
		)
	}
	sel := func(name string, proxies []string, use []string) omap.M {
		g := omap.New("name", name, "type", "select", "proxies", proxies)
		if len(use) > 0 {
			g = append(g, omap.KV{K: "use", V: use})
		}
		return g
	}
	if b.HasOwn {
		groups = append(groups, fallback(GOwn, nil, ownProviders, 60, false))
	}
	groups = append(groups, fetchGroups...)
	if b.HasSub {
		groups = append(groups, omap.New(
			"name", GSub, "type", "url-test", "use", subProviders,
			"url", HealthURL, "expected-status", "204", "interval", 600, "timeout", HealthTimeout,
			"tolerance", 120, "lazy", true,
		))
	}
	var vpnMembers []string
	if b.HasOwn {
		vpnMembers = append(vpnMembers, GOwn)
	}
	if b.HasSub {
		vpnMembers = append(vpnMembers, GSub)
	}
	if b.HasVPN {
		groups = append(groups, fallback(GAuto, vpnMembers, nil, 60, false))
	} else {
		groups = append(groups, sel(GAuto, []string{"DIRECT"}, nil))
	}
	if b.HasVoice {
		groups = append(groups, fallback(GVoiceUDP, nil, udpProviders, 120, false))
		groups = append(groups, fallback(GVoice, []string{GVoiceUDP, GAuto}, nil, 120, false))
	} else {
		groups = append(groups, sel(GVoice, []string{GAuto}, nil))
	}
	order := func(first bool, a, rest []string) []string {
		if first {
			return append(append([]string{}, a...), rest...)
		}
		return append(append([]string{}, rest...), a...)
	}
	youtubeDirect := r.YouTube == settings.ModeDirect || (r.YouTube == settings.ModeZapret && (rt.ZapretActive || !b.HasVPN))
	discordDirect := r.Discord == settings.ModeZapret && (rt.ZapretActive || !b.HasVPN)
	// where "zapret" mode sends traffic: DIRECT (zapret works on the packets)
	// or the ByeDPI proxy on Android
	ytOut, dcOut := []string{"DIRECT"}, []string{"DIRECT"}
	if rt.DPIPort > 0 {
		// both stay selectable, so ByeDPI can be switched on and off
		// without rebuilding the config
		dpi := []string{PByeDPI, "DIRECT"}
		if !rt.ZapretActive {
			dpi = []string{"DIRECT", PByeDPI}
		}
		if r.YouTube == settings.ModeZapret {
			ytOut = dpi
		}
		if r.Discord == settings.ModeZapret {
			dcOut = dpi
		}
	}
	groups = append(groups,
		sel(GYouTube, order(youtubeDirect, ytOut, []string{GAuto}), nil),
		sel(GDiscord, order(discordDirect, dcOut, []string{GVoice, GAuto}), nil),
		sel(GMessengers, order(r.Messengers == settings.ModeDirect, []string{"DIRECT"}, []string{GVoice, GAuto}), nil),
	)
	aiMembers := []string{GAuto}
	if b.HasOwn {
		if r.AI == settings.ModeOwn {
			aiMembers = []string{GOwn, GAuto}
		} else {
			aiMembers = []string{GAuto, GOwn}
		}
	}
	groups = append(groups, sel(GAI, aiMembers, nil))
	blocked := []string{GAuto}
	blocked = append(blocked, vpnMembers...)
	blocked = append(blocked, "DIRECT")
	groups = append(groups, sel(GBlocked, blocked, append(append([]string{}, ownProviders...), subProviders...)))
	groups = append(groups, sel(GOther, order(r.Other != settings.ModeVPN, []string{"DIRECT"}, []string{GAuto}), nil))

	b.Groups = []string{GBlocked, GYouTube, GDiscord, GMessengers, GAI, GOther}
	for _, g := range groups {
		gm := g.(omap.M)
		name, _ := gm.Get("name")
		if px, ok := gm.Get("proxies"); ok {
			if list, ok := px.([]string); ok && len(list) > 0 {
				b.Defaults[name.(string)] = list[0]
			}
		}
	}

	// --- rule providers ---------------------------------------------------
	rps := omap.M{}
	rpProxy := "DIRECT"
	if b.HasVPN {
		rpProxy = GAuto
	}
	for _, p := range RuleProviders(r.HODCA) {
		rps = append(rps, omap.KV{K: p.name, V: omap.New(
			"type", "http",
			"behavior", p.behavior,
			"format", "mrs",
			"url", p.url,
			"path", "./"+RuleFilePath(p.name),
			"interval", p.interval,
			"proxy", rpProxy,
		)})
	}

	// --- rules --------------------------------------------------------------
	var rules []string
	add := func(rule string) { rules = append(rules, rule) }
	for _, cidr := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32"} {
		add("IP-CIDR," + cidr + ",DIRECT,no-resolve")
	}
	// Process names are Windows programs; on Android whole apps skip the VPN
	// instead (VpnService bypass list).
	procRules := !rt.Android
	if re := nameRegex(r.TorrentApps); re != "" && procRules {
		if b.HasVPN {
			add("AND,((PROCESS-NAME-REGEX," + re + "),(RULE-SET,ru-blocked))," + GBlocked)
		}
		add("PROCESS-NAME-REGEX," + re + ",DIRECT")
	}
	if re := nameRegex(r.DirectApps); re != "" && procRules {
		add("PROCESS-NAME-REGEX," + re + ",DIRECT")
	}
	if re := pathRegex(r.DirectPaths); re != "" && procRules {
		add("PROCESS-PATH-REGEX," + re + ",DIRECT")
	}
	if re := nameRegex(r.GameApps); re != "" && procRules {
		add("PROCESS-NAME-REGEX," + re + ",DIRECT")
	}
	for _, d := range r.CustomDirect {
		if rule := customRule(d, "DIRECT"); rule != "" {
			add(rule)
		}
	}
	for _, d := range r.CustomVPN {
		if rule := customRule(d, GBlocked); rule != "" {
			add(rule)
		}
	}
	if rt.DPIPort > 0 && rt.ZapretActive && r.YouTube == settings.ModeZapret {
		// ByeDPI works on TCP: YouTube's QUIC would go around it
		add("AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET,youtube)),REJECT")
	}
	if r.BlockQUIC && b.HasVPN {
		if !youtubeDirect && !(rt.DPIPort > 0 && rt.ZapretActive && r.YouTube == settings.ModeZapret) {
			add("AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET,youtube)),REJECT")
		}
		add("AND,((NETWORK,UDP),(DST-PORT,443),(OR,((RULE-SET,ru-blocked),(RULE-SET,geoblock),(RULE-SET,ai)))),REJECT")
	}
	add("RULE-SET,youtube," + GYouTube)
	if rt.DPIPort > 0 && r.Discord == settings.ModeZapret {
		// ByeDPI carries TCP only: Discord voice (UDP) goes through the VPN
		add("AND,((NETWORK,UDP),(RULE-SET,discord))," + GVoice)
		add("AND,((NETWORK,UDP),(RULE-SET,discord-ip))," + GVoice)
	}
	add("RULE-SET,discord," + GDiscord)
	add("RULE-SET,discord-ip," + GDiscord + ",no-resolve")
	for _, d := range []string{"whatsapp.com", "whatsapp.net", "whatsapp.biz", "wa.me"} {
		add("DOMAIN-SUFFIX," + d + "," + GMessengers)
	}
	add("RULE-SET,telegram," + GMessengers)
	add("RULE-SET,telegram-ip," + GMessengers + ",no-resolve")
	add("RULE-SET,meta," + GBlocked)
	add("RULE-SET,meta-ip," + GMessengers + ",no-resolve")
	add("RULE-SET,ai," + GAI)
	add("RULE-SET,ru-outside,DIRECT")
	add("RULE-SET,ru-blocked," + GBlocked)
	add("RULE-SET,geoblock," + GBlocked)
	add("RULE-SET,twitter-ip," + GBlocked + ",no-resolve")
	if r.HODCA {
		add("RULE-SET,hodca," + GBlocked)
	}
	add("RULE-SET,ru-domains,DIRECT")
	add("RULE-SET,ru-ip,DIRECT,no-resolve")
	if r.UDPDirect {
		add("AND,((NETWORK,UDP),(NOT,((DST-PORT,443)))),DIRECT")
	}
	add("MATCH," + GOther)

	// --- DNS -----------------------------------------------------------------
	// Since August 2026 the TSPU drops DoH/DoT to Google and Cloudflare (by
	// SNI) and sends plain UDP DNS for 8.8.8.8 / 1.1.1.1 to the state
	// resolver НСДИ, which says "no such domain" for YouTube, WhatsApp and
	// the like. DNS over TCP to the same servers still gets real answers;
	// through the VPN everything works. Resolvers that may lie are kept out
	// of these lists: mihomo takes the first answer, a lie included.
	nameservers := append([]string{}, TrustedDNS...)
	if b.HasVPN {
		// by IP: no name to look up first, nothing a lying resolver can spoil
		nameservers = append(nameservers,
			"https://1.1.1.1/dns-query#"+GAuto,
			"https://8.8.8.8/dns-query#"+GAuto)
	}
	dns := omap.New(
		"enable", true,
		"ipv6", false,
		"enhanced-mode", "fake-ip",
		"fake-ip-range", "198.18.0.1/16",
		"fake-ip-filter-mode", "blacklist",
		"fake-ip-filter", fakeIPFilter,
		// each server says itself how it is reached (direct or #AUTO); with
		// rules, DNS to Cloudflare matched discord-ip (104.16.0.0/12)
		"respect-rules", false,
		"use-hosts", true,
		"use-system-hosts", true,
		// all servers above are IP addresses; this is only a safety net and
		// must not be UDP to 8.8.8.8 / 1.1.1.1 (redirected to НСДИ)
		"default-nameserver", append([]string{}, TrustedDNS...),
		"proxy-server-nameserver", append([]string{}, TrustedDNS...),
		"nameserver", nameservers,
		// Yandex over TCP too: on some phones (seen on OnePlus, Android 16)
		// the system catches UDP DNS of every app, the VPN's own included,
		// and answers it through the VPN — mihomo then got its own fake
		// addresses back (yandex.ru → 198.18.0.84) and Russian sites hung
		"nameserver-policy", omap.New("rule-set:ru-domains,ru-outside", []string{"tcp://77.88.8.8", "tcp://77.88.8.1"}),
	)

	// --- TUN -----------------------------------------------------------------
	var tun omap.M
	if rt.TunEnabled && rt.TunFD > 0 {
		// Android: VpnService made the interface (address, routes, DNS,
		// bypassed apps); mihomo only reads and writes packets.
		tun = omap.New(
			"enable", true,
			"stack", "gvisor",
			"file-descriptor", rt.TunFD,
			"auto-route", false,
			"auto-detect-interface", false,
			"dns-hijack", []string{"any:53", "tcp://any:53"},
			"mtu", AndroidMTU,
		)
	} else if rt.TunEnabled {
		tun = omap.New(
			"enable", true,
			"stack", s.App.TunStack,
			"device", rt.TunName,
			"auto-route", true,
			"auto-detect-interface", true,
			"strict-route", true,
			"dns-hijack", []string{"any:53", "tcp://any:53"},
			"mtu", 1500,
			"route-exclude-address", []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4"},
		)
	} else {
		tun = omap.New("enable", false)
	}

	// --- local listeners for the app itself (tests and downloads) -----------
	users := []any{omap.New("username", rt.SocksUser, "password", rt.SocksPass)}
	listeners := []any{omap.New(
		"name", "lz-direct", "type", "socks", "listen", "127.0.0.1", "port", rt.DirectSocksPort,
		"udp", false, "proxy", "DIRECT", "users", users,
	)}
	if b.HasVPN && rt.VPNSocksPort > 0 {
		listeners = append(listeners, omap.New(
			"name", "lz-vpn", "type", "socks", "listen", "127.0.0.1", "port", rt.VPNSocksPort,
			"udp", false, "proxy", GAuto, "users", users,
		))
	}
	if b.HasVPN && rt.ExitSocksPort > 0 {
		listeners = append(listeners, omap.New(
			"name", "lz-exit", "type", "socks", "listen", "127.0.0.1", "port", rt.ExitSocksPort,
			"udp", false, "proxy", GBlocked, "users", users,
		))
	}

	logLevel := "warning"
	if s.App.Verbose {
		logLevel = "info"
	}
	cfg := omap.M{}
	if s.App.MixedPort > 0 {
		cfg = append(cfg, omap.KV{K: "mixed-port", V: s.App.MixedPort})
	}
	cfg = append(cfg,
		omap.KV{K: "allow-lan", V: false},
		omap.KV{K: "bind-address", V: "127.0.0.1"},
		omap.KV{K: "mode", V: "rule"},
		omap.KV{K: "log-level", V: logLevel},
		omap.KV{K: "ipv6", V: false},
		omap.KV{K: "unified-delay", V: true},
		omap.KV{K: "tcp-concurrent", V: true},
		omap.KV{K: "find-process-mode", V: findProcess(rt)},
		omap.KV{K: "external-controller", V: fmt.Sprintf("127.0.0.1:%d", rt.APIPort)},
		omap.KV{K: "secret", V: rt.Secret},
		omap.KV{K: "profile", V: omap.New("store-selected", false, "store-fake-ip", true)},
		omap.KV{K: "geodata-mode", V: false},
		omap.KV{K: "geo-auto-update", V: false},
		omap.KV{K: "sniffer", V: omap.New(
			"enable", true,
			"force-dns-mapping", true,
			"parse-pure-ip", true,
			"override-destination", false,
			"sniff", omap.New(
				"HTTP", omap.New("ports", []any{80, "8080-8880"}, "override-destination", false),
				// Android: apps reach some sites by IPv6 address, and IPv6 is
				// off in the VPN; dialled by the name from TLS they work
				"TLS", omap.New("ports", []any{443, 8443}, "override-destination", rt.Android),
				"QUIC", omap.New("ports", []any{443, 8443}, "override-destination", rt.Android),
			),
		)},
		omap.KV{K: "tun", V: tun},
		omap.KV{K: "dns", V: dns},
		omap.KV{K: "listeners", V: listeners},
	)
	if rt.DPIPort > 0 {
		// TCP only: Discord voice goes through the VPN (VOICE), YouTube's
		// QUIC is rejected so it falls back to TCP
		cfg = append(cfg, omap.KV{K: "proxies", V: []any{omap.New(
			"name", PByeDPI, "type", "socks5", "server", "127.0.0.1", "port", rt.DPIPort, "udp", false,
		)}})
	}
	if len(providers) > 0 {
		cfg = append(cfg, omap.KV{K: "proxy-providers", V: providers})
	}
	cfg = append(cfg,
		omap.KV{K: "proxy-groups", V: groups},
		omap.KV{K: "rule-providers", V: rps},
		omap.KV{K: "rules", V: rules},
	)
	out, err := omap.MarshalIndent(cfg)
	if err != nil {
		return nil, err
	}
	b.Config = out
	return b, nil
}

var fakeIPFilter = []string{
	"*.lan", "*.local", "*.localdomain", "*.home.arpa", "*.localhost",
	"+.msftconnecttest.com", "+.msftncsi.com", "time.windows.com", "time.*.com", "time.*.gov", "+.ntp.org", "+.pool.ntp.org", "ntp.*.com",
	"stun.*.*", "stun.*.*.*", "+.stun.*.*", "+.stun.*.*.*", "+.stun.*.*.*.*",
	"+.xboxlive.com", "xbox.*.microsoft.com", "+.srv.nintendo.net", "+.stun.playstation.net", "+.battlenet.com.cn",
	"localhost.ptlogin2.qq.com", "+.market.xiaomi.com", "+.lazeyka.local",
}

// nameRegex builds a case-insensitive exact-match regex for process names.
func nameRegex(names []string) string {
	var parts []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		parts = append(parts, regexp.QuoteMeta(n))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(?i)^(" + strings.Join(parts, "|") + ")$"
}

// pathRegex builds a case-insensitive "contains" regex for process paths.
func pathRegex(frags []string) string {
	var parts []string
	for _, f := range frags {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		parts = append(parts, regexp.QuoteMeta(f))
	}
	if len(parts) == 0 {
		return ""
	}
	return "(?i)(" + strings.Join(parts, "|") + ")"
}

// ParseCustom understands what people paste into "always via server" /
// "always direct": a domain (сайт.рф too), a URL, host:port, an IP or a
// subnet, or a single word (matched as a keyword). It returns the mihomo rule
// type and payload, or ok=false if the entry makes no sense.
func ParseCustom(entry string) (kind, value string, ok bool) {
	e := strings.TrimSpace(entry)
	if e == "" || strings.HasPrefix(e, "#") {
		return "", "", false
	}
	if p, err := netip.ParsePrefix(e); err == nil {
		p = p.Masked()
		if p.Addr().Is6() {
			return "IP-CIDR6", p.String(), true
		}
		return "IP-CIDR", p.String(), true
	}
	host := idna.HostOf(e)
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if a.Is6() {
			return "IP-CIDR6", a.String() + "/128", true
		}
		return "IP-CIDR", a.String() + "/32", true
	}
	ascii, err := idna.ToASCII(host)
	if err != nil {
		return "", "", false
	}
	if !strings.Contains(ascii, ".") {
		return "DOMAIN-KEYWORD", ascii, true
	}
	return "DOMAIN-SUFFIX", ascii, true
}

// BadCustomEntries returns the entries ParseCustom cannot understand.
func BadCustomEntries(list []string) []string {
	var bad []string
	for _, e := range list {
		if strings.TrimSpace(e) == "" || strings.HasPrefix(strings.TrimSpace(e), "#") {
			continue
		}
		if _, _, ok := ParseCustom(e); !ok {
			bad = append(bad, strings.TrimSpace(e))
		}
	}
	return bad
}

// customRule turns a user entry into a mihomo rule ("" if invalid).
func customRule(entry, target string) string {
	kind, value, ok := ParseCustom(entry)
	if !ok {
		return ""
	}
	if kind == "IP-CIDR" || kind == "IP-CIDR6" {
		return kind + "," + value + "," + target + ",no-resolve"
	}
	return kind + "," + value + "," + target
}

// AndroidMTU of the VPN interface.
const AndroidMTU = 1500

// Android apps cannot read /proc/net of other apps: process rules are off.
func findProcess(rt Runtime) string {
	if rt.Android {
		return "off"
	}
	return "strict"
}

// TrustedDNS: resolvers that still answer honestly from Russia (DNS over TCP;
// see the DNS section of Build).
var TrustedDNS = []string{"tcp://1.1.1.1", "tcp://8.8.8.8", "tcp://9.9.9.9"}
