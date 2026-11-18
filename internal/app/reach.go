package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"lazeyka/internal/core"
	"lazeyka/internal/importer"
	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
)

// Why a server does not answer. mihomo's checks say only "no answer" and
// give no reason, so for the servers that failed them the app connects to
// the server's address itself, past the VPN, the way mihomo would:
//   - no connection at all: the server cannot be reached from this network —
//     its address is blocked by the provider, or the server is down;
//   - a connection, but the TLS handshake is cut or never answered: the
//     provider lets the address through and blocks the protocol (DPI);
//   - a connection and a TLS answer: the server is there; what fails is the
//     VPN through it (expired keys or settings, the server's own trouble).
// Servers over UDP (Hysteria2, TUIC, WireGuard) cannot be checked this way.

// Reach codes, as the web UI sees them.
const (
	reachUnreachable = "unreachable"
	reachDPI         = "dpi"
	reachOpen        = "open"
	reachUDP         = "udp"
	reachUnknown     = "unknown"
)

type probeTarget struct {
	Host string
	Port int
	UDP  bool
	TLS  bool
	SNI  string
}

func (t probeTarget) addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// reachInfo is the verdict for one server.
type reachInfo struct {
	Code string
	Text string // short, for lists: "недоступен", "блокируется", "нет ответа"
	Note string // a sentence for the tooltip and the log
	Addr string // host:port as probed (for the log)
}

func targetOfLink(li importer.LinkInfo) probeTarget {
	return probeTarget{Host: li.Host, Port: li.Port, UDP: li.OverUDP(), TLS: li.UsesTLS(), SNI: li.SNI}
}

// serverTargets maps node names (as mihomo knows them) to server addresses:
// own servers from the settings, subscriptions from mihomo's provider files.
func (a *App) serverTargets(b *core.Built, s *settings.Settings) map[string]probeTarget {
	out := map[string]probeTarget{}
	for _, srv := range s.Servers {
		name, ok := b.NodeName[srv.ID]
		if !ok {
			continue
		}
		switch srv.Kind {
		case settings.KindLink:
			if li, err := importer.InspectLink(srv.Link); err == nil {
				out[name] = targetOfLink(li)
			}
		case settings.KindAWG:
			host, _ := srv.Proxy["server"].(string)
			port := 0
			switch v := srv.Proxy["port"].(type) {
			case float64:
				port = int(v)
			case int:
				port = v
			case string:
				port, _ = strconv.Atoi(v)
			}
			if host != "" && port > 0 {
				out[name] = probeTarget{Host: host, Port: port, UDP: true}
			}
		}
	}
	for _, pname := range b.SubProvider {
		data, err := os.ReadFile(filepath.Join(a.P.MihomoHome, "providers", pname+".yaml"))
		if err != nil {
			continue
		}
		for name, t := range subscriptionTargets(data) {
			if _, dup := out[name]; !dup {
				out[name] = t
			}
		}
	}
	return out
}

// subscriptionTargets reads a downloaded subscription: share links (plain
// or base64) or a Clash/mihomo YAML with a proxies list.
func subscriptionTargets(data []byte) map[string]probeTarget {
	out := map[string]probeTarget{}
	text := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if yamlProxies(text, func(m map[string]string) {
		if t, ok := targetOfYAML(m); ok {
			if _, dup := out[m["name"]]; !dup {
				out[m["name"]] = t
			}
		}
	}) {
		return out
	}
	if !strings.Contains(text, "://") {
		compact := strings.Join(strings.Fields(text), "")
		if raw, err := importer.DecodeB64(compact); err == nil {
			text = string(raw)
		}
	}
	// mihomo names the proxies by the links' names and numbers repeats
	// "name-01", "name-02" (common/convert: uniqueName)
	names := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !importer.IsShareLink(line) {
			continue
		}
		li, err := importer.InspectLink(line)
		if err != nil {
			continue
		}
		name := li.Name
		if n, ok := names[name]; ok {
			n++
			names[name] = n
			name = fmt.Sprintf("%s-%02d", name, n)
		} else {
			names[name] = 0
		}
		out[name] = targetOfLink(li)
	}
	return out
}

func targetOfYAML(m map[string]string) (probeTarget, bool) {
	port, _ := strconv.Atoi(m["port"])
	if m["name"] == "" || m["server"] == "" || port <= 0 {
		return probeTarget{}, false
	}
	t := probeTarget{Host: m["server"], Port: port}
	typ := strings.ToLower(m["type"])
	switch typ {
	case "hysteria", "hysteria2", "tuic", "wireguard", "masque":
		t.UDP = true
		return t, true
	case "trojan", "anytls":
		t.TLS = true
	}
	if b, _ := strconv.ParseBool(m["tls"]); b {
		t.TLS = true
	}
	if _, ok := m["reality-opts"]; ok {
		t.TLS = true
	}
	t.SNI = m["servername"]
	if t.SNI == "" {
		t.SNI = m["sni"]
	}
	return t, true
}

// yamlProxies walks the "proxies:" list of a Clash/mihomo YAML and calls fn
// with each item's own keys (nested maps are skipped; their key is kept with
// an empty value). Enough for names and addresses, not a YAML parser.
// It reports whether the text had a proxies list.
func yamlProxies(text string, fn func(map[string]string)) bool {
	in, found := false, false
	itemIndent, keyIndent := -1, -1
	var cur map[string]string
	flush := func() {
		if cur != nil {
			fn(cur)
		}
		cur = nil
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if !in {
			if indent == 0 && strings.HasPrefix(trimmed, "proxies:") {
				in, found = true, true
			}
			continue
		}
		if indent == 0 && !strings.HasPrefix(trimmed, "-") {
			break // the next top-level key
		}
		if strings.HasPrefix(trimmed, "-") && (itemIndent < 0 || indent == itemIndent) {
			itemIndent = indent
			flush()
			cur = map[string]string{}
			body := strings.TrimSpace(trimmed[1:])
			keyIndent = indent + (len(trimmed) - len(strings.TrimLeft(trimmed[1:], " ")))
			if strings.HasPrefix(body, "{") {
				for _, kv := range splitFlow(strings.TrimSuffix(strings.TrimPrefix(body, "{"), "}")) {
					if k, v, ok := yamlKV(kv); ok {
						cur[k] = v
					}
				}
				flush()
				continue
			}
			if k, v, ok := yamlKV(body); ok {
				cur[k] = v
			}
			continue
		}
		if cur != nil && indent == keyIndent {
			if k, v, ok := yamlKV(trimmed); ok {
				cur[k] = v
			}
		}
	}
	flush()
	return found
}

// splitFlow splits "a: 1, b: {c: 2}, d: [3, 4]" at the top-level commas.
func splitFlow(s string) []string {
	var parts []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func yamlKV(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", "", false
	}
	k := strings.Trim(strings.TrimSpace(s[:i]), `"'`)
	v := strings.TrimSpace(s[i+1:])
	switch {
	case strings.HasPrefix(v, `"`):
		if j := strings.Index(v[1:], `"`); j >= 0 {
			v = v[1 : j+1]
		}
	case strings.HasPrefix(v, "'"):
		if j := strings.Index(v[1:], "'"); j >= 0 {
			v = v[1 : j+1]
		}
	default:
		if j := strings.Index(v, " #"); j >= 0 {
			v = strings.TrimSpace(v[:j])
		}
	}
	return k, v, true
}

// probeServer connects to one server past the VPN.
func probeServer(ctx context.Context, t probeTarget, lookup func(context.Context, string) ([]string, error), d *net.Dialer) reachInfo {
	r := reachInfo{Addr: t.addr()}
	if t.UDP {
		r.Code, r.Text = reachUDP, "нет ответа"
		r.Note = "Сервер работает по UDP (Hysteria2, TUIC, WireGuard), такой напрямую не проверить; UDP часто блокируется провайдером."
		return r
	}
	ips := []string{t.Host}
	if net.ParseIP(t.Host) == nil {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		found, err := lookup(lctx, t.Host)
		cancel()
		if err != nil || len(found) == 0 {
			r.Code, r.Text = reachUnreachable, "недоступен"
			r.Note = "Адрес сервера " + t.Host + " не находится в DNS: сервер, скорее всего, больше не работает."
			if err != nil {
				r.Note += " (" + err.Error() + ")"
			}
			return r
		}
		if len(found) > 2 {
			found = found[:2]
		}
		ips = found
	}
	var conn net.Conn
	var err error
	start := time.Now()
	for _, ip := range ips {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err = d.DialContext(cctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(t.Port)))
		cancel()
		if err == nil {
			r.Addr = net.JoinHostPort(ip, strconv.Itoa(t.Port))
			break
		}
	}
	if err != nil {
		r.Code, r.Text = reachUnreachable, "недоступен"
		msg := err.Error()
		switch {
		case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(msg, "refused"):
			r.Note = "Сервер отклоняет подключение: на этом порту ничего не работает — сервер выключен или данные в подписке устарели."
		case isTimeout(err):
			r.Note = "Сервер не отвечает даже на простое подключение из вашей сети: его адрес, скорее всего, заблокирован провайдером, или сервер выключен."
		case errors.Is(err, syscall.ECONNRESET) || strings.Contains(msg, "reset") || strings.Contains(msg, "unreachable") || strings.Contains(msg, "no route"):
			r.Note = "Подключиться к серверу из вашей сети не удалось (" + msg + "): адрес, скорее всего, заблокирован провайдером."
		default:
			// not the network's answer (a local error): do not blame the server
			r.Code, r.Text = reachUnknown, "нет ответа"
			r.Note = "Проверка через сервер не прошла; проверить сервер напрямую не удалось: " + msg + "."
		}
		return r
	}
	defer conn.Close()
	connectMs := int(time.Since(start) / time.Millisecond)
	if !t.TLS {
		r.Code, r.Text = reachOpen, "нет ответа"
		r.Note = fmt.Sprintf("Сервер доступен напрямую (подключение за %d мс), но VPN через него не работает: ключи или настройки в подписке устарели, протокол блокируется провайдером, либо у сервера нет выхода в интернет.", connectMs)
		return r
	}
	sni := t.SNI
	if sni == "" && net.ParseIP(t.Host) == nil {
		sni = t.Host
	}
	conn.SetDeadline(time.Now().Add(probeTLSTimeout))
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	herr := tc.HandshakeContext(ctx)
	var alert tls.AlertError
	switch {
	case herr == nil || errors.As(herr, &alert) || strings.Contains(herr.Error(), "remote error"):
		// a ServerHello or a TLS alert: the server itself answered
		r.Code, r.Text = reachOpen, "нет ответа"
		r.Note = fmt.Sprintf("Сервер доступен напрямую (подключение за %d мс, TLS отвечает), но VPN через него не работает: ключи или настройки в подписке устарели, либо у сервера нет выхода в интернет.", connectMs)
	case isTimeout(herr):
		r.Code, r.Text = reachDPI, "блокируется"
		r.Note = "Подключение к серверу есть, но на защищённое соединение (TLS) ответа нет: так провайдер блокирует протокол VPN (DPI)."
	case errors.Is(herr, io.EOF) || errors.Is(herr, syscall.ECONNRESET) || strings.Contains(herr.Error(), "reset"):
		r.Code, r.Text = reachDPI, "блокируется"
		r.Note = "Подключение к серверу есть, но защищённое соединение (TLS) обрывается: так провайдер блокирует протокол VPN (DPI), либо сервер не принимает TLS."
	default:
		r.Code, r.Text = reachOpen, "нет ответа"
		r.Note = fmt.Sprintf("Сервер доступен напрямую (подключение за %d мс), но TLS с ним не устанавливается (%v): настройки в подписке, вероятно, устарели.", connectMs, herr)
	}
	return r
}

var probeTLSTimeout = 6 * time.Second

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) || strings.Contains(err.Error(), "timeout")
}

// probeDialer connects past the VPN: on Android the app is excluded from
// its own VPN; on Windows the socket is bound to the network card.
func (a *App) probeDialer() *net.Dialer {
	d := &net.Dialer{Timeout: 5 * time.Second}
	a.mu.Lock()
	tun := a.rt.TunEnabled
	a.mu.Unlock()
	if platform.IsWindows && tun {
		platform.BindDialer(d, platform.DefaultRouteIfIndex(TunName))
	}
	return d
}

// probeDead checks the servers mihomo found dead and remembers why they
// are; with logSummary it writes the outcome to the log when it changed.
func (a *App) probeDead(ctx context.Context, api *core.API, b *core.Built, logSummary bool) {
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	proxies, err := api.AllProxies(pctx)
	cancel()
	if err != nil {
		return
	}
	nodes := map[string]bool{} // node name → own server
	for _, n := range b.NodeName {
		nodes[n] = true
	}
	if len(b.SubProvider) > 0 {
		pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		provs, err := api.Providers(pctx)
		cancel()
		if err == nil {
			for _, pname := range b.SubProvider {
				for _, n := range provs[pname].Proxies {
					if _, own := nodes[n.Name]; !own {
						nodes[n.Name] = false
					}
				}
			}
		}
	}
	var dead []string
	alive := 0
	for n := range nodes {
		p, ok := proxies[n]
		if !ok || len(p.History) == 0 {
			continue
		}
		if p.LastDelay() > 0 {
			alive++
		} else if !p.Alive {
			dead = append(dead, n)
		}
	}
	sort.Strings(dead)
	targets := a.serverTargets(b, a.Settings())
	results := map[string]reachInfo{}
	byAddr := map[probeTarget][]string{}
	for _, n := range dead {
		t, ok := targets[n]
		if !ok {
			results[n] = reachInfo{Code: reachUnknown, Text: "нет ответа", Note: "Проверка через сервер не прошла; адрес сервера Лазейке неизвестен."}
			continue
		}
		byAddr[t] = append(byAddr[t], n)
	}
	if len(byAddr) > 0 {
		d := a.probeDialer()
		lookup := api.LookupIPv4
		if platform.IsAndroid {
			lookup = func(ctx context.Context, host string) ([]string, error) {
				ips, err := net.DefaultResolver.LookupHost(ctx, host)
				var v4 []string
				for _, ip := range ips {
					if p := net.ParseIP(ip); p != nil && p.To4() != nil {
						v4 = append(v4, ip)
					}
				}
				if err == nil && len(v4) == 0 {
					err = fmt.Errorf("для %s нет адреса IPv4", host)
				}
				return v4, err
			}
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 12)
		for t, names := range byAddr {
			wg.Add(1)
			go func(t probeTarget, names []string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				r := probeServer(ctx, t, lookup, d)
				mu.Lock()
				for _, n := range names {
					results[n] = r
				}
				mu.Unlock()
			}(t, names)
		}
		wg.Wait()
	}
	a.mu.Lock()
	a.reach = results
	a.mu.Unlock()
	if !logSummary || len(dead) == 0 {
		return
	}
	summary := reachSummary(alive, dead, results)
	a.mu.Lock()
	same := summary == a.reachLogged
	a.reachLogged = summary
	a.mu.Unlock()
	if !same {
		logx.Infof("%s", summary)
	}
}

// reachSummary: one log line with the counts and a few examples each.
func reachSummary(alive int, dead []string, results map[string]reachInfo) string {
	groups := map[string][]string{}
	for _, n := range dead {
		r := results[n]
		groups[r.Code] = append(groups[r.Code], n)
	}
	var parts []string
	add := func(code, title string) {
		names := groups[code]
		if len(names) == 0 {
			return
		}
		var ex []string
		for i, n := range names {
			if i == 3 {
				ex = append(ex, "…")
				break
			}
			r := results[n]
			e := "«" + n + "»"
			if r.Addr != "" {
				e += " " + r.Addr
			}
			ex = append(ex, e)
		}
		parts = append(parts, fmt.Sprintf("%s — %d (%s)", title, len(names), strings.Join(ex, ", ")))
	}
	add(reachUnreachable, "недоступны из этой сети (адрес заблокирован или сервер выключен)")
	add(reachDPI, "подключение есть, TLS обрывается (блокировка протокола)")
	add(reachOpen, "доступны напрямую, но VPN через них не работает")
	add(reachUDP, "по UDP, напрямую не проверить")
	add(reachUnknown, "адрес неизвестен")
	return fmt.Sprintf("серверы: отвечают %d из %d; не ответили: %s", alive, alive+len(dead), strings.Join(parts, "; "))
}

// reachOf returns the verdict for a dead node ("" when there is none).
func (a *App) reachOf(name string) reachInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reach[name]
}

// reachAfterConnect waits for mihomo's first checks after a start and then
// explains the servers that failed them.
func (a *App) reachAfterConnect(api *core.API, b *core.Built) {
	if !b.HasVPN {
		return
	}
	select {
	case <-a.ctx.Done():
		return
	case <-time.After(25 * time.Second):
	}
	a.mu.Lock()
	current := a.api == api
	a.mu.Unlock()
	if !current {
		return
	}
	a.probeDead(a.ctx, api, b, true)
}
