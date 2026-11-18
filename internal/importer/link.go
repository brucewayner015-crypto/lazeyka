package importer

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Share-link schemes that mihomo converts natively (common/convert/converter.go).
var linkProtos = map[string]string{
	"vless":           "VLESS",
	"vmess":           "VMess",
	"trojan":          "Trojan",
	"ss":              "Shadowsocks",
	"ssr":             "ShadowsocksR",
	"hysteria":        "Hysteria",
	"hysteria2":       "Hysteria2",
	"hy2":             "Hysteria2",
	"hysteria2+realm": "Hysteria2",
	"hy2+realm":       "Hysteria2",
	"tuic":            "TUIC",
	"anytls":          "AnyTLS",
	"mierus":          "Mieru",
	"socks":           "SOCKS5",
	"socks5":          "SOCKS5",
	"socks5h":         "SOCKS5",
}

// SchemeOf returns the lower-cased scheme of a "scheme://..." line.
func SchemeOf(line string) string {
	i := strings.Index(line, "://")
	if i <= 0 || i > 20 {
		return ""
	}
	return strings.ToLower(line[:i])
}

// IsShareLink reports whether line is a proxy share link mihomo understands.
func IsShareLink(line string) bool {
	_, ok := linkProtos[SchemeOf(line)]
	return ok
}

// LinkInfo is a human summary of a share link.
type LinkInfo struct {
	Proto     string
	Name      string
	Host      string
	Port      int
	Transport string
	Security  string
	Flow      string
	SNI       string // the TLS server name the client sends ("" = none or the host)
}

// OverUDP: the protocol runs over UDP (QUIC or WireGuard), so a TCP
// connection to the server says nothing about it.
func (li LinkInfo) OverUDP() bool {
	switch li.Proto {
	case "Hysteria", "Hysteria2", "TUIC", "WireGuard", "AmneziaWG":
		return true
	}
	return false
}

// UsesTLS: the client opens the connection with a TLS handshake (TLS,
// Reality, Trojan), so the server must answer one.
func (li LinkInfo) UsesTLS() bool {
	if li.OverUDP() {
		return false
	}
	switch li.Security {
	case "tls", "xtls", "reality":
		return true
	}
	return li.Proto == "Trojan" || li.Proto == "AnyTLS"
}

// Summary returns "VLESS · XHTTP · Reality".
func (li LinkInfo) Summary() string {
	parts := []string{li.Proto}
	if li.Transport != "" && li.Transport != "tcp" && li.Transport != "raw" {
		parts = append(parts, strings.ToUpper(li.Transport))
	} else if li.Proto == "VLESS" || li.Proto == "Trojan" || li.Proto == "VMess" {
		parts = append(parts, "TCP")
	}
	switch li.Security {
	case "reality":
		parts = append(parts, "Reality")
	case "tls", "xtls":
		parts = append(parts, "TLS")
	}
	if strings.Contains(li.Flow, "vision") {
		parts = append(parts, "Vision")
	}
	return strings.Join(parts, " · ")
}

// InspectLink extracts display information from a share link.
func InspectLink(link string) (LinkInfo, error) {
	scheme := SchemeOf(link)
	proto, ok := linkProtos[scheme]
	if !ok {
		return LinkInfo{}, errf("неизвестный тип ссылки")
	}
	li := LinkInfo{Proto: proto}
	body := link[len(scheme)+3:]
	if scheme == "vmess" {
		if raw, err := decodeB64Loose(stripFragment(body)); err == nil && json.Valid(raw) {
			var v map[string]any
			_ = json.Unmarshal(raw, &v)
			li.Name = str(v["ps"])
			li.Host = str(v["add"])
			li.Port = atoiAny(v["port"])
			li.Transport = strings.ToLower(str(v["net"]))
			li.Security = strings.ToLower(str(v["tls"]))
			li.SNI = str(v["sni"])
			if li.SNI == "" && li.Security == "tls" {
				li.SNI = str(v["host"])
			}
			if li.Host == "" || li.Port == 0 {
				return li, errf("в ссылке VMess нет адреса сервера")
			}
			return li, nil
		}
	}
	u, err := url.Parse(link)
	if err != nil {
		return li, errf("не удалось разобрать ссылку: %v", err)
	}
	li.Name = u.Fragment
	host := u.Host
	if scheme == "ss" && u.Port() == "" {
		// SIP002 legacy: ss://BASE64(method:pass@host:port)#name
		if raw, err := decodeB64Loose(u.Host); err == nil {
			s := string(raw)
			if at := strings.LastIndex(s, "@"); at >= 0 {
				host = s[at+1:]
			}
		}
	}
	if scheme == "vless" && !strings.Contains(host, ":") {
		// some generators base64-encode the host part
		if raw, err := decodeB64Loose(host); err == nil {
			host = string(raw)
		}
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return li, errf("в ссылке нет адреса или порта сервера")
	}
	li.Host = h
	li.Port, _ = strconv.Atoi(p)
	if li.Host == "" || li.Port <= 0 {
		return li, errf("в ссылке нет адреса или порта сервера")
	}
	q := u.Query()
	li.Transport = strings.ToLower(q.Get("type"))
	li.Security = strings.ToLower(q.Get("security"))
	li.Flow = strings.ToLower(q.Get("flow"))
	for _, k := range []string{"sni", "peer", "serverName", "servername"} {
		if v := q.Get(k); v != "" {
			li.SNI = v
			break
		}
	}
	if scheme == "trojan" && li.Security == "" {
		li.Security = "tls"
	}
	if scheme == "vless" && li.Transport == "" {
		li.Transport = "tcp"
	}
	return li, nil
}

// RenameLink sets the display name (fragment, or "ps" for base64 VMess).
func RenameLink(link, name string) string {
	scheme := SchemeOf(link)
	if scheme == "vmess" {
		body := link[len(scheme)+3:]
		if raw, err := decodeB64Loose(stripFragment(body)); err == nil && json.Valid(raw) {
			var v map[string]any
			if json.Unmarshal(raw, &v) == nil {
				v["ps"] = name
				nb, _ := json.Marshal(v)
				return "vmess://" + base64.StdEncoding.EncodeToString(nb)
			}
		}
	}
	base := link
	if i := strings.Index(base, "#"); i >= 0 {
		base = base[:i]
	}
	return base + "#" + strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}

func stripFragment(s string) string {
	if i := strings.Index(s, "#"); i >= 0 {
		return s[:i]
	}
	return s
}

func decodeB64Loose(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func atoiAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	}
	return 0
}

// DecodeB64 decodes base64 in any of its usual forms (standard or URL
// alphabet, with or without padding), as found in subscriptions.
func DecodeB64(s string) ([]byte, error) { return decodeB64Loose(s) }
