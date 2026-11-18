package importer

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// AWGInfo describes a parsed AmneziaWG/WireGuard config.
type AWGInfo struct {
	Version string // "3.1", "3.0", "2.0", "1.5", "1.0", "WireGuard"
	Host    string
	Port    int
}

// Summary returns "AmneziaWG 3.1" or "WireGuard".
func (a AWGInfo) Summary() string {
	if a.Version == "WireGuard" {
		return "WireGuard"
	}
	return "AmneziaWG " + a.Version
}

// IsAWGConf reports whether text looks like a WireGuard-style INI config.
func IsAWGConf(text string) bool {
	low := strings.ToLower(text)
	return strings.Contains(low, "[interface]") && strings.Contains(low, "[peer]")
}

var awgV3Keys = map[string]string{
	"headerprotectionkey":    "header-protection-key",
	"contentpaddingaddition": "content-padding-addition",
	"rekeyaftertime":         "rekey-after-time",
	"rekeytimeout":           "rekey-timeout",
	"rejectaftertime":        "reject-after-time",
	"keepalivetimeout":       "keepalive-timeout",
	"maxhandshakeattempts":   "max-handshake-attempts",
}

// ParseAWGConf converts an AmneziaWG (1.0 … 3.1) or WireGuard .conf into a
// mihomo "wireguard" proxy map with amnezia-wg-option.
func ParseAWGConf(text, name string) (map[string]any, AWGInfo, error) {
	var info AWGInfo
	iface := map[string]string{}
	peer := map[string]string{}
	section := ""
	peers := 0
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peers++
			}
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:eq]))
		v := strings.TrimSpace(line[eq+1:])
		switch section {
		case "interface":
			iface[k] = v
		case "peer":
			if peers == 1 { // only the first peer is used
				peer[k] = v
			}
		}
	}
	if len(iface) == 0 || len(peer) == 0 {
		return nil, info, errf("это не похоже на конфиг AmneziaWG/WireGuard: нужны секции [Interface] и [Peer]")
	}
	priv := iface["privatekey"]
	pub := peer["publickey"]
	endpoint := peer["endpoint"]
	if priv == "" {
		return nil, info, errf("в конфиге нет PrivateKey")
	}
	if pub == "" {
		return nil, info, errf("в конфиге нет PublicKey сервера")
	}
	if endpoint == "" {
		return nil, info, errf("в конфиге нет Endpoint (адреса сервера)")
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, info, errf("не удалось разобрать Endpoint %q", endpoint)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, info, errf("неверный порт в Endpoint %q", endpoint)
	}
	info.Host, info.Port = host, port

	var ip4, ip6 string
	for _, a := range splitList(iface["address"]) {
		addr := a
		if p, err := netip.ParsePrefix(a); err == nil {
			addr = p.Addr().String()
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			continue
		}
		if ip.Is4() && ip4 == "" {
			ip4 = ip.String()
		} else if ip.Is6() && ip6 == "" {
			ip6 = ip.String()
		}
	}
	if ip4 == "" && ip6 == "" {
		return nil, info, errf("в конфиге нет Address (внутреннего адреса туннеля)")
	}

	p := map[string]any{
		"name":        name,
		"type":        "wireguard",
		"server":      host,
		"port":        port,
		"private-key": priv,
		"public-key":  pub,
		"udp":         true,
	}
	if ip4 != "" {
		p["ip"] = ip4
	}
	if ip6 != "" {
		p["ipv6"] = ip6
	}
	if psk := peer["presharedkey"]; psk != "" {
		p["pre-shared-key"] = psk
	}
	allowed := splitList(peer["allowedips"])
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	p["allowed-ips"] = allowed
	if mtu := iface["mtu"]; mtu != "" {
		if n, err := strconv.Atoi(mtu); err == nil && n >= 576 && n <= 9000 {
			p["mtu"] = n
		}
	}
	if ka := peer["persistentkeepalive"]; ka != "" {
		// AWG 3 allows a range ("22-30"); mihomo takes a single number.
		if i := strings.Index(ka, "-"); i > 0 {
			ka = ka[:i]
		}
		if n, err := strconv.Atoi(strings.TrimSpace(ka)); err == nil && n > 0 {
			p["persistent-keepalive"] = n
		}
	}
	if dns := splitList(iface["dns"]); len(dns) > 0 {
		var servers []string
		for _, d := range dns {
			if _, err := netip.ParseAddr(d); err == nil {
				servers = append(servers, d)
			}
		}
		if len(servers) > 0 {
			servers = append(servers, "1.1.1.1")
			p["remote-dns-resolve"] = true
			p["dns"] = dedup(servers)
		}
	}

	opt := map[string]any{}
	intKeys := []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"}
	for _, k := range intKeys {
		if v, ok := iface[k]; ok && v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, info, errf("параметр %s должен быть числом, а не %q", strings.ToUpper(k[:1])+k[1:], v)
			}
			opt[k] = n
		}
	}
	hasRange := false
	for _, k := range []string{"h1", "h2", "h3", "h4"} {
		if v := iface[k]; v != "" {
			opt[k] = v
			if strings.Contains(v, "-") {
				hasRange = true
			}
		}
	}
	hasI := false
	for _, k := range []string{"i1", "i2", "i3", "i4", "i5"} {
		if v := iface[k]; v != "" {
			opt[k] = v
			hasI = true
		}
	}
	v3 := false
	for confKey, optKey := range awgV3Keys {
		if v := iface[confKey]; v != "" {
			opt[optKey] = v
			v3 = true
		}
	}
	v31 := false
	for confKey, optKey := range map[string]string{"randomtrailers": "random-trailers", "disablecookies": "disable-cookies"} {
		if v := iface[confKey]; v != "" {
			v3, v31 = true, true
			if awgToggle(v) {
				opt[optKey] = true
			}
		}
	}
	hasJ := false
	if !v3 {
		for _, k := range []string{"j1", "j2", "j3"} {
			if v := iface[k]; v != "" {
				opt[k] = v
				hasJ = true
			}
		}
		if v := iface["itime"]; v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				opt["itime"] = n
				hasJ = true
			}
		}
	}
	_, hasS3 := opt["s3"]
	_, hasS4 := opt["s4"]
	switch {
	case v31:
		info.Version = "3.1"
	case v3:
		info.Version = "3.0"
	case hasRange || hasS3 || hasS4:
		info.Version = "2.0"
	case hasI || hasJ:
		info.Version = "1.5"
	case len(opt) > 0:
		info.Version = "1.0"
	default:
		info.Version = "WireGuard"
	}
	if v3 {
		opt["version"] = 3
	}
	if len(opt) > 0 {
		p["amnezia-wg-option"] = opt
	}
	return p, info, nil
}

// awgToggle reads an AWG 3.1 switch the way AmneziaVPN does: it writes
// "on"/"off", and anything but "off" (or an explicit false/0/no) means on.
func awgToggle(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "off", "false", "0", "no", "disabled":
		return false
	}
	return true
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
