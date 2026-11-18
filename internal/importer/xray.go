package importer

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// XrayToLinks converts an Xray client JSON config (or a single outbound) into
// share links that mihomo parses natively. VLESS, Trojan and Shadowsocks
// outbounds are supported.
func XrayToLinks(data []byte, defaultName string) ([]string, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, errf("неверный JSON конфига Xray")
	}
	var outbounds []any
	if ob, ok := root["outbounds"].([]any); ok {
		outbounds = ob
	} else if _, ok := root["protocol"]; ok {
		outbounds = []any{root}
	}
	var links []string
	for _, o := range outbounds {
		om, _ := o.(map[string]any)
		if om == nil {
			continue
		}
		proto := strings.ToLower(str(om["protocol"]))
		if proto != "vless" && proto != "trojan" && proto != "shadowsocks" {
			continue
		}
		name := defaultName
		if tag := str(om["tag"]); tag != "" && tag != "proxy" && !strings.HasPrefix(tag, "proxy") {
			name = tag
		}
		link, err := outboundToLink(proto, om, name)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		return nil, errf("в конфиге Xray нет подключений VLESS/Trojan/Shadowsocks")
	}
	return links, nil
}

func outboundToLink(proto string, om map[string]any, name string) (string, error) {
	settings, _ := om["settings"].(map[string]any)
	if settings == nil {
		return "", errf("в конфиге Xray нет settings")
	}
	var addr string
	var port int
	var user map[string]any
	if vnext, ok := settings["vnext"].([]any); ok && len(vnext) > 0 { // classic vless
		v0, _ := vnext[0].(map[string]any)
		addr, port = str(v0["address"]), atoiAny(v0["port"])
		if users, ok := v0["users"].([]any); ok && len(users) > 0 {
			user, _ = users[0].(map[string]any)
		}
	} else if servers, ok := settings["servers"].([]any); ok && len(servers) > 0 { // trojan / ss
		s0, _ := servers[0].(map[string]any)
		addr, port = str(s0["address"]), atoiAny(s0["port"])
		user = s0
	} else { // simplified (Xray 25+) flat form
		addr, port = str(settings["address"]), atoiAny(settings["port"])
		user = settings
	}
	if addr == "" || port == 0 {
		return "", errf("в конфиге Xray нет адреса или порта сервера")
	}
	hostport := net.JoinHostPort(addr, strconv.Itoa(port))
	if proto == "shadowsocks" {
		method, pass := str(user["method"]), str(user["password"])
		if method == "" || pass == "" {
			return "", errf("Shadowsocks: нет метода шифрования или пароля")
		}
		ui := url.UserPassword(method, pass).String()
		return RenameLink("ss://"+ui+"@"+hostport, name), nil
	}

	q := url.Values{}
	stream, _ := om["streamSettings"].(map[string]any)
	network := strings.ToLower(str(stream["network"]))
	switch network {
	case "", "raw", "tcp":
		network = "tcp"
	case "splithttp":
		network = "xhttp"
	case "h2", "http":
		network = "http"
	}
	q.Set("type", network)
	security := strings.ToLower(str(stream["security"]))
	if security == "" {
		security = "none"
	}
	q.Set("security", security)

	switch security {
	case "reality":
		rs, _ := stream["realitySettings"].(map[string]any)
		if rs == nil {
			return "", errf("Reality: нет realitySettings")
		}
		if sn := str(rs["serverName"]); sn != "" {
			q.Set("sni", sn)
		}
		pbk := str(rs["publicKey"])
		if pbk == "" {
			pbk = str(rs["password"]) // Xray 25.x naming
		}
		if pbk == "" {
			return "", errf("Reality: нет publicKey")
		}
		q.Set("pbk", pbk)
		q.Set("sid", str(rs["shortId"]))
		if fp := str(rs["fingerprint"]); fp != "" {
			q.Set("fp", fp)
		}
		if spx := str(rs["spiderX"]); spx != "" {
			q.Set("spx", spx)
		}
	case "tls":
		ts, _ := stream["tlsSettings"].(map[string]any)
		if ts != nil {
			if sn := str(ts["serverName"]); sn != "" {
				q.Set("sni", sn)
			}
			if fp := str(ts["fingerprint"]); fp != "" {
				q.Set("fp", fp)
			}
			if alpn, ok := ts["alpn"].([]any); ok && len(alpn) > 0 {
				var a []string
				for _, x := range alpn {
					a = append(a, str(x))
				}
				q.Set("alpn", strings.Join(a, ","))
			}
		}
	}

	switch network {
	case "xhttp":
		xs, _ := stream["xhttpSettings"].(map[string]any)
		if xs == nil {
			xs, _ = stream["splithttpSettings"].(map[string]any)
		}
		if xs != nil {
			if v := str(xs["path"]); v != "" {
				q.Set("path", v)
			}
			if v := str(xs["host"]); v != "" {
				q.Set("host", v)
			}
			if v := str(xs["mode"]); v != "" {
				q.Set("mode", v)
			}
			if extra, ok := xs["extra"].(map[string]any); ok && len(extra) > 0 {
				eb, _ := json.Marshal(extra)
				q.Set("extra", string(eb))
			}
		}
	case "ws", "httpupgrade":
		key := "wsSettings"
		if network == "httpupgrade" {
			key = "httpupgradeSettings"
		}
		ws, _ := stream[key].(map[string]any)
		if ws != nil {
			if v := str(ws["path"]); v != "" {
				q.Set("path", v)
			}
			host := str(ws["host"])
			if h, ok := ws["headers"].(map[string]any); ok && host == "" {
				host = str(h["Host"])
			}
			if host != "" {
				q.Set("host", host)
			}
		}
	case "grpc":
		gs, _ := stream["grpcSettings"].(map[string]any)
		if gs != nil {
			q.Set("serviceName", str(gs["serviceName"]))
		}
	case "tcp":
		tcp, _ := stream["tcpSettings"].(map[string]any)
		if tcp == nil {
			tcp, _ = stream["rawSettings"].(map[string]any)
		}
		if h, ok := tcp["header"].(map[string]any); ok && strings.EqualFold(str(h["type"]), "http") {
			q.Set("headerType", "http")
		}
	}

	switch proto {
	case "vless":
		id := str(user["id"])
		if id == "" {
			return "", errf("VLESS: нет UUID пользователя")
		}
		if flow := str(user["flow"]); flow != "" {
			q.Set("flow", flow)
		}
		if enc := str(user["encryption"]); enc != "" && enc != "none" {
			q.Set("encryption", enc)
		}
		return RenameLink("vless://"+url.PathEscape(id)+"@"+hostport+"?"+q.Encode(), name), nil
	case "trojan":
		pass := str(user["password"])
		if pass == "" {
			return "", errf("Trojan: нет пароля")
		}
		return RenameLink("trojan://"+url.PathEscape(pass)+"@"+hostport+"?"+q.Encode(), name), nil
	}
	return "", errf("неподдерживаемый протокол %s", proto)
}
