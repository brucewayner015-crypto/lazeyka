package importer

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
)

// DecodeAmneziaLink decodes an AmneziaVPN "vpn://" share string into JSON.
// Format: base64url (no padding) of Qt qCompress(json): 4-byte big-endian
// length followed by a zlib stream.
func DecodeAmneziaLink(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 6 && strings.EqualFold(s[:6], "vpn://") {
		s = s[6:]
	}
	s = strings.TrimRight(strings.Join(strings.Fields(s), ""), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errf("ссылка vpn:// повреждена (base64): %v", err)
	}
	if json.Valid(raw) {
		return raw, nil
	}
	if len(raw) > 4 {
		want := binary.BigEndian.Uint32(raw[:4])
		zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
		if err == nil {
			data, err := io.ReadAll(io.LimitReader(zr, 16<<20))
			zr.Close()
			if err == nil && (want == 0 || int(want) == len(data) || json.Valid(data)) {
				return data, nil
			}
		}
	}
	return nil, errf("не удалось распаковать ссылку vpn://")
}

// ParseAmneziaJSON turns an Amnezia server config (decoded vpn://) into servers.
func ParseAmneziaJSON(data []byte) Result {
	var res Result
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		res.Errors = append(res.Errors, "конфиг Amnezia: неверный JSON")
		return res
	}
	desc := str(root["description"])
	hostName := str(root["hostName"])
	if desc == "" {
		desc = hostName
	}
	containers, _ := root["containers"].([]any)
	if len(containers) == 0 {
		res.Errors = append(res.Errors, "в конфиге Amnezia нет протоколов (containers)")
		return res
	}
	for _, c := range containers {
		cm, _ := c.(map[string]any)
		if cm == nil {
			continue
		}
		cname := strings.ToLower(str(cm["container"]))
		short := strings.TrimPrefix(cname, "amnezia-")
		protoKey := short
		if strings.HasPrefix(short, "awg") {
			protoKey = "awg"
		}
		pm, _ := cm[protoKey].(map[string]any)
		lastCfg := ""
		if pm != nil {
			lastCfg = str(pm["last_config"])
		}
		switch {
		case protoKey == "awg" || protoKey == "wireguard":
			if lastCfg == "" {
				res.Errors = append(res.Errors, "Amnezia: у протокола "+short+" нет клиентского конфига — экспортируйте подключение заново")
				continue
			}
			var lc map[string]any
			if err := json.Unmarshal([]byte(lastCfg), &lc); err != nil {
				res.Errors = append(res.Errors, "Amnezia: повреждён конфиг "+short)
				continue
			}
			conf := str(lc["config"])
			if conf == "" {
				res.Errors = append(res.Errors, "Amnezia: в конфиге "+short+" нет текста .conf")
				continue
			}
			name := strings.TrimSpace(desc + " AWG")
			proxy, info, err := ParseAWGConf(conf, name)
			if err != nil {
				res.Errors = append(res.Errors, "Amnezia ("+short+"): "+err.Error())
				continue
			}
			// AmneziaVPN keeps the MTU (1376 for AWG) beside the .conf text
			if _, ok := proxy["mtu"]; !ok {
				if n := atoiAny(lc["mtu"]); n >= 576 && n <= 9000 {
					proxy["mtu"] = n
				}
			}
			res.Items = append(res.Items, awgItem(proxy, info, name, "AmneziaVPN"))
		case protoKey == "xray" || protoKey == "ssxray":
			if lastCfg == "" {
				res.Errors = append(res.Errors, "Amnezia: у XRay нет клиентского конфига — экспортируйте подключение заново")
				continue
			}
			links, err := XrayToLinks([]byte(lastCfg), strings.TrimSpace(desc+" XRay"))
			if err != nil {
				res.Errors = append(res.Errors, "Amnezia (XRay): "+err.Error())
				continue
			}
			for _, l := range links {
				it, err := linkItem(l, "AmneziaVPN")
				if err != nil {
					res.Errors = append(res.Errors, err.Error())
					continue
				}
				res.Items = append(res.Items, it)
			}
		case strings.Contains(short, "openvpn"), strings.Contains(short, "cloak"), short == "ipsec", short == "ikev2":
			res.Errors = append(res.Errors, "Amnezia: протокол "+short+" не поддерживается (и в РФ он легко блокируется) — пропущен")
		case short == "dns", short == "sftp", short == "tor", short == "socks5proxy", short == "mtproxy", short == "telemt", short == "tproxy":
			// service containers, nothing to import
		default:
			res.Errors = append(res.Errors, "Amnezia: неизвестный протокол "+short+" — пропущен")
		}
	}
	return res
}
