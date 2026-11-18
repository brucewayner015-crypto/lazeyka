// Package importer recognises whatever the user pastes or opens — share links,
// AmneziaWG/WireGuard configs, AmneziaVPN vpn:// strings, Xray JSON, base64
// subscription bodies and subscription URLs — and turns it into servers.
package importer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"lazeyka/internal/settings"
)

// Item is one imported server or subscription.
type Item struct {
	Server       *settings.Server       `json:"server,omitempty"`
	Subscription *settings.Subscription `json:"subscription,omitempty"`
	Amnezia      *AmneziaKey            `json:"amnezia,omitempty"` // a Premium key: a location is chosen in the app
	Note         string                 `json:"note,omitempty"`
}

// AmneziaKey is an Amnezia Premium vpn:// key: no server inside, only the
// login to the personal account, where the files of the locations are.
type AmneziaKey struct {
	Key         string `json:"key"` // the vpn:// text as given (secret)
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`     // awg
	UserCountry string `json:"user_country"` // the user's country the key was sold for
}

// Result of an import.
type Result struct {
	Items  []Item   `json:"items"`
	Errors []string `json:"errors"`
}

type importError string

func (e importError) Error() string { return string(e) }

func errf(format string, a ...any) error { return importError(fmt.Sprintf(format, a...)) }

// Parse recognises text (and an optional file name for naming/format hints).
func Parse(text, filename string) Result {
	text = strings.TrimPrefix(text, "\ufeff")
	t := strings.TrimSpace(text)
	if t == "" {
		return Result{Errors: []string{"пусто: вставьте ссылку, конфиг или адрес подписки"}}
	}
	base := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))

	// Whole-text formats first.
	if IsAWGConf(t) {
		name := base
		if name == "" || name == "." {
			name = ""
		}
		proxy, info, err := ParseAWGConf(t, name)
		if err != nil {
			return Result{Errors: []string{err.Error()}}
		}
		if name == "" {
			proxy["name"] = info.Summary() + " " + info.Host
		}
		return Result{Items: []Item{awgItem(proxy, info, str(proxy["name"]), "файл .conf")}}
	}
	if strings.HasPrefix(t, "{") {
		return parseJSON([]byte(t), base)
	}

	var res Result
	unknown := 0
	for _, raw := range strings.Split(strings.ReplaceAll(t, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "vpn://"):
			data, err := DecodeAmneziaLink(line)
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				continue
			}
			if k, ok := premiumKey(data, line); ok {
				res.Items = append(res.Items, Item{Amnezia: &k,
					Note: "ключ Amnezia Premium: Лазейка возьмёт в личном кабинете файл выбранной локации — одно подключение из 7"})
				continue
			}
			sub := parseJSON(data, "")
			res.Items = append(res.Items, sub.Items...)
			res.Errors = append(res.Errors, sub.Errors...)
		case strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://"):
			it, err := subscriptionItem(line)
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				continue
			}
			res.Items = append(res.Items, it)
		case IsShareLink(line):
			it, err := linkItem(line, "ссылка")
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				continue
			}
			res.Items = append(res.Items, it)
		case strings.HasPrefix(low, "happ://"):
			res.Errors = append(res.Errors, "зашифрованные ссылки happ:// не поддерживаются: возьмите обычную ссылку на подписку")
		case strings.HasPrefix(low, "awg://") || strings.HasPrefix(low, "wireguard://") || strings.HasPrefix(low, "wg://"):
			res.Errors = append(res.Errors, "ссылки awg:// и wireguard:// не поддерживаются: экспортируйте конфиг AmneziaWG файлом .conf или ссылкой vpn://")
		default:
			unknown++
		}
	}
	if len(res.Items) == 0 && unknown > 0 {
		// Maybe a pasted base64 subscription body.
		if raw, err := decodeB64Loose(strings.Join(strings.Fields(t), "")); err == nil && len(raw) > 0 {
			dec := strings.TrimSpace(string(raw))
			if dec != t && (strings.Contains(dec, "://") || strings.HasPrefix(dec, "{")) {
				return Parse(dec, filename)
			}
		}
		if strings.Contains(t, "proxies:") {
			res.Errors = append(res.Errors, "это похоже на YAML-конфиг Clash: добавьте ссылку на подписку (https://…) вместо содержимого")
		} else {
			res.Errors = append(res.Errors, "не удалось распознать: поддерживаются vless://, trojan://, hysteria2://, ss://, vmess://, tuic://, vpn:// (AmneziaVPN), конфиги AmneziaWG/WireGuard (.conf), JSON Xray и ссылки на подписки")
		}
	} else if unknown > 0 {
		res.Errors = append(res.Errors, fmt.Sprintf("пропущено нераспознанных строк: %d", unknown))
	}
	return res
}

func parseJSON(data []byte, base string) Result {
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return Result{Errors: []string{"неверный JSON"}}
	}
	if _, ok := probe["containers"]; ok {
		return ParseAmneziaJSON(data)
	}
	if _, ok := probe["outbounds"]; ok || probe["protocol"] != nil {
		name := base
		if name == "" {
			name = "Xray"
		}
		links, err := XrayToLinks(data, name)
		if err != nil {
			return Result{Errors: []string{err.Error()}}
		}
		var res Result
		for _, l := range links {
			it, err := linkItem(l, "JSON Xray")
			if err != nil {
				res.Errors = append(res.Errors, err.Error())
				continue
			}
			res.Items = append(res.Items, it)
		}
		return res
	}
	if cfg, ok := probe["config"].(string); ok && IsAWGConf(cfg) { // bare Amnezia last_config
		return Parse(cfg, base)
	}
	if probe["auth_data"] != nil || probe["api_config"] != nil || probe["api_key"] != nil || probe["api_endpoint"] != nil {
		return Result{Errors: []string{amneziaServiceKey(probe)}}
	}
	return Result{Errors: []string{"неизвестный формат JSON: ожидается конфиг Xray или AmneziaVPN"}}
}

// premiumKey recognises an Amnezia Premium key (config_version with
// api_config and auth_data, service "amnezia-premium").
func premiumKey(data []byte, raw string) (AmneziaKey, bool) {
	var v struct {
		Name      string `json:"name"`
		APIConfig struct {
			ServiceType     string `json:"service_type"`
			ServiceProtocol string `json:"service_protocol"`
			UserCountryCode string `json:"user_country_code"`
		} `json:"api_config"`
		AuthData struct {
			APIKey string `json:"api_key"`
		} `json:"auth_data"`
	}
	if json.Unmarshal(data, &v) != nil || v.AuthData.APIKey == "" {
		return AmneziaKey{}, false
	}
	service := strings.ToLower(v.APIConfig.ServiceType)
	if !strings.Contains(service, "premium") {
		return AmneziaKey{}, false
	}
	k := AmneziaKey{Key: strings.TrimSpace(raw), Name: v.Name, Protocol: strings.ToLower(v.APIConfig.ServiceProtocol), UserCountry: strings.ToLower(v.APIConfig.UserCountryCode)}
	if k.Name == "" {
		k.Name = "Amnezia Premium"
	}
	if k.Protocol == "" {
		k.Protocol = "awg"
	}
	return k, true
}

// AWGServer makes a server of an AmneziaWG file (the Amnezia Premium
// location files go this way).
func AWGServer(conf, name, source string) (*settings.Server, error) {
	proxy, info, err := ParseAWGConf(conf, name)
	if err != nil {
		return nil, err
	}
	return awgItem(proxy, info, name, source).Server, nil
}

// amneziaServiceKey explains a vpn:// key of the Amnezia Premium or Free
// service. Such a key holds no server: only an access key that the
// AmneziaVPN and DefaultVPN apps trade for settings over Amnezia's own
// encrypted API. For other programs Amnezia hands out ready AmneziaWG files
// in the Premium personal account, where the same key is the login.
func amneziaServiceKey(probe map[string]any) string {
	service := ""
	if ac, ok := probe["api_config"].(map[string]any); ok {
		service = strings.ToLower(str(ac["service_type"]))
	}
	if strings.Contains(service, "free") || strings.Contains(strings.ToLower(str(probe["name"])), "free") {
		return "Это ключ Amnezia Free: сервера в нём нет, только ключ к службе Amnezia, с которой работает лишь приложение AmneziaVPN. " +
			"Файлов конфигурации для других программ у Amnezia Free нет."
	}
	return "Это ключ подписки Amnezia Premium: сервера в нём нет, только ключ к службе Amnezia, с которой работают лишь приложения AmneziaVPN и DefaultVPN. " +
		"Для Лазейки нужен файл AmneziaWG: войдите этим ключом в личный кабинет https://cp.amnezia.org/ru " +
		"(не открывается — зеркало https://storage.googleapis.com/amnezia/cp?m-path=/ru), откройте «Файлы конфигурации», " +
		"выберите локацию, нажмите «Получить новый» и добавьте сюда полученный файл .conf («Открыть файл…»). " +
		"Каждый файл занимает одно из 7 подключений подписки; на каждое устройство — своя локация, один файл на двух устройствах не работает."
}

func linkItem(link, source string) (Item, error) {
	info, err := InspectLink(link)
	if err != nil {
		return Item{}, errf("%s: %v", shorten(link), err)
	}
	name := strings.TrimSpace(info.Name)
	if name == "" {
		name = info.Proto + " " + info.Host
	}
	srv := &settings.Server{
		ID:      settings.RandomHex(4),
		Name:    name,
		Kind:    settings.KindLink,
		Link:    link,
		Enabled: true,
		Source:  source,
		Info:    info.Summary(),
		Host:    info.Host,
		Port:    info.Port,
		Added:   time.Now(),
	}
	it := Item{Server: srv}
	switch {
	case info.Proto == "VLESS" && info.Security == "none":
		it.Note = "VLESS без шифрования (security=none) — легко блокируется"
	case info.Proto == "VLESS" && info.Security == "reality" && (info.Transport == "tcp" || info.Transport == "raw"):
		it.Note = "Reality поверх TCP с 2026 года режут после ~16 КБ — надёжнее XHTTP"
	case info.Proto == "Shadowsocks" || info.Proto == "ShadowsocksR":
		it.Note = "Shadowsocks в РФ определяется DPI — используйте как запасной"
	}
	return it, nil
}

func awgItem(proxy map[string]any, info AWGInfo, name, source string) Item {
	if name == "" {
		name = info.Summary() + " " + info.Host
	}
	proxy["name"] = name
	srv := &settings.Server{
		ID:      settings.RandomHex(4),
		Name:    name,
		Kind:    settings.KindAWG,
		Proxy:   proxy,
		Enabled: true,
		Source:  source,
		Info:    info.Summary(),
		Host:    info.Host,
		Port:    info.Port,
		Added:   time.Now(),
	}
	it := Item{Server: srv}
	switch info.Version {
	case "WireGuard":
		it.Note = "обычный WireGuard в РФ блокируется — нужен AmneziaWG"
	case "1.0", "1.5":
		it.Note = "AmneziaWG " + info.Version + " уже блокируется — обновите сервер до 3.1"
	case "2.0":
		it.Note = "AmneziaWG 2.0 с лета 2026 под блокировками — лучше 3.1"
	}
	return it
}

func subscriptionItem(raw string) (Item, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Item{}, errf("неверный адрес подписки: %s", shorten(raw))
	}
	name := u.Hostname()
	return Item{Subscription: &settings.Subscription{
		ID:            settings.RandomHex(4),
		Name:          name,
		URL:           raw,
		Enabled:       true,
		UserAgent:     settings.DefaultUserAgent,
		HWID:          true,
		IntervalHours: 6,
		Hide:          append([]string{}, settings.DefaultHide...),
		Rename:        []settings.Rename{},
		Added:         time.Now(),
	}}, nil
}

func shorten(s string) string {
	if len(s) > 48 {
		return s[:40] + "…"
	}
	return s
}
