// Package amnezia talks to the Amnezia Premium personal account
// (cp.amnezia.org) with a subscription key: sign in, the list of locations,
// the AmneziaWG file of a location and giving a file back.
//
// These are the calls the account's own web page makes. Amnezia does not
// document them and may block an account that uses them outside its page:
// awg-manager removed the same feature in October 2026 with that warning.
// The owner of Лазейка chose to use them knowingly, so Лазейка calls the
// account only when the user asks (adding the key, changing the location),
// never on a schedule, and says who it is in User-Agent.
package amnezia

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Panel is the personal account.
const Panel = "https://cp.amnezia.org"

// UserAgent: Лазейка does not pretend to be a browser.
var UserAgent = "Lazeyka (Amnezia Premium)"

const maxBody = 4 << 20

// Location is one country of the subscription.
type Location struct {
	Code string `json:"code"` // lower case: "nl"
	Name string `json:"name"` // as the account names it: "Нидерланды"
}

// Error is the account's own refusal.
type Error struct {
	Status int
	Code   string // errorCode: CONFIG_LIMIT, MAX_DEVICES_REACHED, …
	Msg    string
}

func (e *Error) Error() string {
	switch e.Code {
	case "CONFIG_LIMIT", "MAX_DEVICES_REACHED":
		return "заняты все 7 подключений подписки: освободите одно в личном кабинете Amnezia (отвяжите устройство или отзовите файл)"
	case "NO_PROTOCOL_COMPATIBLE_WORKER":
		return "в этой локации сейчас нет сервера AmneziaWG — выберите другую"
	}
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		return "личный кабинет Amnezia не принял ключ: проверьте, что подписка действует"
	}
	msg := e.Msg
	if msg == "" {
		msg = fmt.Sprintf("ответ %d", e.Status)
	}
	return "личный кабинет Amnezia: " + msg
}

// ErrNoRevoke: Лазейка does not know how the account gives a file back.
var ErrNoRevoke = errors.New("не удалось узнать, как личный кабинет отзывает файл")

// Client is one signed-in session.
type Client struct {
	hc   *http.Client
	base string

	revokeRoute, revokeField string // learned from the account's page
	Routes                   []string
}

// New makes a client over hc (its transport and timeout) with its own cookies.
func New(hc *http.Client, base string) *Client {
	if base == "" {
		base = Panel
	}
	jar, _ := cookiejar.New(nil)
	c := *hc
	c.Jar = jar
	return &Client{hc: &c, base: strings.TrimRight(base, "/")}
}

func (c *Client) do(ctx context.Context, method, path string, body any) ([]byte, string, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode >= 400 {
		e := &Error{Status: resp.StatusCode}
		var v struct {
			Message   string `json:"message"`
			ErrorCode string `json:"errorCode"`
		}
		if json.Unmarshal(data, &v) == nil {
			e.Code, e.Msg = v.ErrorCode, v.Message
		}
		return data, resp.Header.Get("Content-Type"), e
	}
	return data, resp.Header.Get("Content-Type"), nil
}

// Login signs in with the vpn:// key (the account's login is the key itself).
func (c *Client) Login(ctx context.Context, key string) error {
	data, _, err := c.do(ctx, http.MethodPost, "/api/login", map[string]any{"vpnKey": strings.TrimSpace(key), "remember": false})
	if err != nil {
		return err
	}
	var v struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &v) != nil || !strings.EqualFold(v.Message, "ok") {
		return &Error{Status: http.StatusUnauthorized, Msg: "ключ не подошёл"}
	}
	return nil
}

// Locations lists the countries where protocol ("awg") is available.
func (c *Client) Locations(ctx context.Context, protocol string) ([]Location, error) {
	data, _, err := c.do(ctx, http.MethodGet, "/api/account-info?appLanguage=ru", nil)
	if err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("личный кабинет Amnezia ответил не JSON")
	}
	if d, ok := top["data"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(d, &inner) == nil {
			top = inner
		}
	}
	raw, ok := top["available_countries"]
	if !ok {
		var ac map[string]json.RawMessage
		if json.Unmarshal(top["api_config"], &ac) == nil {
			raw = ac["available_countries"]
		}
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, fmt.Errorf("личный кабинет Amnezia не прислал список локаций")
	}
	var out []Location
	seen := map[string]bool{}
	for _, it := range items {
		var code, name string
		var protocols []string
		if json.Unmarshal(it, &code) != nil {
			var o struct {
				Code      string   `json:"server_country_code"`
				Code2     string   `json:"country_code"`
				Code3     string   `json:"code"`
				Name      string   `json:"server_country_name"`
				Name2     string   `json:"server_country_code_l10n"`
				Name3     string   `json:"name"`
				Protocols []string `json:"available_protocols"`
			}
			if json.Unmarshal(it, &o) != nil {
				continue
			}
			code = first(o.Code, o.Code2, o.Code3)
			name = first(o.Name, o.Name2, o.Name3)
			protocols = o.Protocols
		}
		code = strings.ToLower(strings.TrimSpace(code))
		if code == "" || seen[code] {
			continue
		}
		if len(protocols) > 0 && protocol != "" && !containsFold(protocols, protocol) {
			continue
		}
		seen[code] = true
		if name == "" {
			name = strings.ToUpper(code)
		}
		out = append(out, Location{Code: code, Name: name})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("в подписке нет локаций с AmneziaWG")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Config returns the AmneziaWG file of a location (issuing it if needed).
// declared is the user's country from the key ("ru").
func (c *Client) Config(ctx context.Context, country, declared string) (string, error) {
	if declared == "" {
		declared = "ru"
	}
	data, ctype, err := c.do(ctx, http.MethodPost, "/api/download-config", map[string]any{
		"countryCode":         strings.ToLower(country),
		"declaredCountryCode": strings.ToLower(declared),
	})
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "{") || strings.Contains(ctype, "json") {
		var v struct {
			Message   string `json:"message"`
			ErrorCode string `json:"errorCode"`
			Config    string `json:"config"`
		}
		if json.Unmarshal(data, &v) == nil && v.Config != "" {
			text = strings.TrimSpace(v.Config)
		} else {
			return "", &Error{Status: http.StatusOK, Code: v.ErrorCode, Msg: v.Message}
		}
	}
	low := strings.ToLower(text)
	if !strings.Contains(low, "[interface]") || !strings.Contains(low, "[peer]") {
		return "", fmt.Errorf("личный кабинет Amnezia прислал не файл AmneziaWG")
	}
	return text + "\n", nil
}

// RevokeCall is how the account gives a file back, once learned; UseRevoke
// hands it to a new session so the page is read only once.
func (c *Client) RevokeCall() (route, field string) { return c.revokeRoute, c.revokeField }

func (c *Client) UseRevoke(route, field string) {
	if revokeCandidate(route) && field != "" {
		c.revokeRoute, c.revokeField = route, field
	}
}

// Revoke gives the file of a location back (frees its slot), the way the
// account's page does it. ErrNoRevoke when that way is unknown.
func (c *Client) Revoke(ctx context.Context, country string) error {
	if c.revokeRoute == "" {
		if err := c.learnRevoke(ctx); err != nil {
			return err
		}
	}
	_, _, err := c.do(ctx, http.MethodPost, c.revokeRoute, map[string]any{c.revokeField: strings.ToLower(country)})
	var e *Error
	if errors.As(err, &e) && (e.Status == http.StatusNotFound || e.Status == http.StatusMethodNotAllowed) {
		c.revokeRoute, c.revokeField = "", "" // the account changed: learn again next time
		return ErrNoRevoke
	}
	return err
}

var (
	scriptRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js)["']`)
	routeRe  = regexp.MustCompile("[\"'`](/api/[A-Za-z0-9_\\-/]+)[\"'`]")
	// the call's own payload, right after the route: ("/api/…", {countryCode: …})
	payloadRe = regexp.MustCompile(`^\s*,\s*\{[^{}]{0,200}?\bcountryCode\b`)
)

// revokeCandidate: a route that gives a file back — "revoke" and "config"
// in its name and nothing about devices, keys or the account.
func revokeCandidate(route string) bool {
	r := strings.ToLower(route)
	if !strings.Contains(r, "revoke") || !strings.Contains(r, "config") {
		return false
	}
	for _, bad := range []string{"device", "key", "account", "subscription", "all"} {
		if strings.Contains(r, bad) {
			return false
		}
	}
	return true
}

// learnRevoke reads the account's page (its scripts) for the call that
// gives a file back: a route with "revoke" and "config" in its name, called
// with an object that names the country in the field download-config uses.
// The page is public; nothing is called unless exactly that is found.
func (c *Client) learnRevoke(ctx context.Context) error {
	var page []byte
	var err error
	for _, p := range []string{"/ru", "/"} {
		if page, _, err = c.do(ctx, http.MethodGet, p, nil); err == nil {
			break
		}
	}
	if err != nil {
		return ErrNoRevoke
	}
	seen := map[string]bool{}
	var scripts [][]byte
	for i, m := range scriptRe.FindAllSubmatch(page, -1) {
		if i == 8 {
			break
		}
		src := string(m[1])
		if strings.HasPrefix(src, "http") && !strings.HasPrefix(src, c.base) {
			continue
		}
		src = strings.TrimPrefix(src, c.base)
		if !strings.HasPrefix(src, "/") {
			src = "/" + src
		}
		if body, _, err := c.do(ctx, http.MethodGet, src, nil); err == nil {
			scripts = append(scripts, body)
		}
	}
	scripts = append(scripts, page)
	for _, js := range scripts {
		for _, loc := range routeRe.FindAllSubmatchIndex(js, -1) {
			route := string(js[loc[2]:loc[3]])
			if !seen[route] {
				seen[route] = true
				c.Routes = append(c.Routes, route)
			}
			if c.revokeRoute != "" || !revokeCandidate(route) {
				continue
			}
			end := loc[1] + 260
			if end > len(js) {
				end = len(js)
			}
			if payloadRe.Match(js[loc[1]:end]) {
				c.revokeRoute, c.revokeField = route, "countryCode"
			}
		}
	}
	sort.Strings(c.Routes)
	if c.revokeRoute == "" {
		return ErrNoRevoke
	}
	return nil
}

func first(v ...string) string {
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), s) {
			return true
		}
	}
	return false
}

// Flag is the emoji flag of a country code ("nl" → 🇳🇱).
func Flag(code string) string {
	code = strings.ToUpper(code)
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	return string([]rune{0x1F1E6 + rune(code[0]-'A'), 0x1F1E6 + rune(code[1]-'A')})
}

// Timeout for one call to the account.
const Timeout = 25 * time.Second
