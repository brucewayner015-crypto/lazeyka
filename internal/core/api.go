package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// API is a client for mihomo's REST controller.
type API struct {
	Base   string
	Secret string
	c      *http.Client
}

// NewAPI returns a client for 127.0.0.1:port.
func NewAPI(port int, secret string) *API {
	tr := &http.Transport{Proxy: nil, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	return &API{
		Base:   fmt.Sprintf("http://127.0.0.1:%d", port),
		Secret: secret,
		c:      &http.Client{Transport: tr},
	}
}

func (a *API) req(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.Base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return a.c.Do(req)
}

func (a *API) do(ctx context.Context, method, path string, body, out any) error {
	resp, err := a.req(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			return fmt.Errorf("mihomo: %s", e.Message)
		}
		return fmt.Errorf("mihomo: %s", resp.Status)
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

// Version returns the core version.
func (a *API) Version(ctx context.Context) (string, error) {
	var v struct {
		Version string `json:"version"`
	}
	err := a.do(ctx, http.MethodGet, "/version", nil, &v)
	return v.Version, err
}

// DelayRecord is one health-check result.
type DelayRecord struct {
	Time  string `json:"time"`
	Delay int    `json:"delay"`
}

// ProxyInfo is a proxy or group as reported by mihomo.
type ProxyInfo struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	Now     string        `json:"now,omitempty"`
	All     []string      `json:"all,omitempty"`
	Alive   bool          `json:"alive"`
	UDP     bool          `json:"udp"`
	History []DelayRecord `json:"history"`
	Hidden  bool          `json:"hidden,omitempty"`
}

// LastDelay is the most recent delay (0 = unknown/failed).
func (p ProxyInfo) LastDelay() int {
	if len(p.History) == 0 {
		return 0
	}
	return p.History[len(p.History)-1].Delay
}

// Proxies returns all proxies and groups.
func (a *API) Proxies(ctx context.Context) (map[string]ProxyInfo, error) {
	var v struct {
		Proxies map[string]ProxyInfo `json:"proxies"`
	}
	err := a.do(ctx, http.MethodGet, "/proxies", nil, &v)
	return v.Proxies, err
}

// Select chooses name inside a select group.
func (a *API) Select(ctx context.Context, group, name string) error {
	return a.do(ctx, http.MethodPut, "/proxies/"+url.PathEscape(group), map[string]string{"name": name}, nil)
}

// GroupDelay tests every member of a group.
func (a *API) GroupDelay(ctx context.Context, group, testURL string, timeoutMs int) (map[string]int, error) {
	q := url.Values{"url": {testURL}, "timeout": {strconv.Itoa(timeoutMs)}}
	out := map[string]int{}
	err := a.do(ctx, http.MethodGet, "/group/"+url.PathEscape(group)+"/delay?"+q.Encode(), nil, &out)
	return out, err
}

// Delay tests one proxy.
func (a *API) Delay(ctx context.Context, name, testURL string, timeoutMs int) (int, error) {
	q := url.Values{"url": {testURL}, "timeout": {strconv.Itoa(timeoutMs)}}
	var v struct {
		Delay int `json:"delay"`
	}
	err := a.do(ctx, http.MethodGet, "/proxies/"+url.PathEscape(name)+"/delay?"+q.Encode(), nil, &v)
	return v.Delay, err
}

// SubscriptionInfo comes from the subscription-userinfo header.
type SubscriptionInfo struct {
	Upload   int64 `json:"Upload"`
	Download int64 `json:"Download"`
	Total    int64 `json:"Total"`
	Expire   int64 `json:"Expire"`
}

// ProviderInfo is a proxy provider.
type ProviderInfo struct {
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	VehicleType      string            `json:"vehicleType"`
	Proxies          []ProxyInfo       `json:"proxies"`
	UpdatedAt        string            `json:"updatedAt"`
	SubscriptionInfo *SubscriptionInfo `json:"subscriptionInfo,omitempty"`
}

// Providers returns proxy providers.
func (a *API) Providers(ctx context.Context) (map[string]ProviderInfo, error) {
	var v struct {
		Providers map[string]ProviderInfo `json:"providers"`
	}
	err := a.do(ctx, http.MethodGet, "/providers/proxies", nil, &v)
	return v.Providers, err
}

// UpdateProvider re-downloads an http provider.
func (a *API) UpdateProvider(ctx context.Context, name string) error {
	return a.do(ctx, http.MethodPut, "/providers/proxies/"+url.PathEscape(name), nil, nil)
}

// HealthCheckProvider re-tests a provider's nodes.
func (a *API) HealthCheckProvider(ctx context.Context, name string) error {
	return a.do(ctx, http.MethodGet, "/providers/proxies/"+url.PathEscape(name)+"/healthcheck", nil, nil)
}

// RuleProviderInfo is a rule provider.
type RuleProviderInfo struct {
	Name        string `json:"name"`
	Behavior    string `json:"behavior"`
	RuleCount   int    `json:"ruleCount"`
	UpdatedAt   string `json:"updatedAt"`
	VehicleType string `json:"vehicleType"`
}

// RuleProviders lists rule providers.
func (a *API) RuleProviders(ctx context.Context) (map[string]RuleProviderInfo, error) {
	var v struct {
		Providers map[string]RuleProviderInfo `json:"providers"`
	}
	err := a.do(ctx, http.MethodGet, "/providers/rules", nil, &v)
	return v.Providers, err
}

// UpdateRuleProvider re-downloads a rule set.
func (a *API) UpdateRuleProvider(ctx context.Context, name string) error {
	return a.do(ctx, http.MethodPut, "/providers/rules/"+url.PathEscape(name), nil, nil)
}

// CloseConnections drops all connections (after a route change).
func (a *API) CloseConnections(ctx context.Context) error {
	return a.do(ctx, http.MethodDelete, "/connections", nil, nil)
}

// Totals of traffic.
type Totals struct {
	Up    int64 `json:"uploadTotal"`
	Down  int64 `json:"downloadTotal"`
	Conns int   `json:"conns"`
}

// Connections returns traffic totals and the number of open connections.
func (a *API) Connections(ctx context.Context) (Totals, error) {
	var v struct {
		Up          int64             `json:"uploadTotal"`
		Down        int64             `json:"downloadTotal"`
		Connections []json.RawMessage `json:"connections"`
	}
	err := a.do(ctx, http.MethodGet, "/connections", nil, &v)
	return Totals{Up: v.Up, Down: v.Down, Conns: len(v.Connections)}, err
}

// StreamTraffic calls fn every second with current up/down speeds until ctx ends.
func (a *API) StreamTraffic(ctx context.Context, fn func(up, down int64)) error {
	resp, err := a.req(ctx, http.MethodGet, "/traffic", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mihomo: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var t struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		}
		if json.Unmarshal(sc.Bytes(), &t) == nil {
			fn(t.Up, t.Down)
		}
	}
	return sc.Err()
}

// FlushFakeIP clears the fake-ip cache.
func (a *API) FlushFakeIP(ctx context.Context) error {
	return a.do(ctx, http.MethodPost, "/cache/fakeip/flush", nil, nil)
}
