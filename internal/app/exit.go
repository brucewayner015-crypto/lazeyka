package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"lazeyka/internal/core"
)

// The country blocked sites leave from. Лазейка asks Cloudflare's trace page
// through a local listener that goes the way blocked sites go (lz-exit), so
// the answer is the selected server's exit — also when the server sends its
// traffic on through WARP or another hop.

const exitTraceURL = "https://www.cloudflare.com/cdn-cgi/trace"

// ExitView answers /api/exit.
type ExitView struct {
	Node    string `json:"node"`    // the exit node the country belongs to
	Country string `json:"country"` // ISO 3166 code, "" while unknown
	IP      string `json:"ip,omitempty"`
	Pending bool   `json:"pending"`
}

type exitState struct {
	node    string
	country string
	ip      string
	at      time.Time
	failed  bool
	running bool
}

// Exit returns what is known about the exit of blocked traffic and starts a
// fresh probe when that is stale or belongs to another node.
func (a *App) Exit() ExitView {
	node := a.blockedExit()
	if node == "" {
		return ExitView{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e := &a.exit
	v := ExitView{Node: node}
	if e.node == node {
		v.Country, v.IP = e.country, e.ip
	}
	age := time.Since(e.at)
	fresh := e.node == node && (!e.failed && age < 10*time.Minute || e.failed && age < time.Minute)
	if fresh {
		return v
	}
	v.Pending = true
	if !e.running {
		e.running = true
		go a.probeExit(node)
	}
	return v
}

// blockedExit is the node blocked sites currently leave by ("" = VPN off).
func (a *App) blockedExit() string {
	api, _, err := a.apiOrErr()
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(a.ctx, 3*time.Second)
	defer cancel()
	proxies, err := api.Proxies(ctx)
	if err != nil {
		return ""
	}
	if _, ok := proxies[core.GBlocked]; !ok {
		return ""
	}
	return resolveExit(proxies, core.GBlocked)
}

func (a *App) probeExit(node string) {
	country, ip, err := a.traceExit()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.exit.running = false
	if err != nil {
		a.exit = exitState{node: node, at: time.Now(), failed: true}
		return
	}
	changed := a.exit.country != country
	a.exit = exitState{node: node, country: country, ip: ip, at: time.Now()}
	if changed {
		go a.refreshTray()
	}
}

func (a *App) traceExit() (country, ip string, err error) {
	u := a.exitProxyURL()
	if u == nil {
		return "", "", errors.New("VPN выключен")
	}
	ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exitTraceURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := socksClient(u, 15*time.Second).Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseTrace(io.LimitReader(resp.Body, 8<<10))
}

// parseTrace reads Cloudflare's "key=value" trace: loc is the country.
func parseTrace(r io.Reader) (country, ip string, err error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		switch k {
		case "loc":
			country = strings.ToUpper(v)
		case "ip":
			ip = v
		}
	}
	if len(country) != 2 || country == "XX" || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
		return "", ip, errors.New("страна не определилась")
	}
	return country, ip, nil
}

// exitCountry is the cached country of the current exit, for the tray.
func (a *App) exitCountry() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.exit.failed || time.Since(a.exit.at) > 30*time.Minute {
		return ""
	}
	return a.exit.country
}
