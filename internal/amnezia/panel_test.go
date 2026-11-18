package amnezia

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testConf = "# VPN Key: vpn://AAAA\n[Interface]\nPrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=\nAddress = 10.8.0.2/32\nJc = 4\n[Peer]\nPublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHVibGk=\nEndpoint = 203.0.113.7:51820\n"

// fakePanel answers like the personal account: a session cookie after the
// login, locations, files per country, and a page whose script gives a
// file back through /api/revoke-config.
type fakePanel struct {
	mu      sync.Mutex
	issued  map[string]bool
	revoked []string
	limit   int
	noPage  bool
}

func (f *fakePanel) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	authed := func(r *http.Request) bool {
		c, err := r.Cookie("session")
		return err == nil && c.Value == "s1"
	}
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			VpnKey string `json:"vpnKey"`
		}
		json.NewDecoder(r.Body).Decode(&v)
		if v.VpnKey != "vpn://good" {
			w.WriteHeader(401)
			w.Write([]byte(`{"message":"invalid key"}`))
			return
		}
		if ua := r.Header.Get("User-Agent"); !strings.Contains(ua, "Lazeyka") {
			t.Errorf("user agent %q", ua)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "s1", Path: "/"})
		w.Write([]byte(`{"message":"ok"}`))
	})
	mux.HandleFunc("GET /api/account-info", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"data":{"available_countries":[
			{"server_country_code":"NL","server_country_name":"Нидерланды","available_protocols":["awg","vless"]},
			{"server_country_code":"DE","server_country_name":"Германия","available_protocols":["awg"]},
			{"server_country_code":"US","server_country_name":"США","available_protocols":["vless"]},
			"FI"]}}`))
	})
	mux.HandleFunc("POST /api/download-config", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(401)
			return
		}
		var v struct {
			Country  string `json:"countryCode"`
			Declared string `json:"declaredCountryCode"`
		}
		json.NewDecoder(r.Body).Decode(&v)
		f.mu.Lock()
		defer f.mu.Unlock()
		if v.Declared != "ru" {
			t.Errorf("declared %q", v.Declared)
		}
		if !f.issued[v.Country] && len(f.issued) >= f.limit {
			w.WriteHeader(403)
			w.Write([]byte(`{"message":"limit","errorCode":"CONFIG_LIMIT"}`))
			return
		}
		f.issued[v.Country] = true
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(strings.Replace(testConf, "203.0.113.7", "203.0.113."+map[string]string{"nl": "10", "de": "20", "fi": "30"}[v.Country], 1)))
	})
	mux.HandleFunc("POST /api/revoke-config", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(401)
			return
		}
		var v struct {
			Country string `json:"countryCode"`
		}
		json.NewDecoder(r.Body).Decode(&v)
		f.mu.Lock()
		delete(f.issued, v.Country)
		f.revoked = append(f.revoked, v.Country)
		f.mu.Unlock()
		w.Write([]byte(`{"message":"ok"}`))
	})
	mux.HandleFunc("GET /ru", func(w http.ResponseWriter, r *http.Request) {
		if f.noPage {
			w.Write([]byte(`<html><script src="/assets/index-old.js"></script></html>`))
			return
		}
		w.Write([]byte(`<!doctype html><html><head><script type="module" crossorigin src="/assets/index-abc123.js"></script></head></html>`))
	})
	mux.HandleFunc("GET /assets/index-abc123.js", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`const a="/api/login",b="/api/account-info";function x(e){return n.post("/api/revoke-device",{deviceId:e})}` +
			`function w(){return n.post("/api/revoke-all-configs",{countryCode:"*"})}function v(){return n.get("/api/configs/revoke-info")}` +
			`function y(e,t){return n.post("/api/revoke-config",{countryCode:e.toLowerCase()})}function z(e){return n.post("/api/download-config",{countryCode:e,declaredCountryCode:t})}`))
	})
	mux.HandleFunc("GET /assets/index-old.js", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`fetch("/api/login");fetch("/api/revoke-device",{body:JSON.stringify({deviceId:1})})`))
	})
	return mux
}

func newFake(t *testing.T) (*fakePanel, *Client) {
	f := &fakePanel{issued: map[string]bool{}, limit: 7}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	return f, New(srv.Client(), srv.URL)
}

func TestPanelFlow(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	if err := New(c.hc, c.base).Login(ctx, "vpn://bad"); err == nil || !strings.Contains(err.Error(), "не принял ключ") {
		t.Fatalf("bad key: %v", err)
	}
	if err := c.Login(ctx, "vpn://good"); err != nil {
		t.Fatal(err)
	}
	locs, err := c.Locations(ctx, "awg")
	if err != nil {
		t.Fatal(err)
	}
	// USA has no AmneziaWG; a bare code keeps its code as the name; sorted by name
	want := []Location{{"de", "Германия"}, {"nl", "Нидерланды"}, {"fi", "FI"}}
	if len(locs) != 3 {
		t.Fatalf("locations %+v", locs)
	}
	got := map[string]string{}
	for _, l := range locs {
		got[l.Code] = l.Name
	}
	for _, w := range want {
		if got[w.Code] != w.Name {
			t.Errorf("location %s: %q", w.Code, got[w.Code])
		}
	}
	conf, err := c.Config(ctx, "NL", "ru")
	if err != nil || !strings.Contains(conf, "203.0.113.10") {
		t.Fatalf("config: %v %q", err, conf)
	}
	if err := c.Revoke(ctx, "nl"); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "nl" || f.issued["nl"] {
		t.Fatalf("revoked %v issued %v", f.revoked, f.issued)
	}
	if c.revokeRoute != "/api/revoke-config" || !strings.Contains(strings.Join(c.Routes, " "), "/api/revoke-device") {
		t.Fatalf("learned %q from %v", c.revokeRoute, c.Routes)
	}
}

func TestPanelLimitAndUnknownRevoke(t *testing.T) {
	f, c := newFake(t)
	f.limit = 1
	f.noPage = true
	ctx := context.Background()
	if err := c.Login(ctx, "vpn://good"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Config(ctx, "nl", "ru"); err != nil {
		t.Fatal(err)
	}
	_, err := c.Config(ctx, "de", "ru")
	var e *Error
	if !errors.As(err, &e) || e.Code != "CONFIG_LIMIT" || !strings.Contains(err.Error(), "7 подключений") {
		t.Fatalf("limit: %v", err)
	}
	// the page only knows "revoke-device": never called for a file
	if err := c.Revoke(ctx, "nl"); !errors.Is(err, ErrNoRevoke) || len(f.revoked) != 0 {
		t.Fatalf("revoke without a known route: %v %v", err, f.revoked)
	}
}

func TestFlag(t *testing.T) {
	if Flag("nl") != "🇳🇱" || Flag("x") != "" {
		t.Fatal(Flag("nl"))
	}
}
