package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lazeyka/internal/importer"
	"lazeyka/internal/settings"
)

// a personal account in miniature: files per country, a slot limit, and a
// page whose script gives a file back (unless noRevoke)
type miniPanel struct {
	mu       sync.Mutex
	issued   map[string]bool
	revoked  []string
	limit    int
	noRevoke bool
}

func (p *miniPanel) start(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "s", Value: "1", Path: "/"})
		w.Write([]byte(`{"message":"ok"}`))
	})
	mux.HandleFunc("GET /api/account-info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"available_countries":[{"server_country_code":"NL","server_country_name":"Нидерланды","available_protocols":["awg"]},{"server_country_code":"DE","server_country_name":"Германия","available_protocols":["awg"]}]}}`))
	})
	mux.HandleFunc("POST /api/download-config", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Country string `json:"countryCode"`
		}
		json.NewDecoder(r.Body).Decode(&v)
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.issued[v.Country] && len(p.issued) >= p.limit {
			w.WriteHeader(403)
			w.Write([]byte(`{"errorCode":"CONFIG_LIMIT"}`))
			return
		}
		p.issued[v.Country] = true
		host := map[string]string{"nl": "203.0.113.10", "de": "203.0.113.20"}[v.Country]
		w.Write([]byte("# VPN Key: vpn://secret\n[Interface]\nPrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=\nAddress = 10.8.0.2/32\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 20\nS2 = 30\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n[Peer]\nPublicKey = cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHVibGk=\nEndpoint = " + host + ":51820\n"))
	})
	mux.HandleFunc("POST /api/revoke-config", func(w http.ResponseWriter, r *http.Request) {
		if p.noRevoke {
			http.NotFound(w, r)
			return
		}
		var v struct {
			Country string `json:"countryCode"`
		}
		json.NewDecoder(r.Body).Decode(&v)
		p.mu.Lock()
		delete(p.issued, v.Country)
		p.revoked = append(p.revoked, v.Country)
		p.mu.Unlock()
		w.Write([]byte(`{"message":"ok"}`))
	})
	mux.HandleFunc("GET /ru", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<script src="/assets/app.js"></script>`))
	})
	mux.HandleFunc("GET /assets/app.js", func(w http.ResponseWriter, r *http.Request) {
		if p.noRevoke {
			w.Write([]byte(`fetch("/api/login")`))
			return
		}
		w.Write([]byte(`x.post("/api/revoke-config",{countryCode:e})`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	amneziaRevoke.Lock()
	amneziaRevoke.route, amneziaRevoke.field = "", ""
	amneziaRevoke.Unlock()
	old := amneziaBase
	amneziaBase = srv.URL
	t.Cleanup(func() { amneziaBase = old })
}

func (p *miniPanel) state() (map[string]bool, []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := map[string]bool{}
	for k, v := range p.issued {
		m[k] = v
	}
	return m, append([]string(nil), p.revoked...)
}

func TestAmneziaOneSlot(t *testing.T) {
	p := &miniPanel{issued: map[string]bool{}, limit: 7}
	p.start(t)
	a := newTestApp(t)
	a.update(func(s *settings.Settings) error { s.App.AutoConnect = false; return nil })
	key := importer.AmneziaKey{Key: "vpn://good", Name: "Amnezia Premium", Protocol: "awg", UserCountry: "ru"}

	locs, err := a.AmneziaLocations(key.Key, "")
	if err != nil || len(locs) != 2 {
		t.Fatalf("locations %v %v", locs, err)
	}
	name, _, err := a.AmneziaAdd(key, "nl")
	if err != nil || !strings.Contains(name, "Нидерланды") {
		t.Fatalf("add: %q %v", name, err)
	}
	set := a.Settings()
	if len(set.Servers) != 1 || set.Servers[0].Amnezia == nil || set.Servers[0].Amnezia.Country != "nl" || set.Servers[0].Host != "203.0.113.10" {
		t.Fatalf("server %+v", set.Servers)
	}
	id := set.Servers[0].ID

	// another location: the new file replaces the old one, the old is given back
	_, note, err := a.AmneziaSwitch(id, "de")
	if err != nil || note != "" {
		t.Fatalf("switch: %q %v", note, err)
	}
	srv := a.Settings().ServerByID(id)
	if srv == nil || srv.Amnezia.Country != "de" || srv.Host != "203.0.113.20" || !strings.Contains(srv.Name, "Германия") {
		t.Fatalf("after switch %+v", srv)
	}
	if issued, revoked := p.state(); len(issued) != 1 || !issued["de"] || len(revoked) != 1 || revoked[0] != "nl" {
		t.Fatalf("one slot: issued %v revoked %v", issued, revoked)
	}
	// adding the same key again only moves the location
	if _, _, err := a.AmneziaAdd(key, "nl"); err != nil || len(a.Settings().Servers) != 1 {
		t.Fatalf("re-add: %v, %d servers", err, len(a.Settings().Servers))
	}

	// all slots taken: the old file goes back first
	p.mu.Lock()
	p.limit = 1
	p.mu.Unlock()
	if err := a.PatchServer(ServerPatch{ID: id, Name: ptr("Мой Amnezia")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.AmneziaSwitch(id, "de"); err != nil {
		t.Fatalf("switch at the limit: %v", err)
	}
	if srv := a.Settings().ServerByID(id); srv.Name != "Мой Amnezia" || srv.Amnezia.Country != "de" {
		t.Fatalf("renamed server %+v", srv)
	}

	// deleting the server frees its slot
	if err := a.PatchServer(ServerPatch{ID: id, Delete: true}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if issued, _ := p.state(); len(issued) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	issued, revoked := p.state()
	t.Fatalf("delete kept the slot: issued %v revoked %v", issued, revoked)
}

func TestAmneziaUnknownRevoke(t *testing.T) {
	p := &miniPanel{issued: map[string]bool{}, limit: 7, noRevoke: true}
	p.start(t)
	a := newTestApp(t)
	a.update(func(s *settings.Settings) error { s.App.AutoConnect = false; return nil })
	key := importer.AmneziaKey{Key: "vpn://good", Protocol: "awg"}
	if _, _, err := a.AmneziaAdd(key, "nl"); err != nil {
		t.Fatal(err)
	}
	id := a.Settings().Servers[0].ID
	_, note, err := a.AmneziaSwitch(id, "de")
	if err != nil || !strings.Contains(note, "Нидерланды") || !strings.Contains(note, "Отозвать") {
		t.Fatalf("note %q %v", note, err)
	}
	if issued, revoked := p.state(); !issued["nl"] || len(revoked) != 0 {
		t.Fatalf("issued %v revoked %v", issued, revoked)
	}
}

func ptr[T any](v T) *T { return &v }
