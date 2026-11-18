package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mihomo's /proxies has no servers from providers; their checks come from
// /providers/proxies (seen live: every server in the picker said "нет ответа").
func TestAllProxiesAddsProviderServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/proxies":
			w.Write([]byte(`{"proxies":{"BLOCKED":{"name":"BLOCKED","type":"Selector","now":"Auto 3","all":["AUTO","Auto 3","Auto 4","own"]},` +
				`"DIRECT":{"name":"DIRECT","type":"Direct","alive":true,"history":[]}}}`))
		case "/providers/proxies":
			w.Write([]byte(`{"providers":{` +
				`"default":{"name":"default","vehicleType":"Compatible","proxies":[{"name":"DIRECT","type":"Direct","alive":true,"history":[]}]},` +
				`"own-01":{"name":"own-01","vehicleType":"File","proxies":[{"name":"own","type":"Vless","alive":true,"history":[{"time":"t","delay":120}]}]},` +
				`"sub-x":{"name":"sub-x","vehicleType":"HTTP","proxies":[` +
				`{"name":"Auto 3","type":"Vless","alive":true,"history":[{"time":"t","delay":340}]},` +
				`{"name":"Auto 4","type":"Vless","alive":false,"history":[{"time":"t","delay":0}]}]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	api := &API{Base: srv.URL, c: srv.Client()}
	all, err := api.AllProxies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p := all["Auto 3"]; !p.Alive || p.LastDelay() != 340 {
		t.Errorf("Auto 3: %+v", p)
	}
	if p := all["Auto 4"]; p.Alive || len(p.History) != 1 {
		t.Errorf("Auto 4: %+v", p)
	}
	if p := all["own"]; p.LastDelay() != 120 {
		t.Errorf("own: %+v", p)
	}
	if p := all["BLOCKED"]; p.Now != "Auto 3" || !strings.Contains(strings.Join(p.All, ","), "Auto 4") {
		t.Errorf("groups must stay: %+v", p)
	}
}
