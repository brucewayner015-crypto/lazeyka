package svyazka

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testEnv struct {
	t      *testing.T
	svc    *Service
	srv    *httptest.Server
	client *http.Client
	admin  string
}

func newTestEnv(t *testing.T) *testEnv {
	dir := t.TempDir()
	st, err := OpenStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st.Update(func(s *State) error {
		s.PasswordHash = HashPassword("correct horse")
		s.PublicIP = "127.0.0.1"
		return nil
	})
	svc := NewService(st, dir)
	svc.Logger = nil
	srv := httptest.NewServer(svc)
	svc.DevURL = srv.URL
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); srv.Close() })
	svc.ctx = ctx
	jar, _ := cookiejar.New(nil)
	return &testEnv{t: t, svc: svc, srv: srv, client: &http.Client{Jar: jar}, admin: "/" + st.Get().AdminPath + "/"}
}

func (e *testEnv) call(method, path string, body any, hdr ...string) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+e.admin+"api/"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set("X-Sv", "1")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (e *testEnv) waitFetched(n int) map[string]any {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, v := e.call(http.MethodGet, "state", nil)
		busy := false
		for _, s := range v["sources"].([]any) {
			if s.(map[string]any)["fetching"].(bool) {
				busy = true
			}
		}
		if !busy && len(v["servers"].([]any)) >= n {
			return v
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("not fetched: %v", v["sources"])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *testEnv) sub(token string) (*http.Response, []string) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/s/"+token, nil)
	req.Header.Set("User-Agent", "Happ/3.2.1")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			e.t.Fatal(err)
		}
		body = zr
	}
	raw, _ := io.ReadAll(body)
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}
	dec, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		e.t.Fatalf("not base64: %q", raw)
	}
	return resp, strings.Split(string(dec), "\n")
}

func TestServiceEndToEnd(t *testing.T) {
	var failB atomic.Bool
	var hwidSeen atomic.Value
	hwidSeen.Store("")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			w.Header().Set("subscription-userinfo", "upload=1; download=2; total=1000; expire=1900000000")
			var many []string
			many = append(many, vlessNL, info, trojRU)
			for i := 0; i < 40; i++ { // big enough to be gzipped
				many = append(many, strings.Replace(vlessDE, "666666666666", "6666666666"+string(rune('a'+i%26))+string(rune('a'+i/26)), 1))
			}
			io.WriteString(w, base64.StdEncoding.EncodeToString([]byte(strings.Join(many, "\n"))))
		case "/b":
			hwidSeen.Store(r.Header.Get("x-hwid"))
			if failB.Load() {
				http.Error(w, "down", http.StatusBadGateway)
				return
			}
			io.WriteString(w, vlessDE+"\n"+vlessNL+"\n")
		}
	}))
	defer up.Close()
	e := newTestEnv(t)
	st := e.svc.Store.Get()

	// strangers see nothing
	for _, p := range []string{"/", "/s/nope", "/admin/", "/" + st.AdminPath + "x/"} {
		resp, _ := http.Get(e.srv.URL + p)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	if code, _ := e.call(http.MethodGet, "state", nil); code != http.StatusUnauthorized {
		t.Fatal(code)
	}
	// the page itself loads, with a strict policy
	resp, err := http.Get(e.srv.URL + e.admin)
	if err != nil || resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal(err, resp.StatusCode)
	}
	resp.Body.Close()
	// no subscription yet: an error, not an empty list
	if r, _ := e.sub(st.SubToken); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatal(r.StatusCode)
	}
	if code, _ := e.call(http.MethodPost, "login", map[string]string{"password": "wrong"}); code != http.StatusUnauthorized {
		t.Fatal(code)
	}
	if code, _ := e.call(http.MethodPost, "login", map[string]string{"password": "correct horse"}); code != 200 {
		t.Fatal(code)
	}
	// a cross-site form cannot act
	if code, _ := e.call(http.MethodPost, "rotate", nil, "X-Sv", ""); code != http.StatusForbidden {
		t.Fatal(code)
	}
	if code, _ := e.call(http.MethodPost, "rotate", nil, "Sec-Fetch-Site", "cross-site"); code != http.StatusForbidden {
		t.Fatal(code)
	}
	// sources
	if code, v := e.call(http.MethodPost, "sources", map[string]string{"url": "ftp://x"}); code != 400 || v["error"] == "" {
		t.Fatal(code, v)
	}
	if code, v := e.call(http.MethodPost, "sources", map[string]string{"url": e.svc.DevURL + "/s/" + st.SubToken}); code != 400 {
		t.Fatal(code, v)
	}
	if code, v := e.call(http.MethodPost, "sources", map[string]string{"url": up.URL + "/a", "name": "Основная", "prefix": "A "}); code != 200 {
		t.Fatal(code, v)
	}
	if code, v := e.call(http.MethodPost, "sources", map[string]string{"url": up.URL + "/b", "hwid": "dev-1"}); code != 200 {
		t.Fatal(code, v)
	}
	if code, _ := e.call(http.MethodPost, "sources", map[string]string{"url": up.URL + "/b"}); code != 400 {
		t.Fatal("duplicate source accepted")
	}
	v := e.waitFetched(45)
	if hwidSeen.Load() != "dev-1" {
		t.Fatal("hwid not sent")
	}
	srcs := v["sources"].([]any)
	if srcs[1].(map[string]any)["name"] != "127.0.0.1" {
		t.Fatal(srcs[1])
	}
	resp, links := e.sub(st.SubToken)
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("not gzipped")
	}
	// info pseudo-server and the duplicate are gone; the RU server stays (no "RU" hide word by default)
	if len(links) != 1+1+40+1-0 { // NL, RU, 40 DE variants, DE from b (NL from b is a duplicate)
		t.Fatalf("%d links", len(links))
	}
	if LinkName(links[0]) != "A 🇳🇱 Netherlands 1" {
		t.Fatal(LinkName(links[0]))
	}
	if resp.Header.Get("Subscription-Userinfo") != "upload=1; download=2; total=1000; expire=1900000000" ||
		resp.Header.Get("Profile-Update-Interval") != "6" ||
		resp.Header.Get("Profile-Title") != "base64:"+base64.StdEncoding.EncodeToString([]byte("Связка")) {
		t.Fatal(resp.Header)
	}
	_, v = e.call(http.MethodGet, "state", nil)
	if hits := v["hits"].([]any); len(hits) == 0 || hits[0].(map[string]any)["ua"] != "Happ/3.2.1" {
		t.Fatal(v["hits"])
	}

	// rename, hide by word and by hand
	code, v := e.call(http.MethodPut, "rules", map[string]string{"rename": "Netherlands → Нидерланды\n/^A / →", "hide": "Moscow"})
	if code != 200 {
		t.Fatal(code, v)
	}
	if code, v := e.call(http.MethodPut, "rules", map[string]string{"rename": "no arrow here"}); code != 400 || !strings.Contains(v["error"].(string), "стрелка") {
		t.Fatal(code, v)
	}
	var deKey string
	for _, s := range v["servers"].([]any) {
		m := s.(map[string]any)
		if m["original"] == "Germany" && m["hidden"] == "" && deKey == "" {
			deKey = m["key"].(string)
		}
	}
	if code, _ := e.call(http.MethodPost, "hidden", map[string]any{"key": deKey, "hidden": true}); code != 200 {
		t.Fatal(code)
	}
	_, links = e.sub(st.SubToken)
	names := map[string]bool{}
	for _, l := range links {
		names[LinkName(l)] = true
	}
	if !names["🇳🇱 Нидерланды 1"] || names["🇷🇺 RU Moscow"] || len(links) != 41 {
		t.Fatalf("%d %v", len(links), names)
	}

	// a failing source keeps serving its last copy
	failB.Store(true)
	b := srcs[1].(map[string]any)["id"].(string)
	e.call(http.MethodPost, "refresh", map[string]string{"id": b})
	v = e.waitFetched(1)
	if src := v["sources"].([]any)[1].(map[string]any); src["err"] == "" || src["count"].(float64) != 2 {
		t.Fatal(src)
	}
	if _, again := e.sub(st.SubToken); len(again) != 41 {
		t.Fatal(len(again))
	}
	// disabling a source removes its servers
	e.call(http.MethodPatch, "sources/"+b, map[string]any{"enabled": false})
	if _, l := e.sub(st.SubToken); len(l) != 40 {
		t.Fatal(len(l))
	}

	// QR code of the link
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+e.admin+"api/qr", nil)
	qr, err := e.client.Do(req)
	if err != nil || qr.Header.Get("Content-Type") != "image/svg+xml" {
		t.Fatal(err)
	}
	qr.Body.Close()

	// a new link: the old one stops working
	if code, _ := e.call(http.MethodPost, "rotate", nil); code != 200 {
		t.Fatal(code)
	}
	if r, _ := e.sub(st.SubToken); r.StatusCode != http.StatusNotFound {
		t.Fatal(r.StatusCode)
	}
	if r, l := e.sub(e.svc.Store.Get().SubToken); r.StatusCode != 200 || len(l) != 40 {
		t.Fatal(r.StatusCode)
	}

	// a password change logs other sessions out
	other := &testEnv{t: t, svc: e.svc, srv: e.srv, admin: e.admin}
	jar, _ := cookiejar.New(nil)
	other.client = &http.Client{Jar: jar}
	other.call(http.MethodPost, "login", map[string]string{"password": "correct horse"})
	if code, _ := e.call(http.MethodPost, "password", map[string]string{"old": "nope", "new": "something-long"}); code != 400 {
		t.Fatal(code)
	}
	if code, v := e.call(http.MethodPost, "password", map[string]string{"old": "correct horse", "new": "something-long"}); code != 200 {
		t.Fatal(code, v)
	}
	if code, _ := e.call(http.MethodGet, "state", nil); code != 200 {
		t.Fatal("the changer itself was logged out")
	}
	if code, _ := other.call(http.MethodGet, "state", nil); code != http.StatusUnauthorized {
		t.Fatal("old session still valid")
	}
	// the service persisted the cache: a restart serves the same list at once
	svc2 := NewService(e.svc.Store, e.svc.DataDir)
	svc2.Logger = nil
	svc2.LoadCache()
	if svc2.snap == nil || len(svc2.snap.Links) != 40 {
		t.Fatal("cache not restored")
	}
}

func TestLoginLimiter(t *testing.T) {
	e := newTestEnv(t)
	for i := 0; i < limitPerIP; i++ {
		if code, _ := e.call(http.MethodPost, "login", map[string]string{"password": "x"}); code != http.StatusUnauthorized {
			t.Fatal(i, code)
		}
	}
	code, v := e.call(http.MethodPost, "login", map[string]string{"password": "correct horse"})
	if code != http.StatusTooManyRequests || !strings.Contains(v["error"].(string), "подождите") {
		t.Fatal(code, v)
	}
	// global limit
	var l limiter
	for i := 0; i < limitGlobal; i++ {
		l.fail("10.0.0." + string(rune('0'+i%10)) + string(rune('0'+i/10)))
	}
	if l.wait("192.0.2.1") <= 0 {
		t.Fatal("global limit not applied")
	}
}

func TestSessionToken(t *testing.T) {
	v := newSession("k1", time.Now().Add(time.Hour))
	if !validSession("k1", v) || validSession("k2", v) || validSession("k1", v+"x") {
		t.Fatal("signature")
	}
	if validSession("k1", newSession("k1", time.Now().Add(-time.Second))) {
		t.Fatal("expired accepted")
	}
}

func TestStoreReloadsExternalChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	a, _ := OpenStore(path)
	a.Update(func(s *State) error { s.Title = "one"; return nil })
	b, _ := OpenStore(path)
	time.Sleep(20 * time.Millisecond) // a different modification time
	b.Update(func(s *State) error { s.Title = "two"; return nil })
	if a.Get().Title != "two" {
		t.Fatal("not reloaded")
	}
}
