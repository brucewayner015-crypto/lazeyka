package svyazka

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed assets
var assets embed.FS

const adminCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// ServeHTTP answers everything: the subscription at /s/<token>, the web
// interface at /<secret path>/, and "not found" for the rest of the world.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	st := s.Store.Get()
	p := r.URL.Path
	if tok, ok := strings.CutPrefix(p, "/s/"); ok {
		if hmac.Equal([]byte(strings.TrimSuffix(tok, "/")), []byte(st.SubToken)) {
			s.serveSub(w, r, st)
			return
		}
	}
	admin := "/" + st.AdminPath
	if p == admin {
		http.Redirect(w, r, admin+"/", http.StatusFound)
		return
	}
	if rest, ok := strings.CutPrefix(p, admin+"/"); ok {
		s.serveAdmin(w, r, st, rest)
		return
	}
	if p == "/robots.txt" {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "User-agent: *\nDisallow: /\n")
		return
	}
	http.NotFound(w, r)
}

func (s *Service) serveSub(w http.ResponseWriter, r *http.Request, st *State) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.recordHit(clientIP(r), r.UserAgent())
	s.mu.Lock()
	snap := s.snap
	s.mu.Unlock()
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	if snap == nil || len(snap.Links) == 0 {
		// an error keeps the apps' previous list; an empty answer would wipe it
		h.Set("Retry-After", "600")
		http.Error(w, "Связка: серверов пока нет — источники ещё не загружены или все серверы скрыты", http.StatusServiceUnavailable)
		return
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(st.Title)))
	h.Set("Profile-Update-Interval", strconv.Itoa(st.UpdateHours))
	h.Set("Content-Disposition", "inline; filename*=UTF-8''"+url.PathEscape(st.Title))
	if snap.Userinfo != "" {
		h.Set("Subscription-Userinfo", snap.Userinfo)
	}
	body := EncodeLinks(snap.Links)
	if r.URL.Query().Has("plain") {
		body = strings.Join(snap.Links, "\n") + "\n"
	}
	writeBody(w, r, []byte(body))
}

func writeBody(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Add("Vary", "Accept-Encoding")
	if len(body) > 1024 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(body)
		zw.Close()
		body = buf.Bytes()
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	w.Write(body)
}

var assetTypes = map[string]string{
	"index.html": "text/html; charset=utf-8",
	"app.js":     "text/javascript; charset=utf-8",
	"app.css":    "text/css; charset=utf-8",
	"icon.svg":   "image/svg+xml",
}

func (s *Service) serveAdmin(w http.ResponseWriter, r *http.Request, st *State, rest string) {
	h := w.Header()
	h.Set("Content-Security-Policy", adminCSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if api, ok := strings.CutPrefix(rest, "api/"); ok {
		s.serveAPI(w, r, st, api)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := rest
	if name == "" {
		name = "index.html"
	}
	typ, ok := assetTypes[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := assets.ReadFile("assets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sum := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	h.Set("ETag", etag)
	h.Set("Cache-Control", "no-cache")
	h.Set("Content-Type", typ)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeBody(w, r, b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		code, b = http.StatusInternalServerError, []byte(`{"error":"внутренняя ошибка"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write(b)
}

func apiErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		return errors.New("неверный запрос")
	}
	return nil
}

// badRequest is an error whose text is shown to the user as is.
type badRequest string

func (e badRequest) Error() string { return string(e) }

func (s *Service) serveAPI(w http.ResponseWriter, r *http.Request, st *State, api string) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// a custom header cannot be sent cross-site without CORS, which is never allowed here
		site := r.Header.Get("Sec-Fetch-Site")
		if r.Header.Get("X-Sv") != "1" || site != "" && site != "same-origin" {
			apiErr(w, http.StatusForbidden, "запрос отклонён")
			return
		}
	}
	if api == "login" {
		if r.Method != http.MethodPost {
			apiErr(w, http.StatusMethodNotAllowed, "нужен POST")
			return
		}
		s.apiLogin(w, r, st)
		return
	}
	if !s.authed(r, st) {
		apiErr(w, http.StatusUnauthorized, "нужно войти")
		return
	}
	var err error
	route := r.Method + " " + api
	switch {
	case route == "GET state":
	case route == "GET qr":
		s.apiQR(w, st)
		return
	case route == "POST logout":
		s.clearSession(w, st)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	case route == "POST sources":
		err = s.apiAddSource(r, st)
	case strings.HasPrefix(api, "sources/") && (r.Method == http.MethodPatch || r.Method == http.MethodDelete):
		err = s.apiChangeSource(r, strings.TrimPrefix(api, "sources/"))
	case route == "POST refresh":
		err = s.apiRefresh(r)
	case route == "PUT rules":
		err = s.apiRules(r)
	case route == "POST hidden":
		err = s.apiHidden(r)
	case route == "PUT settings":
		err = s.apiSettings(r)
	case route == "POST password":
		if !s.apiPassword(w, r, st) {
			return
		}
	case route == "POST rotate":
		err = s.Store.Update(func(st *State) error {
			st.SubToken = RandomToken(16)
			return nil
		})
		if err == nil {
			s.Logf("ссылка подписки заменена: старая больше не работает")
		}
	case route == "POST cert":
		if s.Certs == nil {
			err = badRequest("сертификат не используется: служба запущена без HTTPS")
		} else {
			s.Certs.RenewNow()
			s.Logf("запрошен сертификат Let's Encrypt")
		}
	default:
		apiErr(w, http.StatusNotFound, "нет такого действия")
		return
	}
	if err != nil {
		var br badRequest
		if errors.As(err, &br) {
			apiErr(w, http.StatusBadRequest, br.Error())
		} else {
			apiErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, s.view())
}

func (s *Service) apiLogin(w http.ResponseWriter, r *http.Request, st *State) {
	ip := clientIP(r)
	if wait := s.limiter.wait(ip); wait > 0 {
		apiErr(w, http.StatusTooManyRequests, "слишком много неверных попыток, подождите "+humanWait(wait))
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.checkPassword(r, st, req.Password) {
		s.limiter.fail(ip)
		s.Badf("неверный пароль при входе с %s", ip)
		apiErr(w, http.StatusUnauthorized, "неверный пароль")
		return
	}
	s.limiter.ok(ip)
	s.setSession(w, st)
	s.Logf("вход в панель с %s", ip)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// checkPassword runs the slow hash at most twice at a time.
func (s *Service) checkPassword(r *http.Request, st *State, pw string) bool {
	select {
	case s.pwSem <- struct{}{}:
	case <-r.Context().Done():
		return false
	}
	defer func() { <-s.pwSem }()
	return st.PasswordHash != "" && pw != "" && CheckPassword(st.PasswordHash, pw)
}

func humanWait(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d с", int(math.Ceil(d.Seconds())))
	}
	if d < 2*time.Hour {
		return fmt.Sprintf("%d мин", int(math.Ceil(d.Minutes())))
	}
	return fmt.Sprintf("%d ч", int(math.Ceil(d.Hours())))
}

func (s *Service) apiQR(w http.ResponseWriter, st *State) {
	q, err := EncodeQR(SubURL(s.BaseURL(st), st))
	if err != nil {
		apiErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	io.WriteString(w, q.SVG())
}

type sourceReq struct {
	Name      *string `json:"name"`
	URL       *string `json:"url"`
	Enabled   *bool   `json:"enabled"`
	UserAgent *string `json:"user_agent"`
	Prefix    *string `json:"prefix"`
	HWID      *string `json:"hwid"`
	Move      int     `json:"move"` // -1 up, +1 down
}

func checkSourceURL(raw string, st *State) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", badRequest("нужна ссылка на подписку, начинающаяся с https://")
	}
	if strings.Contains(u.Path, "/s/"+st.SubToken) {
		return "", badRequest("это ссылка самой Связки — добавлять её как источник не нужно")
	}
	return raw, nil
}

func cleanField(p *string, limit int) string {
	if p == nil {
		return ""
	}
	v := strings.TrimSpace(*p)
	if r := []rune(v); len(r) > limit {
		v = string(r[:limit])
	}
	return v
}

func (s *Service) apiAddSource(r *http.Request, cur *State) error {
	var req sourceReq
	if err := readJSON(r, &req); err != nil {
		return badRequest(err.Error())
	}
	if req.URL == nil {
		return badRequest("вставьте ссылку на подписку")
	}
	link, err := checkSourceURL(*req.URL, cur)
	if err != nil {
		return err
	}
	id := RandomToken(4)
	err = s.Store.Update(func(st *State) error {
		if len(st.Upstreams) >= 30 {
			return badRequest("источников уже 30 — это предел")
		}
		for _, up := range st.Upstreams {
			if up.URL == link {
				return badRequest("такой источник уже есть: «" + up.Name + "»")
			}
		}
		name := cleanField(req.Name, 60)
		if name == "" {
			u, _ := url.Parse(link)
			name = u.Hostname()
		}
		st.Upstreams = append(st.Upstreams, Upstream{ID: id, Name: name, URL: link, Enabled: true,
			UserAgent: cleanField(req.UserAgent, 200), Prefix: cleanPrefix(req.Prefix), HWID: cleanField(req.HWID, 100), Added: time.Now()})
		return nil
	})
	if err != nil {
		return err
	}
	s.Logf("добавлен источник «%s»", cleanFieldOr(req.Name, link))
	s.Fetch(id)
	return nil
}

// cleanPrefix keeps a trailing space: "🅰 " separates the prefix from the name.
func cleanPrefix(p *string) string {
	if p == nil {
		return ""
	}
	v := strings.TrimLeft(strings.Map(func(r rune) rune {
		if r < ' ' {
			return -1
		}
		return r
	}, *p), " ")
	if r := []rune(v); len(r) > 30 {
		v = string(r[:30])
	}
	return v
}

func cleanFieldOr(p *string, link string) string {
	if v := cleanField(p, 60); v != "" {
		return v
	}
	u, _ := url.Parse(link)
	return u.Hostname()
}

func (s *Service) apiChangeSource(r *http.Request, id string) error {
	if r.Method == http.MethodDelete {
		var name string
		err := s.Store.Update(func(st *State) error {
			i := slices.IndexFunc(st.Upstreams, func(u Upstream) bool { return u.ID == id })
			if i < 0 {
				return badRequest("источник не найден")
			}
			name = st.Upstreams[i].Name
			st.Upstreams = slices.Delete(st.Upstreams, i, i+1)
			return nil
		})
		if err != nil {
			return err
		}
		s.dropCache(id)
		s.recompose()
		s.Logf("удалён источник «%s»", name)
		return nil
	}
	var req sourceReq
	if err := readJSON(r, &req); err != nil {
		return badRequest(err.Error())
	}
	var refetch, dropped bool
	err := s.Store.Update(func(st *State) error {
		i := slices.IndexFunc(st.Upstreams, func(u Upstream) bool { return u.ID == id })
		if i < 0 {
			return badRequest("источник не найден")
		}
		up := &st.Upstreams[i]
		if req.Name != nil {
			if v := cleanField(req.Name, 60); v != "" {
				up.Name = v
			}
		}
		if req.URL != nil {
			link, err := checkSourceURL(*req.URL, st)
			if err != nil {
				return err
			}
			if link != up.URL {
				up.URL, refetch, dropped = link, true, true
			}
		}
		if req.UserAgent != nil {
			if v := cleanField(req.UserAgent, 200); v != up.UserAgent {
				up.UserAgent, refetch = v, true
			}
		}
		if req.HWID != nil {
			if v := cleanField(req.HWID, 100); v != up.HWID {
				up.HWID, refetch = v, true
			}
		}
		if req.Prefix != nil {
			up.Prefix = cleanPrefix(req.Prefix)
		}
		if req.Enabled != nil {
			if *req.Enabled && !up.Enabled {
				refetch = true
			}
			up.Enabled = *req.Enabled
		}
		if j := i + req.Move; req.Move != 0 && j >= 0 && j < len(st.Upstreams) {
			st.Upstreams[i], st.Upstreams[j] = st.Upstreams[j], st.Upstreams[i]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if dropped {
		s.dropCache(id)
	}
	s.recompose()
	if refetch {
		s.Fetch(id)
	}
	return nil
}

func (s *Service) apiRefresh(r *http.Request) error {
	var req struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &req); err != nil {
		return badRequest(err.Error())
	}
	for _, up := range s.Store.Get().Upstreams {
		if up.Enabled && (req.ID == "" || req.ID == up.ID) {
			s.Fetch(up.ID)
		}
	}
	return nil
}

func (s *Service) apiRules(r *http.Request) error {
	var req struct {
		Rename *string `json:"rename"`
		Hide   *string `json:"hide"`
	}
	if err := readJSON(r, &req); err != nil {
		return badRequest(err.Error())
	}
	var rules []Rename
	if req.Rename != nil {
		var err error
		if rules, err = ParseRenameText(*req.Rename); err != nil {
			return badRequest(err.Error())
		}
		if len(rules) > 500 {
			return badRequest("правил больше 500 — столько не нужно")
		}
	}
	err := s.Store.Update(func(st *State) error {
		if req.Rename != nil {
			st.Rename = rules
		}
		if req.Hide != nil {
			st.Hide = ParseWords(*req.Hide)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.recompose()
	return nil
}

var keyRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

func (s *Service) apiHidden(r *http.Request) error {
	var req struct {
		Key    string   `json:"key"`
		Keys   []string `json:"keys"`
		Hidden bool     `json:"hidden"`
	}
	if err := readJSON(r, &req); err != nil {
		return badRequest(err.Error())
	}
	keys := req.Keys
	if req.Key != "" {
		keys = append(keys, req.Key)
	}
	for _, k := range keys {
		if !keyRE.MatchString(k) {
			return badRequest("неверный сервер")
		}
	}
	err := s.Store.Update(func(st *State) error {
		for _, k := range keys {
			i := slices.Index(st.Hidden, k)
			switch {
			case req.Hidden && i < 0:
				st.Hidden = append(st.Hidden, k)
			case !req.Hidden && i >= 0:
				st.Hidden = slices.Delete(st.Hidden, i, i+1)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.recompose()
	return nil
}

func (s *Service) apiSettings(r *http.Request) error {
	var req struct {
		Title       *string `json:"title"`
		UpdateHours *int    `json:"update_hours"`
		RefreshMin  *int    `json:"refresh_min"`
	}
	if err := readJSON(r, &req); err != nil {
		return badRequest(err.Error())
	}
	return s.Store.Update(func(st *State) error {
		if req.Title != nil {
			t := strings.TrimSpace(*req.Title)
			if t == "" || utf8.RuneCountInString(t) > 60 {
				return badRequest("название: от 1 до 60 символов")
			}
			st.Title = t
		}
		if req.UpdateHours != nil {
			if *req.UpdateHours < 1 || *req.UpdateHours > 168 {
				return badRequest("обновление в приложениях: от 1 до 168 часов")
			}
			st.UpdateHours = *req.UpdateHours
		}
		if req.RefreshMin != nil {
			if *req.RefreshMin < 10 || *req.RefreshMin > 1440 {
				return badRequest("проверка источников: от 10 до 1440 минут")
			}
			st.RefreshMin = *req.RefreshMin
		}
		return nil
	})
}

func (s *Service) apiPassword(w http.ResponseWriter, r *http.Request, st *State) bool {
	ip := clientIP(r)
	if wait := s.limiter.wait(ip); wait > 0 {
		apiErr(w, http.StatusTooManyRequests, "слишком много неверных попыток, подождите "+humanWait(wait))
		return false
	}
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := readJSON(r, &req); err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return false
	}
	if !s.checkPassword(r, st, req.Old) {
		s.limiter.fail(ip)
		apiErr(w, http.StatusBadRequest, "текущий пароль введён неверно")
		return false
	}
	if n := utf8.RuneCountInString(req.New); n < 8 || n > 128 {
		apiErr(w, http.StatusBadRequest, "новый пароль: не короче 8 символов")
		return false
	}
	err := s.Store.Update(func(st *State) error {
		st.PasswordHash = HashPassword(req.New)
		st.SessionKey = RandomToken(32) // other devices have to log in again
		return nil
	})
	if err != nil {
		apiErr(w, http.StatusInternalServerError, err.Error())
		return false
	}
	s.setSession(w, s.Store.Get())
	s.Logf("пароль изменён, остальные входы завершены")
	return true
}

// view is what the web interface gets.
type view struct {
	Now         time.Time   `json:"now"`
	Version     string      `json:"version"`
	Title       string      `json:"title"`
	SubURL      string      `json:"sub_url"`
	IP          string      `json:"ip"`
	Port        int         `json:"port"`
	Cert        *CertStatus `json:"cert"`
	Sources     []srcView   `json:"sources"`
	Servers     []Server    `json:"servers"`
	Served      int         `json:"served"`
	Userinfo    *Userinfo   `json:"userinfo"`
	RenameText  string      `json:"rename_text"`
	HideText    string      `json:"hide_text"`
	RefreshMin  int         `json:"refresh_min"`
	UpdateHours int         `json:"update_hours"`
	Hits        []Hit       `json:"hits"`
	Events      []Event     `json:"events"`
	ComposeErr  string      `json:"compose_err"`
}

type srcView struct {
	Upstream
	Host      string     `json:"host"`
	Count     int        `json:"count"`
	Served    int        `json:"served"`
	FetchedAt *time.Time `json:"fetched_at"`
	Err       string     `json:"err"`
	ErrAt     *time.Time `json:"err_at"`
	Fetching  bool       `json:"fetching"`
	Userinfo  *Userinfo  `json:"userinfo"`
}

func (s *Service) view() view {
	st := s.Store.Get()
	fetching := s.fetchingIDs()
	v := view{Now: time.Now(), Version: s.Version, Title: st.Title, SubURL: SubURL(s.BaseURL(st), st), IP: st.PublicIP, Port: st.Port,
		RefreshMin: st.RefreshMin, UpdateHours: st.UpdateHours, Sources: []srcView{}, Servers: []Server{}, Hits: []Hit{}, Events: []Event{}}
	if s.Certs != nil {
		cs := s.Certs.Status()
		v.Cert = &cs
	}
	var lines []string
	for _, r := range st.Rename {
		lines = append(lines, strings.TrimSpace(QuoteRuleSide(r.From)+" → "+QuoteRuleSide(r.To)))
	}
	v.RenameText = strings.Join(lines, "\n")
	v.HideText = strings.Join(st.Hide, ", ")

	s.mu.Lock()
	snap := s.snap
	v.ComposeErr = s.snapErr
	for _, up := range st.Upstreams {
		sv := srcView{Upstream: up, Fetching: fetching[up.ID]}
		if u, err := url.Parse(up.URL); err == nil {
			sv.Host = u.Hostname()
		}
		if f := s.cache[up.ID]; f != nil {
			sv.Count = len(f.Links)
			if !f.At.IsZero() {
				at := f.At
				sv.FetchedAt = &at
			}
			if f.Err != "" {
				sv.Err = f.Err
				at := f.ErrAt
				sv.ErrAt = &at
			}
			if u, ok := ParseUserinfo(f.Userinfo); ok {
				sv.Userinfo = &u
			}
		}
		v.Sources = append(v.Sources, sv)
	}
	v.Hits = append(v.Hits, s.hits...)
	for i := len(s.events) - 1; i >= 0 && len(v.Events) < 100; i-- {
		v.Events = append(v.Events, s.events[i])
	}
	s.mu.Unlock()

	if snap != nil {
		v.Servers = append(v.Servers, snap.Servers...)
		v.Served = len(snap.Links)
		if u, ok := ParseUserinfo(snap.Userinfo); ok {
			v.Userinfo = &u
		}
		for i := range v.Sources {
			for _, srv := range snap.Servers {
				if srv.Source == v.Sources[i].ID && srv.Hidden == "" {
					v.Sources[i].Served++
				}
			}
		}
	}
	return v
}
