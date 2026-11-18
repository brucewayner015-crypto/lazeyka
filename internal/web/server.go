// Package web serves the local UI and its JSON API on 127.0.0.1.
package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"lazeyka/internal/app"
	"lazeyka/internal/importer"
	"lazeyka/internal/logx"
	"lazeyka/internal/settings"
	"lazeyka/internal/zapret"
)

//go:embed assets
var assets embed.FS

const cookieName = "lz_session"

// Server is the UI server.
type Server struct {
	a     *app.App
	token string
	host  string
	ln    net.Listener
	srv   *http.Server
}

// New listens on a random loopback port.
func New(a *app.App) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{a: a, token: settings.RandomHex(24), ln: ln, host: ln.Addr().String()}
	mux := http.NewServeMux()
	s.routes(mux)
	s.srv = &http.Server{
		Handler:           s.guard(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// URL opens the UI and authenticates the browser.
func (s *Server) URL() string { return "http://" + s.host + "/?t=" + s.token }

// Serve blocks.
func (s *Server) Serve() error {
	err := s.srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the server.
func (s *Server) Close() { s.srv.Close() }

// guard checks Host (anti DNS-rebinding), the session cookie and, for state
// changes, a custom header that cross-site pages cannot send.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.host {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/api/instance/show" || r.URL.Path == "/api/instance/quit" {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" && r.URL.Query().Get("t") != "" {
			if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("t")), []byte(s.token)) == 1 {
				http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			http.Error(w, "неверная ссылка — откройте Лазейку из значка в трее", http.StatusForbidden)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.token)) != 1 {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>Лазейка</title><p style="font:16px Segoe UI,sans-serif;margin:3em">Откройте Лазейку из значка в трее: эта страница доступна только по ссылке из приложения.</p>`)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Lz") != "1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": logx.Redact(err.Error())})
}

func readJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(v); err != nil {
		return fmt.Errorf("неверный запрос: %w", err)
	}
	return nil
}

func ok(w http.ResponseWriter, err error) {
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) routes(mux *http.ServeMux) {
	sub, _ := fs.Sub(assets, "assets")
	files := http.FileServer(http.FS(sub))
	mux.Handle("GET /", files)

	a := s.a
	mux.HandleFunc("POST /api/instance/show", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Lz-Instance")), []byte(app.InstanceToken())) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		go a.OpenUI()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/instance/quit", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Lz-Instance")), []byte(app.InstanceToken())) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); a.Quit() }()
	})

	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Status())
	})
	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, publicSettings(a.Settings()))
	})
	mux.HandleFunc("POST /api/vpn/connect", func(w http.ResponseWriter, r *http.Request) {
		go a.Connect()
		ok(w, nil)
	})
	mux.HandleFunc("POST /api/vpn/disconnect", func(w http.ResponseWriter, r *http.Request) {
		go a.Disconnect()
		ok(w, nil)
	})

	// servers & subscriptions
	mux.HandleFunc("POST /api/import", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text     string `json:"text"`
			Filename string `json:"filename"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, a.Import(req.Text, req.Filename))
	})
	mux.HandleFunc("POST /api/servers/add", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Items []importer.Item `json:"items"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		n, err := a.AddItems(req.Items)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]int{"added": n})
	})
	mux.HandleFunc("POST /api/servers/patch", func(w http.ResponseWriter, r *http.Request) {
		var p app.ServerPatch
		if err := readJSON(r, &p); err != nil {
			writeErr(w, err)
			return
		}
		ok(w, a.PatchServer(p))
	})
	mux.HandleFunc("POST /api/subs/patch", func(w http.ResponseWriter, r *http.Request) {
		var p app.SubPatch
		if err := readJSON(r, &p); err != nil {
			writeErr(w, err)
			return
		}
		ok(w, a.PatchSubscription(p))
	})
	mux.HandleFunc("POST /api/subs/refresh", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		ok(w, a.RefreshSubscription(req.ID))
	})
	mux.HandleFunc("GET /api/nodes", func(w http.ResponseWriter, r *http.Request) {
		v, err := a.Nodes()
		if err != nil {
			writeJSON(w, map[string]any{"off": true, "error": logx.Redact(err.Error())})
			return
		}
		writeJSON(w, v)
	})
	mux.HandleFunc("POST /api/nodes/test", func(w http.ResponseWriter, r *http.Request) {
		ok(w, a.TestDelays())
	})

	// routing
	mux.HandleFunc("GET /api/groups", func(w http.ResponseWriter, r *http.Request) {
		g, err := a.Groups()
		if err != nil {
			writeJSON(w, map[string]any{"off": true, "error": logx.Redact(err.Error()), "groups": []any{}})
			return
		}
		writeJSON(w, map[string]any{"groups": g})
	})
	mux.HandleFunc("POST /api/groups/select", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Group string `json:"group"`
			Name  string `json:"name"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		ok(w, a.Select(req.Group, req.Name))
	})
	mux.HandleFunc("POST /api/routing", func(w http.ResponseWriter, r *http.Request) {
		var rt settings.Routing
		if err := readJSON(r, &rt); err != nil {
			writeErr(w, err)
			return
		}
		ok(w, a.SetRouting(rt))
	})
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, r *http.Request) {
		info, err := a.RulesInfo()
		if err != nil {
			writeJSON(w, map[string]any{"off": true})
			return
		}
		writeJSON(w, info)
	})
	mux.HandleFunc("POST /api/rules/refresh", func(w http.ResponseWriter, r *http.Request) {
		ok(w, a.RefreshRules())
	})

	// zapret
	mux.HandleFunc("GET /api/zapret", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.ZapretInfo())
	})
	mux.HandleFunc("POST /api/zapret/enable", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			On bool `json:"on"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		go a.SetZapretEnabled(req.On)
		ok(w, nil)
	})
	mux.HandleFunc("POST /api/zapret/options", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Strategy   *string `json:"strategy"`
			GameFilter *string `json:"game_filter"`
			IPSet      *string `json:"ipset"`
			Bind       *bool   `json:"bind_physical"`
			PauseVPN   *string `json:"pause_with_vpn"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		ok(w, a.SetZapretOptions(req.Strategy, req.GameFilter, req.IPSet, req.Bind, req.PauseVPN))
	})
	mux.HandleFunc("POST /api/zapret/autoselect", func(w http.ResponseWriter, r *http.Request) {
		ok(w, a.AutoSelectZapret())
	})
	mux.HandleFunc("POST /api/zapret/check", func(w http.ResponseWriter, r *http.Request) {
		ok(w, a.CheckZapret())
	})
	mux.HandleFunc("POST /api/zapret/fix", func(w http.ResponseWriter, r *http.Request) {
		ok(w, a.FixZapretConflicts())
	})
	mux.HandleFunc("POST /api/zapret/ipset-update", func(w http.ResponseWriter, r *http.Request) {
		ok(w, a.UpdateIPSet())
	})
	mux.HandleFunc("POST /api/zapret/install", func(w http.ResponseWriter, r *http.Request) {
		go func() {
			if err := a.InstallZapret(); err != nil {
				logx.Errorf("%v", err)
			}
		}()
		ok(w, nil)
	})
	mux.HandleFunc("GET /api/zapret/list", func(w http.ResponseWriter, r *http.Request) {
		txt, err := zapret.ReadUserList(zapret.Paths{Dir: a.P.Zapret}, r.URL.Query().Get("name"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"text": txt})
	})
	mux.HandleFunc("POST /api/zapret/list", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
			Text string `json:"text"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		err := zapret.WriteUserList(zapret.Paths{Dir: a.P.Zapret}, req.Name, req.Text)
		if err == nil && a.Status().Zapret == "on" {
			go a.StartZapret()
		}
		ok(w, err)
	})

	// app settings, engines, logs
	mux.HandleFunc("POST /api/app", func(w http.ResponseWriter, r *http.Request) {
		var p app.AppPatch
		if err := readJSON(r, &p); err != nil {
			writeErr(w, err)
			return
		}
		ok(w, a.SetApp(p))
	})
	mux.HandleFunc("POST /api/ui", func(w http.ResponseWriter, r *http.Request) {
		var p app.UIPatch
		if err := readJSON(r, &p); err != nil {
			writeErr(w, err)
			return
		}
		ok(w, a.SetUI(p))
	})
	mux.HandleFunc("GET /api/defender", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Defender())
	})
	mux.HandleFunc("GET /api/selfupdate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.SelfUpdate())
	})
	mux.HandleFunc("POST /api/selfupdate/check", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.CheckSelfUpdate())
	})
	mux.HandleFunc("POST /api/selfupdate/install", func(w http.ResponseWriter, r *http.Request) {
		ok(w, a.InstallSelfUpdate())
	})
	mux.HandleFunc("GET /api/exit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Exit())
	})
	mux.HandleFunc("GET /api/zapret/strategies", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.RankedStrategies())
	})
	mux.HandleFunc("GET /api/engines", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.Engines())
	})
	mux.HandleFunc("POST /api/engines/check", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, a.CheckEngineUpdates(false))
	})
	mux.HandleFunc("POST /api/engines/update", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		go func() {
			var err error
			switch req.Name {
			case "mihomo":
				err = a.InstallMihomo()
			case "zapret":
				err = a.InstallZapret()
			}
			if err != nil {
				logx.Errorf("%v", err)
			}
		}()
		ok(w, nil)
	})
	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		writeJSON(w, logx.Default().Since(since, 800))
	})
	mux.HandleFunc("GET /api/diag", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="lazeyka-diag.txt"`)
		io.WriteString(w, s.diagnostics())
	})
	mux.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		ok(w, nil)
		go func() { time.Sleep(300 * time.Millisecond); a.Quit() }()
	})
	mux.HandleFunc("POST /api/uninstall", func(w http.ResponseWriter, r *http.Request) {
		ok(w, nil)
		go func() { time.Sleep(300 * time.Millisecond); a.Uninstall() }()
	})
}

// publicSettings hides the controller secret from the browser.
// publicSettings strips everything the UI never needs: API secret, HWID salt,
// server keys and the token part of subscription URLs. The UI only shows
// names, hosts and switches; it never sends the settings object back whole.
func publicSettings(s *settings.Settings) *settings.Settings {
	s.Secret, s.HWIDSalt = "", ""
	for i := range s.Servers {
		s.Servers[i].Link = ""
		s.Servers[i].Proxy = nil
	}
	for i := range s.Subscriptions {
		s.Subscriptions[i].URL = redactURL(s.Subscriptions[i].URL)
	}
	return s
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "…"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

func (s *Server) diagnostics() string {
	a := s.a
	st := a.Status()
	set := a.Settings()
	var b strings.Builder
	fmt.Fprintf(&b, "Лазейка %s, %s/%s, создано %s\n\n", st.Version, runtime.GOOS, runtime.GOARCH, time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "VPN: %s %s%s\nzapret: %s %s (стратегия %s, game filter %s, ipset %s, привязка %v)\n",
		st.VPN, st.VPNError, st.VPNWarn, st.Zapret, st.ZapretError, set.Zapret.Strategy, set.Zapret.GameFilter, set.Zapret.IPSet, set.Zapret.BindPhysical)
	if d := a.NetDiag(); d != "" {
		fmt.Fprintf(&b, "%s\n", d)
	}
	e := a.Engines()
	fmt.Fprintf(&b, "mihomo %s (последний %s), zapret %s (последний %s)\n", e.Mihomo, e.MihomoLatest, e.Zapret, e.ZapretLatest)
	fmt.Fprintf(&b, "Свои серверы: %d, подписки: %d\n", len(set.Servers), len(set.Subscriptions))
	for i, srv := range set.Servers {
		fmt.Fprintf(&b, "  %d. %s — %s, включён: %v\n", i+1, srv.Name, srv.Info, srv.Enabled)
	}
	r := set.Routing
	fmt.Fprintf(&b, "Маршруты: YouTube=%s Discord=%s мессенджеры=%s ИИ=%s остальное=%s HODCA=%v QUIC=%v UDP=%v\n",
		r.YouTube, r.Discord, r.Messengers, r.AI, r.Other, r.HODCA, r.BlockQUIC, r.UDPDirect)
	if c := a.Conflicts(); len(c) > 0 {
		fmt.Fprintf(&b, "Конфликты: %s\n", strings.Join(c, ", "))
	}
	b.WriteString("\nЖурнал (последние 400 строк; адреса серверов и ключи не записываются):\n")
	for _, e := range logx.Default().Tail("", 400) {
		fmt.Fprintf(&b, "%s [%s] %s %s\n", e.Time.Format("15:04:05"), e.Src, e.Level, e.Msg)
	}
	return b.String()
}
