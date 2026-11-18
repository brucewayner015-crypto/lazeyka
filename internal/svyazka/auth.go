package svyazka

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookie = "sv"
	sessionLife   = 30 * 24 * time.Hour
)

// newSession signs "expiry + random" with the state's session key; changing
// the password changes the key and so ends every session.
func newSession(key string, exp time.Time) string {
	payload := make([]byte, 16)
	binary.BigEndian.PutUint64(payload, uint64(exp.Unix()))
	if _, err := rand.Read(payload[8:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + sign(key, payload)
}

func sign(key string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:18])
}

func validSession(key, value string) bool {
	p, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil || len(payload) != 16 {
		return false
	}
	if !hmac.Equal([]byte(sign(key, payload)), []byte(sig)) {
		return false
	}
	return time.Now().Unix() < int64(binary.BigEndian.Uint64(payload))
}

func (s *Service) setSession(w http.ResponseWriter, st *State) {
	exp := time.Now().Add(sessionLife)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    newSession(st.SessionKey, exp),
		Path:     "/" + st.AdminPath + "/",
		Expires:  exp,
		MaxAge:   int(sessionLife / time.Second),
		HttpOnly: true,
		Secure:   s.Certs != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Service) clearSession(w http.ResponseWriter, st *State) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/" + st.AdminPath + "/", MaxAge: -1,
		HttpOnly: true, Secure: s.Certs != nil, SameSite: http.SameSiteStrictMode})
}

func (s *Service) authed(r *http.Request, st *State) bool {
	c, err := r.Cookie(sessionCookie)
	return err == nil && validSession(st.SessionKey, c.Value)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter slows down password guessing: five misses from one address lock
// it for a minute, doubling up to an hour; thirty misses in ten minutes from
// anywhere lock everyone for a while.
type limiter struct {
	mu     sync.Mutex
	ips    map[string]*tries
	global []time.Time
}

type tries struct {
	n     int
	until time.Time
	last  time.Time
}

const (
	limitPerIP   = 5
	limitGlobal  = 30
	globalWindow = 10 * time.Minute
)

func (l *limiter) wait(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.pruneGlobal(now)
	if len(l.global) >= limitGlobal {
		return l.global[0].Add(globalWindow).Sub(now)
	}
	if t := l.ips[ip]; t != nil && now.Before(t.until) {
		return t.until.Sub(now)
	}
	return 0
}

func (l *limiter) pruneGlobal(now time.Time) {
	i := 0
	for i < len(l.global) && now.Sub(l.global[i]) >= globalWindow {
		i++
	}
	l.global = l.global[i:]
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.ips == nil {
		l.ips = map[string]*tries{}
	}
	if len(l.ips) > 4096 {
		for k, t := range l.ips {
			if now.Sub(t.last) > 24*time.Hour {
				delete(l.ips, k)
			}
		}
	}
	t := l.ips[ip]
	if t == nil {
		t = &tries{}
		l.ips[ip] = t
	}
	t.n++
	t.last = now
	if t.n >= limitPerIP {
		t.until = now.Add(min(time.Minute<<min(t.n-limitPerIP, 6), time.Hour))
	}
	l.global = append(l.global, now)
}

func (l *limiter) ok(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.ips, ip)
}
