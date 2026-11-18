package svyazka

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Service is the running Связка: it downloads the sources, keeps the last
// good copy of each, composes the subscription and serves it together with
// the web interface.
type Service struct {
	Store   *Store
	DataDir string
	Certs   *CertManager // nil: plain HTTP for development
	DevURL  string       // base of the links in development, e.g. http://127.0.0.1:8080
	Version string
	Client  *http.Client
	Logger  *log.Logger

	ctx      context.Context
	mu       sync.Mutex
	cache    map[string]*Fetched
	fetching map[string]bool
	snap     *Snapshot
	snapErr  string
	events   []Event
	hits     []Hit
	limiter  limiter
	pwSem    chan struct{}
}

// Event is a line of the journal in the web interface.
type Event struct {
	At   time.Time `json:"at"`
	Text string    `json:"text"`
	Bad  bool      `json:"bad"`
}

// Hit is an app that recently downloaded the subscription.
type Hit struct {
	At    time.Time `json:"at"`
	IP    string    `json:"ip"`
	UA    string    `json:"ua"`
	Count int       `json:"count"`
}

// NewService prepares the service; call Run to start the source refresher.
func NewService(store *Store, dataDir string) *Service {
	return &Service{
		Store:    store,
		DataDir:  dataDir,
		Client:   &http.Client{Timeout: 40 * time.Second},
		Logger:   log.New(os.Stderr, "", 0),
		ctx:      context.Background(),
		cache:    map[string]*Fetched{},
		fetching: map[string]bool{},
		pwSem:    make(chan struct{}, 2),
	}
}

func (s *Service) event(bad bool, format string, a ...any) {
	text := fmt.Sprintf(format, a...)
	if s.Logger != nil {
		s.Logger.Print(text)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, Event{At: time.Now(), Text: text, Bad: bad})
	if len(s.events) > 200 {
		s.events = append([]Event{}, s.events[len(s.events)-200:]...)
	}
}

// Logf adds a journal line.
func (s *Service) Logf(format string, a ...any) { s.event(false, format, a...) }

// Badf adds a journal line about a problem.
func (s *Service) Badf(format string, a ...any) { s.event(true, format, a...) }

func (s *Service) cacheDir() string { return filepath.Join(s.DataDir, "cache") }

func (s *Service) cachePath(id string) string {
	return filepath.Join(s.cacheDir(), id+".json")
}

// LoadCache reads the sources' last downloads from disk.
func (s *Service) LoadCache() {
	st := s.Store.Get()
	s.mu.Lock()
	for _, up := range st.Upstreams {
		b, err := os.ReadFile(s.cachePath(up.ID))
		if err != nil {
			continue
		}
		var f Fetched
		if json.Unmarshal(b, &f) == nil {
			s.cache[up.ID] = &f
		}
	}
	s.mu.Unlock()
	s.recompose()
}

func (s *Service) saveCache(id string, f *Fetched) {
	if err := os.MkdirAll(s.cacheDir(), 0o700); err != nil {
		return
	}
	b, _ := json.Marshal(f)
	if err := WriteFileLikeDir(s.cachePath(id), b); err != nil {
		s.Badf("не удалось сохранить копию источника: %v", err)
	}
}

func (s *Service) dropCache(id string) {
	s.mu.Lock()
	delete(s.cache, id)
	s.mu.Unlock()
	os.Remove(s.cachePath(id))
}

// recompose rebuilds the served subscription from the cache and the rules.
func (s *Service) recompose() {
	st := s.Store.Get()
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := Compose(st, s.cache)
	if err != nil {
		s.snapErr = err.Error()
		return
	}
	s.snap, s.snapErr = snap, ""
}

// Run refreshes the sources until ctx ends.
func (s *Service) Run(ctx context.Context) {
	s.ctx = ctx
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		s.refreshDue()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// refreshDue starts downloads of sources whose copy is old. After a failure
// the next try comes sooner (in 10 minutes at most).
func (s *Service) refreshDue() {
	st := s.Store.Get()
	every := time.Duration(st.RefreshMin) * time.Minute
	retry := min(every, 10*time.Minute)
	for _, up := range st.Upstreams {
		if !up.Enabled {
			continue
		}
		s.mu.Lock()
		f := s.cache[up.ID]
		s.mu.Unlock()
		due := f == nil
		if f != nil {
			if f.ErrAt.After(f.At) {
				due = time.Since(f.ErrAt) >= retry
			} else {
				due = time.Since(f.At) >= every
			}
		}
		if due {
			s.Fetch(up.ID)
		}
	}
}

// Fetch downloads one source in the background (once at a time).
func (s *Service) Fetch(id string) {
	s.mu.Lock()
	if s.fetching[id] {
		s.mu.Unlock()
		return
	}
	s.fetching[id] = true
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.fetching, id)
			s.mu.Unlock()
		}()
		s.fetchNow(id)
	}()
}

func findUpstream(st *State, id string) (Upstream, bool) {
	for _, up := range st.Upstreams {
		if up.ID == id {
			return up, true
		}
	}
	return Upstream{}, false
}

func sameRequest(a, b Upstream) bool {
	return a.URL == b.URL && a.UserAgent == b.UserAgent && a.HWID == b.HWID
}

func (s *Service) fetchNow(id string) {
	up, ok := findUpstream(s.Store.Get(), id)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 45*time.Second)
	got, err := FetchUpstream(ctx, s.Client, up)
	cancel()
	// the source may have been removed or changed meanwhile
	now, ok := findUpstream(s.Store.Get(), id)
	if !ok || !sameRequest(up, now) {
		return
	}
	s.mu.Lock()
	old := s.cache[id]
	var next Fetched
	if err != nil {
		if old != nil {
			next = *old
		}
		next.Err, next.ErrAt = err.Error(), time.Now()
	} else {
		next = *got
	}
	s.cache[id] = &next
	s.mu.Unlock()
	s.saveCache(id, &next)
	s.recompose()
	name := up.Name
	switch {
	case err != nil && (old == nil || old.Err != next.Err):
		if old != nil && len(old.Links) > 0 {
			s.Badf("«%s»: %v — пока отдаю прошлую копию", name, err)
		} else {
			s.Badf("«%s»: %v", name, err)
		}
	case err == nil && (old == nil || old.Err != "" || len(old.Links) != len(next.Links)):
		s.Logf("«%s»: загружено серверов: %d", name, len(next.Links))
	}
}

// fetchingAny reports whether a download is running (the interface polls
// faster meanwhile).
func (s *Service) fetchingIDs() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.fetching))
	for k := range s.fetching {
		out[k] = true
	}
	return out
}

func (s *Service) recordHit(ip, ua string) {
	if r := []rune(ua); len(r) > 120 {
		ua = string(r[:120])
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	next := []Hit{{At: now, IP: ip, UA: ua, Count: 1}}
	for _, h := range s.hits {
		if h.IP == ip && h.UA == ua {
			next[0].Count = h.Count + 1
			continue
		}
		next = append(next, h)
	}
	if len(next) > 20 {
		next = next[:20]
	}
	s.hits = next
}

// BaseURL is the address the service is reached at.
func (s *Service) BaseURL(st *State) string {
	if s.DevURL != "" {
		return strings.TrimSuffix(s.DevURL, "/")
	}
	return BaseURL(st)
}

// BaseURL builds https://IP[:port] from the state.
func BaseURL(st *State) string {
	host := st.PublicIP
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if st.Port != 0 && st.Port != 443 {
		host = fmt.Sprintf("%s:%d", host, st.Port)
	}
	return "https://" + host
}

// SubURL is the subscription link.
func SubURL(base string, st *State) string { return base + "/s/" + st.SubToken }

// AdminURL is the web interface address.
func AdminURL(base string, st *State) string { return base + "/" + st.AdminPath + "/" }
