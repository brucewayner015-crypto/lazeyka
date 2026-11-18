// Package svyazka is «Связка»: a small self-hosted service that merges
// several VPN subscriptions into one link, renames and hides servers, and
// serves the result over HTTPS with a Let's Encrypt certificate for the
// server's IP address.
package svyazka

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Upstream is one source subscription.
type Upstream struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Enabled   bool      `json:"enabled"`
	UserAgent string    `json:"user_agent"` // empty = DefaultUA
	Prefix    string    `json:"prefix"`     // put before every server name of this source
	HWID      string    `json:"hwid"`       // sent as x-hwid; empty = do not send
	Added     time.Time `json:"added"`
}

// Rename replaces From with To in server names. From written as /…/ is a
// regular expression and To may use $1; otherwise both are plain text and
// case is ignored.
type Rename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// State is everything Связка keeps on disk (one JSON file, mode 0600).
type State struct {
	Version int `json:"version"`

	// access
	PasswordHash string `json:"password_hash"` // pbkdf2-sha256$iter$salt$hash
	AdminPath    string `json:"admin_path"`    // secret path of the web interface
	SubToken     string `json:"sub_token"`     // secret part of the subscription link
	SessionKey   string `json:"session_key"`

	// where it runs
	PublicIP string `json:"public_ip"`
	Port     int    `json:"port"`

	Upstreams    []Upstream `json:"upstreams"`
	Rename       []Rename   `json:"rename"`
	Hide         []string   `json:"hide"`           // words: servers whose name contains one are hidden
	Hidden       []string   `json:"hidden"`         // server keys hidden by hand
	RefreshMin   int        `json:"refresh_min"`    // how often sources are re-downloaded
	UpdateHours  int        `json:"update_hours"`   // told to client apps (profile-update-interval)
	Title        string     `json:"title"`          // profile title shown by phone apps
	ACMEEmail    string     `json:"acme_email"`     // optional
	ACMEStaging  bool       `json:"acme_staging"`   // for tests
	CertNotAfter time.Time  `json:"cert_not_after"` // informational
}

// DefaultUA makes most panels (Remnawave, Marzban, 3x-ui) answer with plain
// share links in base64, which is what Связка understands and re-serves.
const DefaultUA = "v2rayNG/1.10.5"

// DefaultHide: informational pseudo-servers that panels add to subscriptions.
var DefaultHide = []string{"осталось", "истекает", "истёк", "expire", "traffic", "трафик", "сайт", "website",
	"канал", "support", "поддержк", "продл", "обнов"}

// Store guards the state file. The command line («svyazka passwd») may
// change the file while the service runs, so it is re-read when it changes.
type Store struct {
	path string
	mu   sync.Mutex
	st   *State
	mod  time.Time
	size int64
}

// OpenStore loads (or creates) the state at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.st = &State{}
	case err != nil:
		return nil, err
	default:
		var st State
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, fmt.Errorf("%s повреждён: %w", path, err)
		}
		s.st = &st
		s.remember()
	}
	s.st.normalize()
	return s, nil
}

// Path is where the state lives.
func (s *Store) Path() string { return s.path }

func (s *Store) remember() {
	if fi, err := os.Stat(s.path); err == nil {
		s.mod, s.size = fi.ModTime(), fi.Size()
	}
}

func (s *Store) reloadIfChanged() {
	fi, err := os.Stat(s.path)
	if err != nil || (fi.ModTime().Equal(s.mod) && fi.Size() == s.size) {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var st State
	if json.Unmarshal(b, &st) != nil {
		return // half-written by someone else: keep what we have
	}
	st.normalize()
	s.st = &st
	s.mod, s.size = fi.ModTime(), fi.Size()
}

func (st *State) normalize() {
	if st.Version == 0 {
		st.Version = 1
	}
	if st.AdminPath == "" {
		st.AdminPath = "a-" + RandomToken(6)
	}
	if st.SubToken == "" {
		st.SubToken = RandomToken(16)
	}
	if st.SessionKey == "" {
		st.SessionKey = RandomToken(32)
	}
	if st.RefreshMin <= 0 {
		st.RefreshMin = 60
	}
	if st.UpdateHours <= 0 {
		st.UpdateHours = 6
	}
	if st.Title == "" {
		st.Title = "Связка"
	}
	if st.Hide == nil {
		st.Hide = append([]string{}, DefaultHide...)
	}
	if st.Rename == nil {
		st.Rename = []Rename{}
	}
	if st.Hidden == nil {
		st.Hidden = []string{}
	}
	if st.Upstreams == nil {
		st.Upstreams = []Upstream{}
	}
}

// Get returns a deep copy of the state.
func (s *Store) Get() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadIfChanged()
	return s.st.clone()
}

// Update changes the state and saves it atomically.
func (s *Store) Update(fn func(st *State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadIfChanged()
	next := s.st.clone()
	if err := fn(next); err != nil {
		return err
	}
	next.normalize()
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	if err := WriteFileLikeDir(s.path, b); err != nil {
		return err
	}
	s.st = next
	s.remember()
	return nil
}

// WriteFileLikeDir writes atomically (mode 0600). When root writes into the
// service's folder (the command line run with sudo), the file gets the
// folder's owner, so the service can still read it.
func WriteFileLikeDir(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	chownLikeDir(tmp, filepath.Dir(path))
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (st *State) clone() *State {
	b, _ := json.Marshal(st)
	var c State
	_ = json.Unmarshal(b, &c)
	return &c
}

// RandomToken returns n random bytes as URL-safe text.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// RandomPassword is easy to type: 4 groups of 4 letters/digits.
func RandomPassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, 0, 19)
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(c)%len(alphabet)])
	}
	return string(out)
}

const pbkdfIter = 300_000

// HashPassword returns a PBKDF2-SHA256 hash string.
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, hex.EncodeToString(salt), hex.EncodeToString(key))
}

// CheckPassword compares pw with a hash from HashPassword.
func CheckPassword(hash, pw string) bool {
	var iter int
	var saltHex, keyHex string
	if _, err := fmt.Sscanf(replaceDollar(hash), "pbkdf2-sha256 %d %s %s", &iter, &saltHex, &keyHex); err != nil || iter < 1000 {
		return false
	}
	salt, err1 := hex.DecodeString(saltHex)
	want, err2 := hex.DecodeString(keyHex)
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func replaceDollar(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == '$' {
			b[i] = ' '
		}
	}
	return string(b)
}
