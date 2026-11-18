package svyazka

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertManager keeps a Let's Encrypt certificate for the server's IP: loads
// it from disk, renews it when a third of its life is left (every ~4 days
// for the 160-hour IP certificates), and meanwhile serves a self-signed one,
// so the web interface still opens (with a browser warning) before the real
// certificate arrives.
type CertManager struct {
	Dir      string // keys and certificates live here (0700)
	IP       net.IP
	DirURL   string // ACME directory
	Email    string
	HTTPAddr string // where the http-01 answers are served during issuance (":80")
	Logf     func(format string, a ...any)
	Errf     func(format string, a ...any) // failures; Logf when nil

	mu      sync.RWMutex
	cert    *tls.Certificate
	leaf    *x509.Certificate
	self    bool
	lastErr string
	wake    chan struct{}
}

// CertStatus is what the web interface shows.
type CertStatus struct {
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	Error      string    `json:"error"`
}

func (m *CertManager) logf(format string, a ...any) {
	if m.Logf != nil {
		m.Logf(format, a...)
	}
}

func (m *CertManager) errf(format string, a ...any) {
	if m.Errf != nil {
		m.Errf(format, a...)
		return
	}
	m.logf(format, a...)
}

// Load picks up a saved certificate, or makes a temporary self-signed one.
func (m *CertManager) Load() {
	m.wake = make(chan struct{}, 1)
	certPEM, err1 := os.ReadFile(filepath.Join(m.Dir, "cert.pem"))
	keyPEM, err2 := os.ReadFile(filepath.Join(m.Dir, "key.pem"))
	if err1 == nil && err2 == nil {
		if c, err := tls.X509KeyPair(certPEM, keyPEM); err == nil && m.usable(c) {
			m.set(&c, false)
			return
		}
	}
	c, err := selfSigned(m.IP)
	if err != nil {
		m.errf("временный сертификат не создан: %v", err)
		return
	}
	m.set(c, true)
}

func (m *CertManager) usable(c tls.Certificate) bool {
	if len(c.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || time.Now().After(leaf.NotAfter) {
		return false
	}
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(m.IP) {
			return true
		}
	}
	return false
}

func (m *CertManager) set(c *tls.Certificate, self bool) {
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	m.mu.Lock()
	m.cert, m.leaf, m.self = c, leaf, self
	m.mu.Unlock()
}

// GetCertificate is for tls.Config.
func (m *CertManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cert == nil {
		return nil, errors.New("сертификата пока нет")
	}
	return m.cert, nil
}

// Status reports the current certificate.
func (m *CertManager) Status() CertStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := CertStatus{SelfSigned: m.self, Error: m.lastErr}
	if m.leaf != nil {
		st.NotAfter = m.leaf.NotAfter
	}
	return st
}

// RenewNow asks the loop to try again right away.
func (m *CertManager) RenewNow() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *CertManager) needsRenewal() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.self || m.leaf == nil {
		return true
	}
	life := m.leaf.NotAfter.Sub(m.leaf.NotBefore)
	return time.Until(m.leaf.NotAfter) < life/3
}

// Run renews in a loop until ctx ends. Failures back off from 10 minutes to
// 3 hours (Let's Encrypt allows only a few failed validations per hour).
func (m *CertManager) Run(ctx context.Context) {
	backoff := 10 * time.Minute
	var last time.Time
	for {
		wait := time.Hour
		if m.needsRenewal() {
			// a pressed button must not burn Let's Encrypt's failure limit
			if d := 2*time.Minute - time.Since(last); d > 0 {
				if sleepCtx(ctx, d) != nil {
					return
				}
			}
			last = time.Now()
			err := m.renew(ctx)
			m.mu.Lock()
			if err != nil {
				m.lastErr = err.Error()
			} else {
				m.lastErr = ""
			}
			m.mu.Unlock()
			if err != nil {
				m.errf("сертификат Let's Encrypt не получен: %v (следующая попытка через %s)", err, humanWait(backoff))
				wait = backoff
				backoff = min(backoff*2, 3*time.Hour)
			} else {
				backoff = 10 * time.Minute
				st := m.Status()
				m.logf("сертификат Let's Encrypt для %s получен, действует до %s", m.IP, st.NotAfter.Local().Format("02.01 15:04"))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-time.After(wait):
		}
	}
}

func (m *CertManager) renew(ctx context.Context) error {
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(m.Dir, "account.key")
	acct, err := readKey(keyPath)
	if err != nil {
		acct = newECKey()
		if err := writeAtomic(keyPath, encodeKey(acct)); err != nil {
			return err
		}
	}
	ln, err := net.Listen("tcp", m.HTTPAddr)
	if err != nil {
		return fmt.Errorf("порт 80 нужен Let's Encrypt для проверки, но занят: %v", err)
	}
	ch := &Challenges{}
	srv := &http.Server{Handler: ch, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	client := &ACMEClient{DirURL: m.DirURL, Key: acct, Email: m.Email, HTTP: &http.Client{Timeout: 30 * time.Second}}
	certKey := newECKey()
	chain, err := client.Obtain(ctx, m.IP, ch, certKey)
	if err != nil {
		return err
	}
	keyPEM := encodeKey(certKey)
	c, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return fmt.Errorf("полученный сертификат не подошёл: %w", err)
	}
	if !m.usable(c) {
		return errors.New("полученный сертификат выписан не на этот адрес")
	}
	if err := writeAtomic(filepath.Join(m.Dir, "key.pem"), keyPEM); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(m.Dir, "cert.pem"), chain); err != nil {
		return err
	}
	m.set(&c, false)
	return nil
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeKey(b)
}

func writeAtomic(path string, data []byte) error {
	return WriteFileLikeDir(path, data)
}

func selfSigned(ip net.IP) (*tls.Certificate, error) {
	key := newECKey()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Svyazka (temporary)"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), encodeKey(key))
	if err != nil {
		return nil, err
	}
	return &c, nil
}
