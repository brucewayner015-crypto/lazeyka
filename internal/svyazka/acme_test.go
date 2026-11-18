package svyazka

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockCA is a tiny ACME server that checks what a real one checks: JWS
// signatures, nonces, URLs, the http-01 answer, and the CSR.
type mockCA struct {
	t         *testing.T
	srv       *httptest.Server
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	mu        sync.Mutex
	nonces    map[string]bool
	acctKey   *ecdsa.PublicKey
	token     string
	authzOK   bool
	issued    []byte
	validator string // host:port where the client answers http-01
	badNonce  bool   // answer badNonce once to the first order request
	profile   string
}

func newMockCA(t *testing.T) *mockCA {
	m := &mockCA{t: t, nonces: map[string]bool{}, token: "tok_" + RandomToken(8), badNonce: true}
	m.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mock CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &m.caKey.PublicKey, m.caKey)
	m.caCert, _ = x509.ParseCertificate(der)
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	return m
}

func (m *mockCA) url(p string) string { return m.srv.URL + p }

func (m *mockCA) newNonce(w http.ResponseWriter) {
	n := RandomToken(12)
	m.mu.Lock()
	m.nonces[n] = true
	m.mu.Unlock()
	w.Header().Set("Replay-Nonce", n)
}

func (m *mockCA) problem(w http.ResponseWriter, typ, detail string, code int) {
	m.newNonce(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": code})
}

// verify checks the JWS and returns the payload (nil for POST-as-GET).
func (m *mockCA) verify(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Header.Get("Content-Type") != "application/jose+json" {
		m.problem(w, "malformed", "content type", 400)
		return nil, false
	}
	var jws struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		m.problem(w, "malformed", "json", 400)
		return nil, false
	}
	pb, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
	var prot struct {
		Alg, Nonce, URL, Kid string
		JWK                  *struct{ Crv, Kty, X, Y string }
	}
	if err := json.Unmarshal(pb, &prot); err != nil || prot.Alg != "ES256" {
		m.problem(w, "malformed", "protected", 400)
		return nil, false
	}
	m.mu.Lock()
	okNonce := m.nonces[prot.Nonce]
	delete(m.nonces, prot.Nonce)
	m.mu.Unlock()
	if !okNonce {
		m.problem(w, "badNonce", "unknown nonce", 400)
		return nil, false
	}
	if prot.URL != m.url(r.URL.Path) {
		m.problem(w, "unauthorized", "url mismatch "+prot.URL, 401)
		return nil, false
	}
	var pub *ecdsa.PublicKey
	if prot.JWK != nil {
		x, _ := base64.RawURLEncoding.DecodeString(prot.JWK.X)
		y, _ := base64.RawURLEncoding.DecodeString(prot.JWK.Y)
		if len(x) != 32 || len(y) != 32 || prot.JWK.Crv != "P-256" || prot.JWK.Kty != "EC" {
			m.problem(w, "badPublicKey", "jwk", 400)
			return nil, false
		}
		pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	} else {
		if prot.Kid != m.url("/acct/1") || m.acctKey == nil {
			m.problem(w, "accountDoesNotExist", "kid", 400)
			return nil, false
		}
		pub = m.acctKey
	}
	sig, _ := base64.RawURLEncoding.DecodeString(jws.Signature)
	digest := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		m.problem(w, "malformed", "bad signature", 400)
		return nil, false
	}
	if prot.JWK != nil {
		m.acctKey = pub
	}
	if jws.Payload == "" {
		return nil, true
	}
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	return payload, true
}

func (m *mockCA) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/dir":
		json.NewEncoder(w).Encode(map[string]any{"newNonce": m.url("/nonce"), "newAccount": m.url("/acct"), "newOrder": m.url("/order"),
			"meta": map[string]any{"profiles": map[string]string{"classic": "", "shortlived": ""}}})
		return
	case r.URL.Path == "/nonce":
		m.newNonce(w)
		return
	}
	payload, ok := m.verify(w, r)
	if !ok {
		return
	}
	m.newNonce(w)
	switch r.URL.Path {
	case "/acct":
		var req struct{ TermsOfServiceAgreed bool }
		json.Unmarshal(payload, &req)
		if !req.TermsOfServiceAgreed {
			m.problem(w, "malformed", "terms", 400)
			return
		}
		w.Header().Set("Location", m.url("/acct/1"))
		w.WriteHeader(201)
		io.WriteString(w, `{"status":"valid"}`)
	case "/order":
		if m.badNonce {
			m.badNonce = false
			m.problem(w, "badNonce", "try again", 400)
			return
		}
		var req struct {
			Identifiers []struct{ Type, Value string }
			Profile     string
		}
		json.Unmarshal(payload, &req)
		if len(req.Identifiers) != 1 || req.Identifiers[0].Type != "ip" || req.Identifiers[0].Value != "127.0.0.1" {
			m.problem(w, "rejectedIdentifier", fmt.Sprint(req.Identifiers), 400)
			return
		}
		m.profile = req.Profile
		w.Header().Set("Location", m.url("/order/1"))
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(m.order())
	case "/order/1":
		json.NewEncoder(w).Encode(m.order())
	case "/authz/1":
		json.NewEncoder(w).Encode(m.authz())
	case "/chall/1":
		// validate like the CA would: fetch the token over plain HTTP
		resp, err := http.Get("http://" + m.validator + "/.well-known/acme-challenge/" + m.token)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			x, y := m.acctKey.X.FillBytes(make([]byte, 32)), m.acctKey.Y.FillBytes(make([]byte, 32))
			canon := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
			sum := sha256.Sum256([]byte(canon))
			m.authzOK = string(body) == m.token+"."+base64.RawURLEncoding.EncodeToString(sum[:])
		}
		json.NewEncoder(w).Encode(map[string]string{"type": "http-01", "status": "processing"})
	case "/finalize/1":
		var req struct{ CSR string }
		json.Unmarshal(payload, &req)
		der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil || len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
			m.problem(w, "badCSR", "csr", 400)
			return
		}
		if !m.authzOK {
			m.problem(w, "orderNotReady", "not authorized", 403)
			return
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(160 * time.Hour),
			IPAddresses: csr.IPAddresses, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		leaf, _ := x509.CreateCertificate(rand.Reader, tpl, m.caCert, csr.PublicKey, m.caKey)
		m.issued = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})...)
		json.NewEncoder(w).Encode(m.order())
	case "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(m.issued)
	default:
		m.problem(w, "malformed", "no route "+r.URL.Path, 404)
	}
}

func (m *mockCA) order() map[string]any {
	o := map[string]any{"status": "pending", "authorizations": []string{m.url("/authz/1")}, "finalize": m.url("/finalize/1")}
	if m.authzOK {
		o["status"] = "ready"
	}
	if m.issued != nil {
		o["status"] = "valid"
		o["certificate"] = m.url("/cert/1")
	}
	return o
}

func (m *mockCA) authz() map[string]any {
	st := "pending"
	if m.authzOK {
		st = "valid"
	}
	return map[string]any{"status": st, "identifier": map[string]string{"type": "ip", "value": "127.0.0.1"},
		"challenges": []map[string]string{{"type": "http-01", "url": m.url("/chall/1"), "token": m.token, "status": st}}}
}

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestCertManagerWithMockCA(t *testing.T) {
	ca := newMockCA(t)
	defer ca.srv.Close()
	ca.validator = freeAddr(t)
	dir := t.TempDir()
	m := &CertManager{Dir: dir, IP: net.ParseIP("127.0.0.1"), DirURL: ca.url("/dir"), HTTPAddr: ca.validator, Logf: t.Logf}
	m.Load()
	if st := m.Status(); !st.SelfSigned {
		t.Fatal("expected a temporary self-signed certificate first")
	}
	if !m.needsRenewal() {
		t.Fatal("self-signed must be renewed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := m.renew(ctx); err != nil {
		t.Fatal(err)
	}
	if ca.profile != "shortlived" {
		t.Fatalf("profile %q", ca.profile)
	}
	st := m.Status()
	if st.SelfSigned || time.Until(st.NotAfter) < 150*time.Hour {
		t.Fatal(st)
	}
	if m.needsRenewal() {
		t.Fatal("fresh certificate should not need renewal")
	}
	// a restart picks the saved certificate up again
	m2 := &CertManager{Dir: dir, IP: net.ParseIP("127.0.0.1")}
	m2.Load()
	if m2.Status().SelfSigned {
		t.Fatal("saved certificate not loaded")
	}
	// and it really serves TLS for the IP, trusted through the mock CA
	pool := x509.NewCertPool()
	pool.AddCert(ca.caCert)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: m2.GetCertificate})
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	// a busy port 80 is reported clearly
	busy, _ := net.Listen("tcp", ca.validator)
	defer busy.Close()
	if err := m.renew(ctx); err == nil || !strings.Contains(err.Error(), "порт 80") {
		t.Fatal(err)
	}
}
