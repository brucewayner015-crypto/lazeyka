package svyazka

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// A minimal ACME client (RFC 8555 with the ACME profiles draft) for one job:
// a Let's Encrypt certificate for the server's IP address. Such certificates
// exist only with the "shortlived" profile (160 hours), are validated with
// the http-01 challenge on port 80, and are renewed every few days.

const (
	LEProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LEStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	Meta       struct {
		Profiles map[string]any `json:"profiles"`
	} `json:"meta"`
}

// acmeProblem is an RFC 7807 error from the CA.
type acmeProblem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (p *acmeProblem) Error() string {
	t := strings.TrimPrefix(p.Type, "urn:ietf:params:acme:error:")
	if p.Detail != "" {
		return t + ": " + p.Detail
	}
	return t
}

type acmeOrder struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
	Error          *acmeProblem
}

type acmeAuthz struct {
	Status     string `json:"status"`
	Identifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifier"`
	Challenges []struct {
		Type   string       `json:"type"`
		URL    string       `json:"url"`
		Token  string       `json:"token"`
		Status string       `json:"status"`
		Error  *acmeProblem `json:"error"`
	} `json:"challenges"`
}

// ACMEClient talks to one CA with one account key.
type ACMEClient struct {
	DirURL string
	Key    *ecdsa.PrivateKey
	HTTP   *http.Client
	Email  string

	dir    *acmeDirectory
	kid    string
	nonces []string
	mu     sync.Mutex
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pad32 gives the fixed-width big-endian form JWK and ES256 require.
func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// JWK of the account key, members in the order RFC 7638 needs for the thumbprint.
func jwkJSON(k *ecdsa.PublicKey) string {
	return fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, b64(pad32(k.X)), b64(pad32(k.Y)))
}

// Thumbprint is the RFC 7638 thumbprint of the account key.
func Thumbprint(k *ecdsa.PublicKey) string {
	sum := sha256.Sum256([]byte(jwkJSON(k)))
	return b64(sum[:])
}

func (c *ACMEClient) directory(ctx context.Context) (*acmeDirectory, error) {
	if c.dir != nil {
		return c.dir, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.DirURL, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Let's Encrypt недоступен: %w", err)
	}
	defer resp.Body.Close()
	var d acmeDirectory
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil || d.NewOrder == "" {
		return nil, fmt.Errorf("неожиданный ответ Let's Encrypt (%s)", resp.Status)
	}
	c.dir = &d
	return &d, nil
}

func (c *ACMEClient) nonce(ctx context.Context) (string, error) {
	c.mu.Lock()
	if n := len(c.nonces); n > 0 {
		v := c.nonces[n-1]
		c.nonces = c.nonces[:n-1]
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	d, err := c.directory(ctx)
	if err != nil {
		return "", err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, d.NewNonce, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if v := resp.Header.Get("Replay-Nonce"); v != "" {
		return v, nil
	}
	return "", errors.New("CA не выдал nonce")
}

func (c *ACMEClient) keepNonce(h http.Header) {
	if v := h.Get("Replay-Nonce"); v != "" {
		c.mu.Lock()
		c.nonces = append(c.nonces, v)
		c.mu.Unlock()
	}
}

// post sends a JWS-signed request; payload nil means POST-as-GET.
func (c *ACMEClient) post(ctx context.Context, url string, payload any) (*http.Response, []byte, error) {
	for attempt := 0; ; attempt++ {
		nonce, err := c.nonce(ctx)
		if err != nil {
			return nil, nil, err
		}
		prot := map[string]any{"alg": "ES256", "nonce": nonce, "url": url}
		if c.kid != "" {
			prot["kid"] = c.kid
		} else {
			prot["jwk"] = json.RawMessage(jwkJSON(&c.Key.PublicKey))
		}
		pb, _ := json.Marshal(prot)
		var payloadB64 string
		if payload != nil {
			b, err := json.Marshal(payload)
			if err != nil {
				return nil, nil, err
			}
			payloadB64 = b64(b)
		}
		input := b64(pb) + "." + payloadB64
		digest := sha256.Sum256([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, c.Key, digest[:])
		if err != nil {
			return nil, nil, err
		}
		sig := append(pad32(r), pad32(s)...)
		body, _ := json.Marshal(map[string]string{"protected": b64(pb), "payload": payloadB64, "signature": b64(sig)})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/jose+json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		c.keepNonce(resp.Header)
		if resp.StatusCode < 400 {
			return resp, data, nil
		}
		p := &acmeProblem{Status: resp.StatusCode}
		_ = json.Unmarshal(data, p)
		if p.Type == "urn:ietf:params:acme:error:badNonce" && attempt < 3 {
			continue
		}
		if p.Type == "" {
			p.Detail = resp.Status
		}
		return resp, data, p
	}
}

func (c *ACMEClient) account(ctx context.Context) error {
	if c.kid != "" {
		return nil
	}
	d, err := c.directory(ctx)
	if err != nil {
		return err
	}
	req := map[string]any{"termsOfServiceAgreed": true}
	if c.Email != "" {
		req["contact"] = []string{"mailto:" + c.Email}
	}
	resp, _, err := c.post(ctx, d.NewAccount, req)
	if err != nil {
		return fmt.Errorf("регистрация в Let's Encrypt: %w", err)
	}
	c.kid = resp.Header.Get("Location")
	if c.kid == "" {
		return errors.New("Let's Encrypt не вернул адрес учётной записи")
	}
	return nil
}

// Challenges serves http-01 answers on port 80 while an order is validated.
type Challenges struct {
	mu   sync.Mutex
	keys map[string]string
}

func (h *Challenges) set(token, keyAuth string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.keys == nil {
		h.keys = map[string]string{}
	}
	h.keys[token] = keyAuth
}

func (h *Challenges) del(token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.keys, token)
}

func (h *Challenges) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	h.mu.Lock()
	v, ok := h.keys[strings.TrimPrefix(r.URL.Path, prefix)]
	h.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	io.WriteString(w, v)
}

// Obtain gets a certificate for ip. The caller must route
// http://ip/.well-known/acme-challenge/ to ch during the call.
func (c *ACMEClient) Obtain(ctx context.Context, ip net.IP, ch *Challenges, certKey crypto.Signer) (chainPEM []byte, err error) {
	if err := c.account(ctx); err != nil {
		return nil, err
	}
	d, _ := c.directory(ctx)
	order := map[string]any{"identifiers": []map[string]string{{"type": "ip", "value": ip.String()}}}
	if _, ok := d.Meta.Profiles["shortlived"]; ok || len(d.Meta.Profiles) == 0 {
		order["profile"] = "shortlived"
	}
	resp, data, err := c.post(ctx, d.NewOrder, order)
	if err != nil {
		return nil, fmt.Errorf("заказ сертификата: %w", err)
	}
	orderURL := resp.Header.Get("Location")
	var o acmeOrder
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, err
	}
	for _, az := range o.Authorizations {
		if err := c.authorize(ctx, az, ch); err != nil {
			return nil, err
		}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{IPAddresses: []net.IP{ip}}, certKey)
	if err != nil {
		return nil, err
	}
	if _, data, err = c.post(ctx, o.Finalize, map[string]string{"csr": b64(csr)}); err != nil {
		return nil, fmt.Errorf("выпуск сертификата: %w", err)
	}
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, err
	}
	for i := 0; o.Status != "valid"; i++ {
		if o.Status == "invalid" || i > 40 {
			return nil, fmt.Errorf("Let's Encrypt не выпустил сертификат (%s)", o.Status)
		}
		if err := sleepCtx(ctx, 2*time.Second); err != nil {
			return nil, err
		}
		if _, data, err = c.post(ctx, orderURL, nil); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, err
		}
	}
	_, chain, err := c.post(ctx, o.Certificate, nil)
	if err != nil {
		return nil, fmt.Errorf("скачивание сертификата: %w", err)
	}
	if !bytes.Contains(chain, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, errors.New("Let's Encrypt прислал не сертификат")
	}
	return chain, nil
}

func (c *ACMEClient) authorize(ctx context.Context, url string, ch *Challenges) error {
	_, data, err := c.post(ctx, url, nil)
	if err != nil {
		return err
	}
	var az acmeAuthz
	if err := json.Unmarshal(data, &az); err != nil {
		return err
	}
	if az.Status == "valid" {
		return nil
	}
	var chURL, token string
	for _, x := range az.Challenges {
		if x.Type == "http-01" {
			chURL, token = x.URL, x.Token
		}
	}
	if chURL == "" {
		return errors.New("Let's Encrypt не предложил проверку через порт 80 (http-01)")
	}
	ch.set(token, token+"."+Thumbprint(&c.Key.PublicKey))
	defer ch.del(token)
	if _, _, err := c.post(ctx, chURL, struct{}{}); err != nil {
		return fmt.Errorf("проверка адреса: %w", err)
	}
	for i := 0; i < 60; i++ {
		if err := sleepCtx(ctx, 2*time.Second); err != nil {
			return err
		}
		_, data, err := c.post(ctx, url, nil)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &az); err != nil {
			return err
		}
		switch az.Status {
		case "valid":
			return nil
		case "invalid":
			for _, x := range az.Challenges {
				if x.Type == "http-01" && x.Error != nil {
					return fmt.Errorf("Let's Encrypt не достучался до порта 80 этого сервера: %s", x.Error.Detail)
				}
			}
			return errors.New("Let's Encrypt не подтвердил адрес")
		}
	}
	return errors.New("проверка адреса заняла слишком долго")
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// --- keys on disk ------------------------------------------------------------

func newECKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func encodeKey(k *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func decodeKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("не PEM")
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}
