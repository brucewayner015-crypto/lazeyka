package app

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionTargetsLinks(t *testing.T) {
	links := strings.Join([]string{
		"vless://uuid@a.example.com:443?security=reality&sni=www.microsoft.com&type=tcp#Auto%201%20%E2%86%92%20%5B%F0%9F%9A%80%20%D0%9E%D0%BF%D1%82%D0%B8%D0%BC%D0%B0%D0%BB%D1%8C%D0%BD%D0%B0%D1%8F%5D",
		"vless://uuid@b.example.com:8443?security=none&type=ws#Same",
		"trojan://pw@1.2.3.4:443#Same",
		"hysteria2://pw@h.example.com:443?sni=h.example.com#HY",
		"ss://YWVzLTEyOC1nY206cHc=@5.6.7.8:8388#SS",
	}, "\n")
	got := subscriptionTargets([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	want := map[string]probeTarget{
		"Auto 1 → [🚀 Оптимальная]": {Host: "a.example.com", Port: 443, TLS: true, SNI: "www.microsoft.com"},
		"Same":    {Host: "b.example.com", Port: 8443},
		"Same-01": {Host: "1.2.3.4", Port: 443, TLS: true},
		"HY":      {Host: "h.example.com", Port: 443, UDP: true, SNI: "h.example.com"},
		"SS":      {Host: "5.6.7.8", Port: 8388},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets: %+v", len(got), got)
	}
	for n, w := range want {
		if got[n] != w {
			t.Errorf("%s: got %+v, want %+v", n, got[n], w)
		}
	}
}

func TestSubscriptionTargetsYAML(t *testing.T) {
	y := `mixed-port: 7890
proxies:
  - name: "🇳🇱 NL"
    type: vless
    server: nl.example.com
    port: 443
    tls: true
    servername: www.apple.com
    reality-opts:
      public-key: abc
      short-id: "01"
  - {name: 'DE fast', server: 9.9.9.9, port: 8443, type: trojan, sni: de.example, ws-opts: {path: /x, headers: {Host: a}}}
  - name: TUIC
    type: tuic
    server: t.example.com
    port: 443
- name: broken
proxy-groups:
  - name: "🚀 Оптимальная"
    type: url-test
    server: not.a.proxy
    port: 1
`
	got := subscriptionTargets([]byte(y))
	want := map[string]probeTarget{
		"🇳🇱 NL":   {Host: "nl.example.com", Port: 443, TLS: true, SNI: "www.apple.com"},
		"DE fast": {Host: "9.9.9.9", Port: 8443, TLS: true, SNI: "de.example"},
		"TUIC":    {Host: "t.example.com", Port: 443, UDP: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets: %+v", len(got), got)
	}
	for n, w := range want {
		if got[n] != w {
			t.Errorf("%s: got %+v, want %+v", n, got[n], w)
		}
	}
}

func noLookup(ctx context.Context, host string) ([]string, error) {
	if host == "localhost" {
		return []string{"127.0.0.1"}, nil
	}
	return nil, errors.New("no such host")
}

func hostPort(t *testing.T, addr string) (string, int) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func TestProbeServer(t *testing.T) {
	probeTLSTimeout = 1500 * time.Millisecond
	ctx := context.Background()
	d := &net.Dialer{Timeout: 3 * time.Second}

	// TLS answers: the server is there
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	h, p := hostPort(t, srv.Listener.Addr().String())
	if r := probeServer(ctx, probeTarget{Host: "localhost", Port: p, TLS: true, SNI: "www.microsoft.com"}, noLookup, d); r.Code != reachOpen {
		t.Errorf("TLS server: %+v", r)
	}
	_ = h

	// accepted, then cut: DPI-like
	cut, _ := net.Listen("tcp", "127.0.0.1:0")
	defer cut.Close()
	go func() {
		for {
			c, err := cut.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, p = hostPort(t, cut.Addr().String())
	if r := probeServer(ctx, probeTarget{Host: "127.0.0.1", Port: p, TLS: true}, noLookup, d); r.Code != reachDPI {
		t.Errorf("cut: %+v", r)
	}

	// accepted, then silence: DPI-like for TLS, open for plain TCP
	silent, _ := net.Listen("tcp", "127.0.0.1:0")
	defer silent.Close()
	var held []net.Conn
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	_, p = hostPort(t, silent.Addr().String())
	if r := probeServer(ctx, probeTarget{Host: "127.0.0.1", Port: p, TLS: true}, noLookup, d); r.Code != reachDPI || !strings.Contains(r.Note, "ответа нет") {
		t.Errorf("silent TLS: %+v", r)
	}
	if r := probeServer(ctx, probeTarget{Host: "127.0.0.1", Port: p}, noLookup, d); r.Code != reachOpen {
		t.Errorf("silent TCP: %+v", r)
	}

	// nothing listens: refused
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	_, p = hostPort(t, closed.Addr().String())
	closed.Close()
	if r := probeServer(ctx, probeTarget{Host: "127.0.0.1", Port: p, TLS: true}, noLookup, d); r.Code != reachUnreachable || !strings.Contains(r.Note, "отклоняет") {
		t.Errorf("refused: %+v", r)
	}

	// the name does not resolve
	if r := probeServer(ctx, probeTarget{Host: "gone.example", Port: 443, TLS: true}, noLookup, d); r.Code != reachUnreachable || !strings.Contains(r.Note, "DNS") {
		t.Errorf("dns: %+v", r)
	}

	// UDP protocols are not probed
	if r := probeServer(ctx, probeTarget{Host: "1.2.3.4", Port: 443, UDP: true}, noLookup, d); r.Code != reachUDP {
		t.Errorf("udp: %+v", r)
	}
}

func TestReachSummary(t *testing.T) {
	res := map[string]reachInfo{
		"A": {Code: reachUnreachable, Addr: "1.1.1.1:443"},
		"B": {Code: reachUnreachable, Addr: "1.1.1.2:443"},
		"C": {Code: reachOpen, Addr: "1.1.1.3:443"},
		"D": {Code: reachUDP, Addr: "1.1.1.4:443"},
	}
	s := reachSummary(1, []string{"A", "B", "C", "D"}, res)
	for _, want := range []string{"отвечают 1 из 5", "недоступны из этой сети", "— 2 («A» 1.1.1.1:443, «B» 1.1.1.2:443)", "VPN через них не работает — 1", "по UDP"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q: %s", want, s)
		}
	}
}
