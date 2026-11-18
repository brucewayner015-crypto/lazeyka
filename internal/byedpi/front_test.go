package byedpi

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type mapResolver map[string]string

func (m mapResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, ok := m[host]; ok {
		return []netip.Addr{netip.MustParseAddr(ip)}, nil
	}
	return nil, errors.New("NXDOMAIN")
}

// fakeUpstream is a SOCKS5 server that records what it was asked to connect to.
func fakeUpstream(t *testing.T) (addr string, asked func() []string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				host, port, err := readRequest(c)
				if err != nil {
					return
				}
				mu.Lock()
				got = append(got, net.JoinHostPort(host, strconv.Itoa(int(port))))
				mu.Unlock()
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
				if err != nil {
					reply(c, repConnRef)
					return
				}
				defer up.Close()
				reply(c, repOK)
				pipe(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, got...) }
}

func TestFrontResolvesNames(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello "+r.Host) }))
	defer web.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(web.URL, "http://"))
	up, asked := fakeUpstream(t)
	f := &Front{Upstream: up, Resolver: mapResolver{"youtube.test": "127.0.0.1"}}
	fp, err := f.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(fp))
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 5 * time.Second}
	resp, err := cl.Get("http://youtube.test:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "hello youtube.test:"+port {
		t.Fatalf("body %q", b)
	}
	// ByeDPI was given the address, not the name
	if a := asked(); len(a) != 1 || a[0] != "127.0.0.1:"+port {
		t.Fatalf("upstream asked for %v", a)
	}
	// unknown name: a clean SOCKS error, no upstream connection
	if _, err := cl.Get("http://nowhere.test:" + port + "/"); err == nil {
		t.Fatal("expected an error")
	}
	if len(asked()) != 1 {
		t.Fatal("upstream must not be asked for unresolvable names")
	}
}

func TestFrontUpstreamDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	var reported error
	f := &Front{Upstream: dead, Resolver: mapResolver{"a.test": "127.0.0.1"}, OnError: func(h string, err error) { reported = err }}
	fp, _ := f.Listen(0)
	defer f.Close()
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(fp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	var m [2]byte
	io.ReadFull(c, m[:])
	req := []byte{5, 1, 0, 3, 6}
	req = append(req, "a.test"...)
	req = binary.BigEndian.AppendUint16(req, 443)
	c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[1] != repConnRef || reported == nil || !strings.Contains(reported.Error(), "ByeDPI не отвечает") {
		t.Fatalf("rep %v, reported %v", rep, reported)
	}
}

// a minimal DNS-over-TCP server: every A question gets 192.0.2.7
func fakeTCPDNS(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					var l [2]byte
					if _, err := io.ReadFull(br, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(br, q); err != nil {
						return
					}
					// header(12) + question; answer = header with flags + question + one A
					qend := 12
					for q[qend] != 0 {
						qend += int(q[qend]) + 1
					}
					qend += 1 + 4
					resp := append([]byte{}, q[:qend]...)
					resp[2], resp[3] = 0x81, 0x80 // response, RD, RA
					binary.BigEndian.PutUint16(resp[6:], 1)
					binary.BigEndian.PutUint16(resp[8:], 0)
					binary.BigEndian.PutUint16(resp[10:], 0)
					resp = append(resp, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7)
					out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
					c.Write(append(out, resp...))
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestTCPResolver(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	r := &TCPResolver{Servers: []string{dead, fakeTCPDNS(t)}}
	ips, err := r.LookupIPv4(context.Background(), "www.youtube.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.7" {
		t.Fatalf("%v %v", ips, err)
	}
	// cached: works even with no servers left
	r.Servers = []string{dead}
	if ips, err := r.LookupIPv4(context.Background(), "WWW.YouTube.com."); err != nil || ips[0].String() != "192.0.2.7" {
		t.Fatalf("cache: %v %v", ips, err)
	}
}

// With the real ByeDPI (BYEDPI_BIN): a fetch through the front works. Only
// strategies without decoys: fakes with a short TTL and OOB bytes do reach a
// server on the same machine (no hops to expire on) and garble the request.
func TestFrontWithByeDPI(t *testing.T) {
	bin := os.Getenv("BYEDPI_BIN")
	if bin == "" {
		t.Skip("BYEDPI_BIN not set")
	}
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer web.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(web.URL, "http://"))
	for i, s := range Strategies {
		if strings.Contains(s.Args, "-f") || strings.Contains(s.Args, "-o") || strings.Contains(s.Args, "-q") {
			continue
		}
		bp := 23000 + i
		args, _ := Args(s.Key, bp)
		cmd := exec.Command(bin, args...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		f := &Front{Upstream: "127.0.0.1:" + strconv.Itoa(bp), Resolver: mapResolver{"site.test": "127.0.0.1"}}
		fp, _ := f.Listen(0)
		proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(fp))
		cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 5 * time.Second}
		resp, err := cl.Get("http://site.test:" + port + "/")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) != "ok" {
				err = fmt.Errorf("body %q", b)
			}
		}
		f.Close()
		cmd.Process.Kill()
		cmd.Wait()
		if err != nil {
			t.Errorf("%s: %v", s.Key, err)
		}
	}
}
