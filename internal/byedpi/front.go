package byedpi

// Front is a SOCKS5 server in front of ByeDPI. mihomo hands proxies the site
// name, and ByeDPI would look it up with the phone's DNS — which in Russia
// (since 2026, НСДИ) answers "no such domain" for YouTube, Discord and the
// like, so ByeDPI could never connect. The front resolves the name with DNS
// it can trust and asks ByeDPI to connect to the IP address. Only TCP
// CONNECT: Discord voice goes through the VPN, YouTube's QUIC is rejected.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Resolver returns IPv4 addresses for a host name.
type Resolver interface {
	LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error)
}

// Front accepts SOCKS5 CONNECT on Addr and forwards through ByeDPI.
type Front struct {
	// Upstream is ByeDPI's SOCKS5 address ("127.0.0.1:port").
	Upstream string
	Resolver Resolver
	// OnError sees connection failures (for the log; keep it quick).
	OnError func(host string, err error)

	ln   net.Listener
	mu   sync.Mutex
	done chan struct{}
}

// Listen starts the front on 127.0.0.1:port (0: any free port).
func (f *Front) Listen(port int) (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	f.ln, f.done = ln, make(chan struct{})
	f.mu.Unlock()
	go f.serve(ln)
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// Close stops accepting.
func (f *Front) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ln != nil {
		f.ln.Close()
		f.ln = nil
	}
}

func (f *Front) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

const (
	socksVer      = 5
	cmdConnect    = 1
	atypIPv4      = 1
	atypDomain    = 3
	atypIPv6      = 4
	repOK         = 0
	repFail       = 1
	repHostUnr    = 4
	repConnRef    = 5
	repCmdUnsupp  = 7
	repAtypUnsupp = 8
)

func reply(c net.Conn, code byte) {
	c.Write([]byte{socksVer, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
}

func (f *Front) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	host, port, err := readRequest(c)
	if err != nil {
		var se socksErr
		if errors.As(err, &se) {
			reply(c, byte(se))
		}
		return
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		ips, rerr := f.Resolver.LookupIPv4(ctx, host)
		cancel()
		if rerr != nil || len(ips) == 0 {
			if rerr == nil {
				rerr = errors.New("нет IPv4-адреса")
			}
			f.report(host, fmt.Errorf("DNS: %w", rerr))
			reply(c, repHostUnr)
			return
		}
		ip = ips[0]
	}
	up, err := dialThrough(f.Upstream, ip, port)
	if err != nil {
		f.report(host, err)
		reply(c, repConnRef)
		return
	}
	defer up.Close()
	reply(c, repOK)
	_ = c.SetDeadline(time.Time{})
	pipe(c, up)
}

func (f *Front) report(host string, err error) {
	if f.OnError != nil {
		f.OnError(host, err)
	}
}

type socksErr byte

func (e socksErr) Error() string { return "socks5 error " + strconv.Itoa(int(e)) }

// readRequest reads the greeting and the CONNECT request (no auth).
func readRequest(c net.Conn) (host string, port uint16, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != socksVer {
		return "", 0, errors.New("not socks5")
	}
	methods := make([]byte, hdr[1])
	if _, err = io.ReadFull(c, methods); err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == 0 {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{socksVer, 0xff})
		return "", 0, errors.New("no acceptable auth method")
	}
	if _, err = c.Write([]byte{socksVer, 0}); err != nil {
		return
	}
	var req [4]byte
	if _, err = io.ReadFull(c, req[:]); err != nil {
		return
	}
	if req[0] != socksVer {
		return "", 0, errors.New("bad request")
	}
	if req[1] != cmdConnect {
		return "", 0, socksErr(repCmdUnsupp)
	}
	switch req[3] {
	case atypIPv4:
		var a [4]byte
		if _, err = io.ReadFull(c, a[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(a).String()
	case atypIPv6:
		var a [16]byte
		if _, err = io.ReadFull(c, a[:]); err != nil {
			return
		}
		host = netip.AddrFrom16(a).String()
	case atypDomain:
		var l [1]byte
		if _, err = io.ReadFull(c, l[:]); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err = io.ReadFull(c, name); err != nil {
			return
		}
		host = string(name)
	default:
		return "", 0, socksErr(repAtypUnsupp)
	}
	var p [2]byte
	if _, err = io.ReadFull(c, p[:]); err != nil {
		return
	}
	return host, binary.BigEndian.Uint16(p[:]), nil
}

// dialThrough opens a SOCKS5 CONNECT to ip:port via the upstream proxy.
func dialThrough(upstream string, ip netip.Addr, port uint16) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", upstream, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ByeDPI не отвечает: %w", err)
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	fail := func(err error) (net.Conn, error) { c.Close(); return nil, err }
	if _, err := c.Write([]byte{socksVer, 1, 0}); err != nil {
		return fail(err)
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		return fail(fmt.Errorf("ByeDPI: %w", err))
	}
	if m[1] != 0 {
		return fail(errors.New("ByeDPI отказал в подключении"))
	}
	req := []byte{socksVer, cmdConnect, 0}
	if ip.Is4() {
		a := ip.As4()
		req = append(append(req, atypIPv4), a[:]...)
	} else {
		a := ip.As16()
		req = append(append(req, atypIPv6), a[:]...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	var rep [4]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return fail(fmt.Errorf("ByeDPI: %w", err))
	}
	if rep[1] != repOK {
		return fail(fmt.Errorf("ByeDPI не смог подключиться к %s (код %d)", netip.AddrPortFrom(ip, port), rep[1]))
	}
	// skip the bound address
	var skip int
	switch rep[3] {
	case atypIPv4:
		skip = 4 + 2
	case atypIPv6:
		skip = 16 + 2
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return fail(err)
		}
		skip = int(l[0]) + 2
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}
