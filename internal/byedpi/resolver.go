package byedpi

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// TrustedDNS: DNS over TCP to resolvers abroad. Since August 2026 the TSPU
// redirects plain (UDP) DNS sent to these addresses to the state resolver
// НСДИ, which answers "no such domain" for blocked sites, and breaks DoH/DoT
// to Google and Cloudflare by SNI; DNS over TCP still reaches the real
// servers. The same list goes into mihomo's config (core.TrustedDNS).
var TrustedDNS = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// TCPResolver looks names up over TCP, trying the servers in turn.
type TCPResolver struct {
	Servers []string

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	ips []netip.Addr
	exp time.Time
}

const cacheTTL = 2 * time.Minute

// LookupIPv4 implements Resolver.
func (r *TCPResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	r.mu.Lock()
	if c, ok := r.cache[host]; ok && time.Now().Before(c.exp) {
		r.mu.Unlock()
		return c.ips, nil
	}
	r.mu.Unlock()
	servers := r.Servers
	if len(servers) == 0 {
		servers = TrustedDNS
	}
	var lastErr error
	for _, s := range servers {
		server := s
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", server) // a stream conn: Go uses TCP framing
			},
		}
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := res.LookupNetIP(qctx, "ip4", host)
		cancel()
		if err == nil && len(ips) > 0 {
			for i := range ips {
				ips[i] = ips[i].Unmap()
			}
			r.mu.Lock()
			if r.cache == nil || len(r.cache) > 4096 {
				r.cache = map[string]cached{}
			}
			r.cache[host] = cached{ips: ips, exp: time.Now().Add(cacheTTL)}
			r.mu.Unlock()
			return ips, nil
		}
		if err == nil {
			err = errors.New("пустой ответ")
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}
