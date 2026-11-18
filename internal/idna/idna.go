// Package idna converts internationalised domain names (сайт.рф) to their
// ASCII form (xn--80aswg.xn--p1ai). mihomo rules and zapret host lists match
// the name as it appears in DNS and TLS SNI, which is always ASCII.
//
// This is RFC 3492 punycode plus simple lower-casing; full UTS #46 mapping is
// not needed for names people type by hand.
package idna

import (
	"errors"
	"math"
	"strings"
)

const (
	base        int32 = 36
	tMin        int32 = 1
	tMax        int32 = 26
	skew        int32 = 38
	damp        int32 = 700
	initialBias int32 = 72
	initialN    int32 = 128
)

var errOverflow = errors.New("idna: слишком длинное имя")

// ErrInvalid means the input is not a usable domain name.
var ErrInvalid = errors.New("idna: недопустимое доменное имя")

// ToASCII converts a domain to its ASCII (punycode) form and validates it.
// Leading "*." / "+." / "." and a trailing "." are not handled here.
func ToASCII(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	// ideographic and fullwidth dots are label separators too
	domain = strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(domain)
	if domain == "" || len(domain) > 1024 {
		return "", ErrInvalid
	}
	labels := strings.Split(domain, ".")
	for i, l := range labels {
		if l == "" {
			return "", ErrInvalid
		}
		if isASCII(l) {
			if !validLabel(l) {
				return "", ErrInvalid
			}
			continue
		}
		p, err := punycode(l)
		if err != nil {
			return "", err
		}
		l = "xn--" + p
		if !validLabel(l) {
			return "", ErrInvalid
		}
		labels[i] = l
	}
	out := strings.Join(labels, ".")
	if len(out) > 253 {
		return "", ErrInvalid
	}
	return out, nil
}

// HostOf extracts the host from what people paste: a URL, host:port, a bare
// host or a wildcard ("*.site.ru", "+.site.ru", ".site.ru"). It lower-cases,
// strips brackets and a trailing dot, and does not convert to ASCII.
func HostOf(entry string) string {
	h := strings.TrimSpace(entry)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 { // user:pass@host
		h = h[i+1:]
	}
	switch {
	case strings.HasPrefix(h, "["): // [v6]:port
		if i := strings.Index(h, "]"); i > 0 {
			h = h[1:i]
		}
	case strings.Count(h, ":") == 1: // host:port (a bare v6 has more colons)
		h = h[:strings.Index(h, ":")]
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	for _, p := range []string{"*.", "+.", "."} {
		h = strings.TrimPrefix(h, p)
	}
	return h
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if len(l) == 0 || len(l) > 63 {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func adapt(delta, numPoints int32, first bool) int32 {
	if first {
		delta /= damp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := int32(0)
	for delta > ((base-tMin)*tMax)/2 {
		delta /= base - tMin
		k += base
	}
	return k + (base-tMin+1)*delta/(delta+skew)
}

func digit(d int32) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// punycode encodes one label (RFC 3492, section 6.3).
func punycode(s string) (string, error) {
	runes := []rune(s)
	out := make([]byte, 0, len(s)+8)
	for _, r := range runes {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	b := int32(len(out))
	h := b
	if b > 0 {
		out = append(out, '-')
	}
	n, delta, bias := initialN, int32(0), initialBias
	for h < int32(len(runes)) {
		m := int32(math.MaxInt32)
		for _, r := range runes {
			if r >= n && r < m {
				m = r
			}
		}
		if m-n > (math.MaxInt32-delta)/(h+1) {
			return "", errOverflow
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			if r < n {
				delta++
				if delta == math.MaxInt32 {
					return "", errOverflow
				}
			}
			if r != n {
				continue
			}
			q := delta
			for k := base; ; k += base {
				t := k - bias
				if t < tMin {
					t = tMin
				} else if t > tMax {
					t = tMax
				}
				if q < t {
					break
				}
				out = append(out, digit(t+(q-t)%(base-t)))
				q = (q - t) / (base - t)
			}
			out = append(out, digit(q))
			bias = adapt(delta, h+1, h == b)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return string(out), nil
}
