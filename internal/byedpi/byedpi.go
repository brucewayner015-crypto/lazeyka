// Package byedpi describes ByeDPI (github.com/hufrea/byedpi), the Android
// stand-in for zapret: zapret rewrites packets with root rights, ByeDPI is a
// local SOCKS5 proxy that splits and disguises the first packets of each
// connection itself, which needs no root. mihomo sends YouTube and Discord
// to it; everything else is untouched.
package byedpi

import (
	"fmt"
	"strconv"
	"strings"

	"lazeyka/internal/zapret"
)

// Strategy is a named set of ByeDPI options.
type Strategy struct {
	Key  string
	Name string
	Args string
}

// UDP: a fake packet before Discord voice and QUIC, then the TCP group. "-An"
// makes the next group apply to everything the UDP group skipped.
const udpPrefix = "-Ku -a1 -An -Kt,h "

// Strategies, the most universal first. Positions: "1+s" is one byte into
// the SNI (the site name the DPI reads), "-1" the end of the packet.
var Strategies = []Strategy{
	{"bd-1", "Перестановка у имени сайта + TLS-записи", udpPrefix + "-d1 -s1+s -r1+s"},
	{"bd-2", "Фейк с TTL 5 + перестановка", udpPrefix + "-f-1 -t5 -d1+s -r1+s"},
	{"bd-3", "Разбиение посреди имени сайта", udpPrefix + "-s1 -d0+sm -r1+s"},
	{"bd-4", "OOB-байт + TLS-записи", udpPrefix + "-o1 -r1+s"},
	{"bd-5", "Перестановка OOB + без SACK", udpPrefix + "-q1 -r1+s -Y"},
	{"bd-6", "Фейк с чужим именем (ya.ru), TTL 6", udpPrefix + "-f-1 -t6 -n ya.ru --fake-tls-mod=rand -s1+s -r1+s"},
	{"bd-7", "Авто: при обрыве — фейк, затем OOB", udpPrefix + "-d1 -s1+s -r1+s -At,r,s -f-1 -t5 -r1+s -As -o1+s -r1+s"},
	{"bd-8", "Много разрывов (для упрямого DPI)", udpPrefix + "-s1 -q1 -Y -At,r,s -s5 -o1+s -f-1 -r1+s -As -s1 -o1+s -s-1"},
	{"bd-9", "Фейк с TTL 8, глубокое разбиение", udpPrefix + "-d1+s -s50+s -f-1 -t8 -r1+s"},
	{"bd-10", "TLS-записи + подмена версии", udpPrefix + "-r1+s -m1 -d1"},
	{"bd-11", "Только TLS-записи (самый мягкий)", udpPrefix + "-r1+s"},
}

// Default strategy key.
const Default = "bd-1"

// Find returns the strategy with key.
func Find(key string) (Strategy, bool) {
	for _, s := range Strategies {
		if s.Key == key {
			return s, true
		}
	}
	return Strategy{}, false
}

// IsKey reports whether key names a ByeDPI strategy ("bd-…" or "custom:…").
func IsKey(key string) bool {
	_, ok := Find(key)
	return ok || strings.HasPrefix(key, CustomPrefix)
}

// CustomPrefix marks a strategy the user typed: "custom:-d1 -r1+s".
const CustomPrefix = "custom:"

// List for the UI, in the same shape as zapret's .bat strategies.
func List() []zapret.Strategy {
	out := make([]zapret.Strategy, 0, len(Strategies))
	for _, s := range Strategies {
		out = append(out, zapret.Strategy{File: s.Key, Name: s.Name})
	}
	return out
}

// Args builds the command line: listen on 127.0.0.1:port, then the strategy.
func Args(key string, port int) ([]string, error) {
	var opts string
	if s, ok := Find(key); ok {
		opts = s.Args
	} else if strings.HasPrefix(key, CustomPrefix) {
		opts = strings.TrimSpace(strings.TrimPrefix(key, CustomPrefix))
		if opts == "" {
			return nil, fmt.Errorf("пустая своя стратегия")
		}
	} else {
		return nil, fmt.Errorf("нет стратегии %q", key)
	}
	args := []string{"-i", "127.0.0.1", "-p", strconv.Itoa(port)}
	for _, f := range strings.Fields(opts) {
		switch f {
		case "-i", "--ip", "-p", "--port", "-D", "--daemon", "-w", "--pidfile", "-E", "--transparent":
			return nil, fmt.Errorf("опция %s задаётся Лазейкой", f)
		}
		args = append(args, f)
	}
	return args, nil
}
