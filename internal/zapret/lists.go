package zapret

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"lazeyka/internal/idna"
)

// QuoteList renders up to max items as «a», «b» and "ещё N".
func QuoteList(items []string, max int) string {
	var parts []string
	for i, s := range items {
		if i == max {
			parts = append(parts, fmt.Sprintf("и ещё %d", len(items)-max))
			break
		}
		parts = append(parts, "«"+s+"»")
	}
	return strings.Join(parts, ", ")
}

// placeholder keeps winws happy: list files must never be empty.
const placeholderIP = "203.0.113.113/32"

const (
	markBegin  = "# >>> Лазейка: IP ваших VPN-серверов (обновляется автоматически)"
	hostsBegin = "# >>> Лазейка: сайты, которые нужны самой Лазейке (обновляется автоматически)"
	markEnd    = "# <<< Лазейка"
)

// managedBegin: the files that carry a block Лазейка maintains itself.
var managedBegin = map[string]string{
	"ipset-exclude-user.txt": markBegin,
	"list-general-user.txt":  hostsBegin,
}

// splitManaged separates our block (its lines, without markers) from the
// user's own lines.
func splitManaged(content []byte, begin string) (block, rest []string) {
	in := false
	for _, l := range strings.Split(string(content), "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case l == begin:
			in = true
		case in && l == markEnd:
			in = false
		case in:
			if t := strings.TrimSpace(l); t != "" {
				block = append(block, t)
			}
		default:
			rest = append(rest, l)
		}
	}
	return block, rest
}

// SetManagedHosts writes the hosts Лазейка itself needs (GitHub downloads,
// subscription servers) into list-general-user.txt, so zapret also gets them
// past the provider's DPI. winws re-reads a changed host list by itself.
func SetManagedHosts(p Paths, hosts []string) error {
	if err := EnsureUserLists(p); err != nil {
		return err
	}
	fp := filepath.Join(p.Lists(), "list-general-user.txt")
	old, _ := os.ReadFile(fp)
	_, rest := splitManaged(old, hostsBegin)
	uniq := map[string]bool{}
	var block []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || uniq[h] {
			continue
		}
		uniq[h] = true
		block = append(block, h)
	}
	sort.Strings(block)
	var b strings.Builder
	if len(block) > 0 {
		b.WriteString(hostsBegin + "\n")
		for _, h := range block {
			b.WriteString(h + "\n")
		}
		b.WriteString(markEnd + "\n")
	}
	user := strings.TrimSpace(strings.Join(rest, "\n"))
	if user == "" {
		user = strings.TrimSpace(userLists["list-general-user.txt"])
	}
	b.WriteString(user + "\n")
	if string(old) == b.String() {
		return nil // unchanged: do not make winws reload
	}
	return os.WriteFile(fp, []byte(b.String()), 0o644)
}

// User list files referenced by Flowseal strategies.
var userLists = map[string]string{
	"ipset-exclude-user.txt": placeholderIP + "\n",
	"list-general-user.txt":  "# Never leave this file empty\ndomain.example.abc\n",
	"list-exclude-user.txt":  "domain.example.abc\n",
}

// EnsureUserLists creates the per-user list files with safe defaults.
func EnsureUserLists(p Paths) error {
	if err := os.MkdirAll(p.Lists(), 0o755); err != nil {
		return err
	}
	for name, def := range userLists {
		fp := filepath.Join(p.Lists(), name)
		st, err := os.Stat(fp)
		if errors.Is(err, os.ErrNotExist) || (err == nil && st.Size() == 0) {
			if err := os.WriteFile(fp, []byte(def), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// SetExcludeIPs writes the VPN servers' IPs into ipset-exclude-user.txt so
// zapret never touches the tunnel connections.
func SetExcludeIPs(p Paths, ips []string) error {
	if err := EnsureUserLists(p); err != nil {
		return err
	}
	fp := filepath.Join(p.Lists(), "ipset-exclude-user.txt")
	old, _ := os.ReadFile(fp)
	var keep []string
	in := false
	sc := bufio.NewScanner(bytes.NewReader(old))
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), "\r")
		switch {
		case l == markBegin:
			in = true
		case l == markEnd:
			in = false
		case !in && strings.TrimSpace(l) != "":
			keep = append(keep, l)
		}
	}
	uniq := map[string]bool{}
	var block []string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || uniq[ip] {
			continue
		}
		uniq[ip] = true
		if !strings.Contains(ip, "/") {
			if strings.Contains(ip, ":") {
				ip += "/128"
			} else {
				ip += "/32"
			}
		}
		block = append(block, ip)
	}
	sort.Strings(block)
	var b strings.Builder
	b.WriteString(markBegin + "\n")
	for _, ip := range block {
		b.WriteString(ip + "\n")
	}
	b.WriteString(markEnd + "\n")
	hasPlaceholder := false
	for _, l := range keep {
		if strings.TrimSpace(l) == placeholderIP {
			hasPlaceholder = true
		}
		b.WriteString(l + "\n")
	}
	if !hasPlaceholder {
		b.WriteString(placeholderIP + "\n")
	}
	return os.WriteFile(fp, []byte(b.String()), 0o644)
}

// IPSet modes (same as service.bat).
const (
	IPSetNone   = "none"
	IPSetLoaded = "loaded"
	IPSetAny    = "any"
)

func ipsetPaths(p Paths) (string, string) {
	f := filepath.Join(p.Lists(), "ipset-all.txt")
	return f, f + ".backup"
}

// IPSetMode reports the current mode of lists/ipset-all.txt.
func IPSetMode(p Paths) string {
	f, _ := ipsetPaths(p)
	b, err := os.ReadFile(f)
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		return IPSetAny
	}
	if bytes.Contains(b, []byte(placeholderIP)) {
		return IPSetNone
	}
	return IPSetLoaded
}

// SetIPSetMode switches lists/ipset-all.txt, keeping the full list in .backup.
func SetIPSetMode(p Paths, mode string) error {
	f, bak := ipsetPaths(p)
	cur := IPSetMode(p)
	if cur == mode {
		return nil
	}
	if cur == IPSetLoaded {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if err := os.WriteFile(bak, data, 0o644); err != nil {
			return err
		}
	}
	switch mode {
	case IPSetLoaded:
		data, err := os.ReadFile(bak)
		if err != nil || len(bytes.TrimSpace(data)) == 0 {
			return fmt.Errorf("полный список IP не найден — обновите списки zapret")
		}
		return os.WriteFile(f, data, 0o644)
	case IPSetNone:
		return os.WriteFile(f, []byte(placeholderIP+"\n"), 0o644)
	case IPSetAny:
		return os.WriteFile(f, nil, 0o644)
	}
	return fmt.Errorf("неизвестный режим IPSet %q", mode)
}

// UpdateIPSet replaces the full IP list (from Flowseal's repository).
func UpdateIPSet(p Paths, data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 || bytes.Count(data, []byte("\n")) < 100 {
		return fmt.Errorf("загруженный список IP пустой или повреждён")
	}
	f, bak := ipsetPaths(p)
	if err := os.WriteFile(bak, data, 0o644); err != nil {
		return err
	}
	if IPSetMode(p) == IPSetLoaded {
		return os.WriteFile(f, data, 0o644)
	}
	return nil
}

// ReadUserList returns an editable user list (without our managed block).
func ReadUserList(p Paths, name string) (string, error) {
	if _, ok := userLists[name]; !ok {
		return "", fmt.Errorf("неизвестный список")
	}
	b, err := os.ReadFile(filepath.Join(p.Lists(), name))
	if err != nil {
		return "", err
	}
	if begin, ok := managedBegin[name]; ok {
		_, rest := splitManaged(b, begin)
		return strings.TrimSpace(strings.Join(rest, "\n")), nil
	}
	return strings.TrimSpace(string(b)), nil
}

// NormalizeUserList cleans what the user typed: host lists get bare ASCII
// hosts (URLs and wildcards stripped, сайт.рф → xn--80aswg.xn--p1ai, since
// winws matches SNI/Host bytes), IP lists get valid addresses or subnets.
// Comments and blank lines are kept. Lines that make no sense are returned
// in bad.
func NormalizeUserList(name, content string) (string, []string) {
	ipList := strings.HasPrefix(name, "ipset-")
	var out, bad []string
	for _, l := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.ContainsAny(l[:1], "#;/") {
			out = append(out, l)
			continue
		}
		if ipList {
			if pfx, err := netip.ParsePrefix(l); err == nil {
				out = append(out, pfx.Masked().String())
			} else if a, err := netip.ParseAddr(l); err == nil {
				out = append(out, a.Unmap().String())
			} else {
				bad = append(bad, l)
			}
			continue
		}
		strict := strings.HasPrefix(l, "^")
		host := idna.HostOf(strings.TrimPrefix(l, "^"))
		if _, err := netip.ParseAddr(host); err != nil {
			ascii, err := idna.ToASCII(host)
			if err != nil {
				bad = append(bad, l)
				continue
			}
			host = ascii
		}
		if strict {
			host = "^" + host
		}
		out = append(out, host)
	}
	return strings.TrimSpace(strings.Join(out, "\n")), bad
}

// WriteUserList saves a user list; empty input falls back to a placeholder.
// Lines that are not hosts (or IPs for ipset lists) are refused.
func WriteUserList(p Paths, name, content string) error {
	def, ok := userLists[name]
	if !ok {
		return fmt.Errorf("неизвестный список")
	}
	if err := EnsureUserLists(p); err != nil {
		return err
	}
	content, bad := NormalizeUserList(name, content)
	if len(bad) > 0 {
		what := "домен или адрес сайта"
		if strings.HasPrefix(name, "ipset-") {
			what = "IP-адрес или подсеть"
		}
		return fmt.Errorf("не понял строки: %s. В каждой строке нужен %s", QuoteList(bad, 5), what)
	}
	if content == "" {
		content = strings.TrimSpace(def)
	}
	if name == "ipset-exclude-user.txt" {
		// re-apply our block on the next SetExcludeIPs; keep it now
		old, _ := ReadManagedBlock(p)
		if err := os.WriteFile(filepath.Join(p.Lists(), name), []byte(content+"\n"), 0o644); err != nil {
			return err
		}
		return SetExcludeIPs(p, old)
	}
	if name == "list-general-user.txt" {
		cur, _ := os.ReadFile(filepath.Join(p.Lists(), name))
		hosts, _ := splitManaged(cur, hostsBegin)
		if err := os.WriteFile(filepath.Join(p.Lists(), name), []byte(content+"\n"), 0o644); err != nil {
			return err
		}
		return SetManagedHosts(p, hosts)
	}
	return os.WriteFile(filepath.Join(p.Lists(), name), []byte(content+"\n"), 0o644)
}

// ReadManagedBlock returns the IPs currently in our managed block.
func ReadManagedBlock(p Paths) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(p.Lists(), "ipset-exclude-user.txt"))
	if err != nil {
		return nil, err
	}
	var ips []string
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == markBegin:
			in = true
		case l == markEnd:
			in = false
		case in && l != "":
			ips = append(ips, l)
		}
	}
	return ips, nil
}
