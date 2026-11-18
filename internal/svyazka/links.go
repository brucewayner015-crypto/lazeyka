package svyazka

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"lazeyka/internal/importer"
)

// ParseBody pulls share links out of a subscription response: a base64
// encoded list of links (what v2rayNG, Happ and others get) or the plain list.
func ParseBody(body []byte) ([]string, error) {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return nil, errors.New("источник отдал пустой ответ")
	}
	if !strings.Contains(text, "://") {
		compact := strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, text)
		if raw, err := importer.DecodeB64(compact); err == nil && bytes.Contains(raw, []byte("://")) {
			text = string(raw)
		}
	}
	var links []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if importer.IsShareLink(line) {
			links = append(links, line)
		}
	}
	if len(links) > 0 {
		return links, nil
	}
	low := strings.ToLower(text)
	switch {
	case strings.Contains(low, "proxies:") || strings.Contains(low, "proxy-groups:"):
		return nil, errors.New("источник отдал конфигурацию Clash, а не ссылки: поставьте у него User-Agent " + DefaultUA)
	case strings.HasPrefix(low, "{") || strings.HasPrefix(low, "["):
		return nil, errors.New("источник отдал JSON (sing-box или Xray), а не ссылки: поставьте у него User-Agent " + DefaultUA)
	case strings.Contains(low, "<html"):
		return nil, errors.New("вместо подписки пришла веб-страница: проверьте адрес")
	}
	return nil, errors.New("в ответе не нашлось ссылок на серверы")
}

// ServerKey identifies a server by what it is (protocol, address, keys), not
// by its name, so hiding by hand survives renaming and re-downloading.
func ServerKey(link string) string {
	base := link
	if importer.SchemeOf(link) == "vmess" {
		if raw, err := importer.DecodeB64(strings.SplitN(link[len("vmess://"):], "#", 2)[0]); err == nil {
			var v map[string]any
			if json.Unmarshal(raw, &v) == nil {
				delete(v, "ps")
				b, _ := json.Marshal(v) // map keys come out sorted
				base = "vmess://" + string(b)
			}
		}
	} else if i := strings.Index(base, "#"); i >= 0 {
		base = base[:i]
	}
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:8])
}

// LinkName returns the display name stored in a share link.
func LinkName(link string) string {
	if li, err := importer.InspectLink(link); err == nil {
		return li.Name
	}
	return ""
}

type rule struct {
	re *regexp.Regexp
	to string
}

// CompileRules prepares rename rules; plain text ignores case, /…/ is a
// regular expression whose replacement may use $1 (or ${1}).
func CompileRules(rules []Rename) ([]rule, error) {
	var out []rule
	for i, r := range rules {
		if strings.TrimSpace(r.From) == "" {
			continue
		}
		from, to := r.From, r.To
		var pattern string
		if len(from) >= 3 && strings.HasPrefix(from, "/") && strings.HasSuffix(from, "/") {
			pattern = from[1 : len(from)-1]
		} else {
			pattern = "(?i)" + regexp.QuoteMeta(from)
			to = strings.ReplaceAll(to, "$", "$$")
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("правило %d («%s»): неверное выражение", i+1, r.From)
		}
		out = append(out, rule{re: re, to: to})
	}
	return out, nil
}

func applyRules(name string, rules []rule) string {
	for _, r := range rules {
		name = r.re.ReplaceAllString(name, r.to)
	}
	return strings.Join(strings.Fields(name), " ") // tidy spaces left by deletions
}

// hideMatcher finds the first hide word in a name. Words of up to three Latin
// letters or digits match whole words only ("RU" hides "RU-1", not "Peru").
type hideMatcher struct {
	words []string
	res   []*regexp.Regexp
}

func newHideMatcher(words []string) hideMatcher {
	var m hideMatcher
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		q := regexp.QuoteMeta(w)
		if shortLatin(w) {
			q = `\b` + q + `\b`
		}
		m.words = append(m.words, w)
		m.res = append(m.res, regexp.MustCompile("(?i)"+q))
	}
	return m
}

func (m hideMatcher) match(names ...string) string {
	for i, re := range m.res {
		for _, n := range names {
			if re.MatchString(n) {
				return m.words[i]
			}
		}
	}
	return ""
}

func shortLatin(w string) bool {
	if len(w) > 3 {
		return false
	}
	for _, c := range w {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// ParseRenameText reads rules written one per line as "что → на что"
// ("->" and "=>" work too; an empty right side removes the text).
func ParseRenameText(text string) ([]Rename, error) {
	rules := []Rename{}
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cut, sep := -1, ""
		for _, s := range []string{"→", "=>", "->"} {
			if j := strings.Index(line, s); j >= 0 && (cut < 0 || j < cut) {
				cut, sep = j, s
			}
		}
		if cut < 0 {
			return nil, fmt.Errorf("строка %d («%s»): нужна стрелка, например: Netherlands → Нидерланды", i+1, line)
		}
		from := unquote(strings.TrimSpace(line[:cut]))
		if from == "" {
			return nil, fmt.Errorf("строка %d: слева от стрелки пусто", i+1)
		}
		rules = append(rules, Rename{From: from, To: unquote(strings.TrimSpace(line[cut+len(sep):]))})
	}
	if _, err := CompileRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// unquote: "…" keeps spaces at the edges (" | " → ", ").
func unquote(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s[1 : len(s)-1]
	}
	return s
}

// QuoteRuleSide is the reverse of unquote for showing rules as text.
func QuoteRuleSide(s string) string {
	if s != strings.TrimSpace(s) {
		return `"` + s + `"`
	}
	return s
}

// ParseWords reads words separated by commas or new lines.
func ParseWords(text string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		w = strings.TrimSpace(w)
		if w == "" || seen[strings.ToLower(w)] {
			continue
		}
		seen[strings.ToLower(w)] = true
		out = append(out, w)
	}
	return out
}

// Userinfo is the "subscription-userinfo" header panels send.
type Userinfo struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"` // unix seconds, 0 = none
}

// ParseUserinfo reads "upload=1; download=2; total=3; expire=4".
func ParseUserinfo(h string) (Userinfo, bool) {
	var u Userinfo
	ok := false
	for _, part := range strings.Split(h, ";") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		ok = true
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			u.Upload = n
		case "download":
			u.Download = n
		case "total":
			u.Total = n
		case "expire":
			u.Expire = n
		}
	}
	return u, ok
}

func (u Userinfo) String() string {
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", u.Upload, u.Download, u.Total, u.Expire)
}

// EncodeLinks is the subscription body: base64 of the links, one per line.
func EncodeLinks(links []string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}
