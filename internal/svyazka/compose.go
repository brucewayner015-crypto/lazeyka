package svyazka

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"lazeyka/internal/importer"
)

// Fetched is the last download of one source (kept on disk, so a source
// that is down keeps serving its last good list).
type Fetched struct {
	At       time.Time `json:"at"`       // last successful download
	Links    []string  `json:"links"`    // share links from it
	Userinfo string    `json:"userinfo"` // its subscription-userinfo header
	Err      string    `json:"err"`      // last error, if the last attempt failed
	ErrAt    time.Time `json:"err_at"`
}

// Server is one proxy as it is served (or why it is not).
type Server struct {
	Key      string `json:"key"`
	Source   string `json:"source"`   // upstream ID
	Original string `json:"original"` // name as the source gave it
	Name     string `json:"name"`     // after prefix and renaming
	Kind     string `json:"kind"`     // "VLESS · XHTTP · Reality"
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Hidden   string `json:"hidden"`  // "" = served; otherwise the reason
	Renamed  bool   `json:"renamed"` // the rules changed the name (not just the prefix)
	link     string
}

// Snapshot is the composed subscription.
type Snapshot struct {
	Servers  []Server
	Links    []string // what is served
	Userinfo string   // merged header ("" if no source sent one)
}

// Compose merges the sources' links with the rules: prefix per source, then
// renaming; hidden are servers matching a hide word (in the original or the
// new name), hidden by hand, or already served from an earlier source.
func Compose(st *State, cache map[string]*Fetched) (*Snapshot, error) {
	rules, err := CompileRules(st.Rename)
	if err != nil {
		return nil, err
	}
	hide := newHideMatcher(st.Hide)
	manual := map[string]bool{}
	for _, k := range st.Hidden {
		manual[k] = true
	}
	snap := &Snapshot{}
	seen := map[string]bool{}
	names := map[string]int{}
	var sum Userinfo
	haveInfo := false
	for _, up := range st.Upstreams {
		if !up.Enabled {
			continue
		}
		f := cache[up.ID]
		if f == nil {
			continue
		}
		if u, ok := ParseUserinfo(f.Userinfo); ok {
			haveInfo = true
			sum.Upload += u.Upload
			sum.Download += u.Download
			sum.Total += u.Total
			if u.Expire > 0 && (sum.Expire == 0 || u.Expire < sum.Expire) {
				sum.Expire = u.Expire
			}
		}
		for _, link := range f.Links {
			li, err := importer.InspectLink(link)
			if err != nil {
				continue
			}
			s := Server{Key: ServerKey(link), Source: up.ID, Original: li.Name, Kind: li.Summary(), Host: li.Host, Port: li.Port}
			s.Name = applyRules(up.Prefix+li.Name, rules)
			s.Renamed = s.Name != applyRules(up.Prefix+li.Name, nil)
			if s.Name == "" {
				s.Name = li.Host
			}
			switch {
			case seen[s.Key]:
				s.Hidden = "повтор"
			case manual[s.Key]:
				s.Hidden = "скрыт вручную"
			case placeholder(li.Host, li.Port):
				s.Hidden = "не сервер: адрес " + li.Host
			default:
				if w := hide.match(li.Name, s.Name); w != "" {
					s.Hidden = "по слову «" + w + "»"
				}
			}
			seen[s.Key] = true
			if s.Hidden == "" {
				// clients need distinct names
				base := s.Name
				for names[s.Name] > 0 {
					names[base]++
					s.Name = fmt.Sprintf("%s %d", base, names[base])
				}
				names[s.Name]++
				s.link = importer.RenameLink(link, s.Name)
				snap.Links = append(snap.Links, s.link)
			}
			snap.Servers = append(snap.Servers, s)
		}
	}
	if haveInfo {
		snap.Userinfo = sum.String()
	}
	return snap, nil
}

// placeholder: panels put notices ("осталось 3 дня", "продлите подписку")
// into subscriptions as fake servers pointing nowhere.
func placeholder(host string, port int) bool {
	if port <= 1 {
		return true
	}
	h := strings.Trim(strings.ToLower(host), "[]")
	if h == "" || h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 0 {
		return true
	}
	return ip.IsUnspecified() || ip.IsLoopback()
}

// FetchUpstream downloads and parses one source.
func FetchUpstream(ctx context.Context, c *http.Client, up Upstream) (*Fetched, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, up.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("неверный адрес: %w", err)
	}
	ua := up.UserAgent
	if ua == "" {
		ua = DefaultUA
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	if up.HWID != "" {
		req.Header.Set("x-hwid", up.HWID)
		req.Header.Set("x-device-os", "Linux")
		req.Header.Set("x-device-model", "Svyazka")
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue interface{ Timeout() bool }
		if errors.As(err, &ue) && ue.Timeout() {
			return nil, errors.New("источник не ответил вовремя")
		}
		return nil, fmt.Errorf("не удалось подключиться: %v", shortErr(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("источник ответил %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("загрузка прервалась: %v", shortErr(err))
	}
	links, err := ParseBody(body)
	if err != nil {
		return nil, err
	}
	return &Fetched{At: time.Now(), Links: links, Userinfo: resp.Header.Get("subscription-userinfo")}, nil
}

// shortErr drops the URL (it holds the source's secret token) from errors.
func shortErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, "\": "); i >= 0 {
		return msg[i+3:]
	}
	return msg
}
