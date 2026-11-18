package zapret

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Check is one reachability test.
type Check struct {
	Name     string `json:"name"`
	Group    string `json:"group"`
	URL      string `json:"url"`
	Download bool   `json:"download"` // read 64 KB to catch the 16–20 KB freeze
}

// CheckResult of a single check.
type CheckResult struct {
	Name  string `json:"name"`
	Group string `json:"group"`
	OK    bool   `json:"ok"`
	Ms    int    `json:"ms"`
	Bytes int64  `json:"bytes,omitempty"`
	Err   string `json:"err,omitempty"`
}

// DefaultChecks covers YouTube and Discord the way users notice problems.
func DefaultChecks() []Check {
	return []Check{
		{"YouTube", "youtube", "https://www.youtube.com/", true},
		{"Картинки YouTube", "youtube", "https://i.ytimg.com/vi/aqz-KE-bpKQ/maxresdefault.jpg", true},
		{"Видео YouTube", "youtube", "https://redirector.googlevideo.com/report_mapping", false},
		{"youtu.be", "youtube", "https://youtu.be/", false},
		{"Discord", "discord", "https://discord.com/", true},
		{"Шлюз Discord", "discord", "https://gateway.discord.gg/", false},
		{"Файлы Discord", "discord", "https://cdn.discordapp.com/", false},
		{"Обновления Discord", "discord", "https://updates.discord.com/", false},
		{"Google", "google", "https://www.google.com/", false},
	}
}

const downloadBytes = 64 << 10

// RunChecks runs all checks in parallel with fresh connections.
func RunChecks(ctx context.Context, proxy *url.URL, checks []Check) []CheckResult {
	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 6 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
	if proxy != nil {
		tr.Proxy = http.ProxyURL(proxy)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   9 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a redirect already proves reachability
		},
	}
	out := make([]CheckResult, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			out[i] = runCheck(ctx, client, c)
		}(i, c)
	}
	wg.Wait()
	return out
}

func runCheck(ctx context.Context, client *http.Client, c Check) CheckResult {
	res := CheckResult{Name: c.Name, Group: c.Group}
	start := time.Now()
	method := http.MethodHead
	if c.Download {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL, nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36")
	if c.Download {
		req.Header.Set("Range", "bytes=0-65535")
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Err = humanErr(err)
		res.Ms = int(time.Since(start).Milliseconds())
		return res
	}
	defer resp.Body.Close()
	if c.Download {
		n, rerr := io.Copy(io.Discard, io.LimitReader(resp.Body, downloadBytes))
		res.Bytes = n
		if rerr != nil && n < downloadBytes {
			if n > 0 && n < 32<<10 {
				res.Err = "соединение «замерзает» после " + kb(n) + " — признак блокировки 16–20 КБ"
			} else {
				res.Err = humanErr(rerr)
			}
			res.Ms = int(time.Since(start).Milliseconds())
			return res
		}
	}
	res.OK = true
	res.Ms = int(time.Since(start).Milliseconds())
	return res
}

func kb(n int64) string {
	return strings.Replace(fmt.Sprintf("%.1f КБ", float64(n)/1024), ".", ",", 1)
}

func humanErr(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "отменено"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, os.ErrDeadlineExceeded):
		return "нет ответа (таймаут)"
	case errors.Is(err, syscall.ECONNRESET), strings.Contains(err.Error(), "reset"), strings.Contains(err.Error(), "forcibly closed"):
		return "соединение сброшено (похоже на DPI)"
	case errors.Is(err, syscall.ECONNREFUSED), strings.Contains(err.Error(), "refused"):
		return "соединение отклонено"
	case strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "TLS") || strings.Contains(err.Error(), "certificate"):
		return "ошибка TLS (похоже на подмену или DPI)"
	case strings.Contains(err.Error(), "no such host"):
		return "домен не найден (DNS)"
	case strings.Contains(err.Error(), "EOF"):
		return "соединение оборвано"
	}
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return msg
}

// Summary of a batch of results.
type Summary struct {
	OK      int `json:"ok"`
	Total   int `json:"total"`
	AvgMs   int `json:"avg_ms"`
	YouTube int `json:"youtube"` // ok count in group
	Discord int `json:"discord"`
}

// Summarize counts successes.
func Summarize(rs []CheckResult) Summary {
	s := Summary{Total: len(rs)}
	sum := 0
	for _, r := range rs {
		if r.OK {
			s.OK++
			sum += r.Ms
			switch r.Group {
			case "youtube":
				s.YouTube++
			case "discord":
				s.Discord++
			}
		}
	}
	if s.OK > 0 {
		s.AvgMs = sum / s.OK
	}
	return s
}

// StrategyScore is the outcome of testing one strategy.
type StrategyScore struct {
	File    string        `json:"file"`
	Summary Summary       `json:"summary"`
	Results []CheckResult `json:"results"`
	Err     string        `json:"err,omitempty"`
}

// Best picks the strategy with most successes, then lowest latency.
func Best(scores []StrategyScore) (StrategyScore, bool) {
	var ok []StrategyScore
	for _, s := range scores {
		if s.Err == "" && s.Summary.OK > 0 {
			ok = append(ok, s)
		}
	}
	if len(ok) == 0 {
		return StrategyScore{}, false
	}
	sort.SliceStable(ok, func(i, j int) bool {
		a, b := ok[i].Summary, ok[j].Summary
		if a.OK != b.OK {
			return a.OK > b.OK
		}
		return a.AvgMs < b.AvgMs
	})
	return ok[0], true
}
