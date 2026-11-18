// Package update downloads engines from their official GitHub releases and
// verifies them against the SHA-256 digest GitHub publishes for each asset.
package update

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// UserAgent for GitHub requests.
var UserAgent = "Lazeyka"

// Asset is a release file.
type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"` // "sha256:<hex>"
}

// Release is a GitHub release.
type Release struct {
	Tag       string    `json:"tag_name"`
	Name      string    `json:"name"`
	Published time.Time `json:"published_at"`
	Assets    []Asset   `json:"assets"`
}

// Latest returns the latest release of owner/repo.
func Latest(ctx context.Context, c *http.Client, repo string) (*Release, error) {
	return getRelease(ctx, c, "https://api.github.com/repos/"+repo+"/releases/latest")
}

// ReleaseByTag returns the release with the given tag.
func ReleaseByTag(ctx context.Context, c *http.Client, repo, tag string) (*Release, error) {
	return getRelease(ctx, c, "https://api.github.com/repos/"+repo+"/releases/tags/"+url.PathEscape(tag))
}

func getRelease(ctx context.Context, c *http.Client, u string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub недоступен: %s", NetError(err))
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errors.New("на GitHub нет такого релиза")
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, errors.New("GitHub временно ограничил запросы — попробуйте через час")
	default:
		return nil, fmt.Errorf("GitHub ответил %s", resp.Status)
	}
	var r Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&r); err != nil {
		return nil, fmt.Errorf("ответ GitHub не разобран: %w", err)
	}
	return &r, nil
}

// NetError turns a network error into one short line without the (long,
// signed) download URL: "release-assets.githubusercontent.com: TLS-соединение
// не установилось за отведённое время".
func NetError(err error) string {
	var ue *url.Error
	if !errors.As(err, &ue) {
		return err.Error()
	}
	host := ue.URL
	if u, perr := url.Parse(ue.URL); perr == nil && u.Host != "" {
		host = u.Host
	}
	inner := ue.Err
	msg := inner.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "tls handshake timeout"):
		msg = "TLS-соединение не установилось за отведённое время (похоже, провайдер мешает)"
	case errors.Is(inner, context.DeadlineExceeded) || strings.Contains(low, "timeout"):
		msg = "нет ответа (таймаут)"
	case strings.Contains(low, "connection reset") || strings.Contains(low, "forcibly closed"):
		msg = "соединение сброшено (похоже, провайдер мешает)"
	case strings.Contains(low, "no such host"):
		msg = "адрес не найден (DNS)"
	case strings.Contains(low, "refused"):
		msg = "соединение отклонено"
	case strings.Contains(low, "certificate"):
		msg = "сертификат не прошёл проверку (кто-то подменяет соединение?)"
	}
	return host + ": " + msg
}

// Temporary reports errors worth one more try (timeouts, resets, stalls).
func Temporary(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	for _, s := range []string{"timeout", "таймаут", "reset", "сброшено", "eof", "прервалась", "остановилась", "отведённое время"} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// Find returns the first asset whose name matches re.
func (r *Release) Find(re *regexp.Regexp) *Asset {
	for i := range r.Assets {
		if re.MatchString(r.Assets[i].Name) {
			return &r.Assets[i]
		}
	}
	return nil
}

// Download saves an asset to dst, verifying the SHA-256 digest when GitHub
// provides one. progress may be nil.
func Download(ctx context.Context, c *http.Client, a *Asset, dst string, progress func(done, total int64)) error {
	const maxSize = 300 << 20
	if a.Size > maxSize {
		return fmt.Errorf("файл %s слишком большой", a.Name)
	}
	// A stalled transfer (some providers freeze foreign CDNs after ~16 KB)
	// would otherwise hang until the overall deadline.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var lastData atomic.Int64
	var stalled atomic.Bool
	lastData.Store(time.Now().UnixNano())
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Since(time.Unix(0, lastData.Load())) > 45*time.Second {
					stalled.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		if stalled.Load() {
			return fmt.Errorf("загрузка %s: сервер не ответил за 45 секунд", a.Name)
		}
		return fmt.Errorf("загрузка %s: %s", a.Name, NetError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("загрузка %s: %s", a.Name, resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	part := dst + ".part"
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	h := sha256.New()
	total := a.Size
	if total <= 0 {
		total = resp.ContentLength
	}
	var done int64
	buf := make([]byte, 64<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			lastData.Store(time.Now().UnixNano())
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				os.Remove(part)
				return werr
			}
			h.Write(buf[:n])
			done += int64(n)
			if done > maxSize {
				f.Close()
				os.Remove(part)
				return fmt.Errorf("файл %s больше ожидаемого", a.Name)
			}
			if progress != nil {
				progress(done, total)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			os.Remove(part)
			if stalled.Load() {
				return fmt.Errorf("загрузка %s остановилась: 45 секунд без данных (похоже, провайдер обрывает загрузку)", a.Name)
			}
			return fmt.Errorf("загрузка %s прервалась: %s", a.Name, NetError(rerr))
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(part)
		return err
	}
	if a.Size > 0 && done != a.Size {
		os.Remove(part)
		return fmt.Errorf("загрузка %s неполная (%d из %d байт)", a.Name, done, a.Size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if want, ok := strings.CutPrefix(strings.ToLower(a.Digest), "sha256:"); ok && want != "" {
		if want != got {
			os.Remove(part)
			return fmt.Errorf("контрольная сумма %s не совпала: файл повреждён или подменён", a.Name)
		}
	}
	os.Remove(dst)
	return os.Rename(part, dst)
}

// WantDigest is the lower-case hex SHA-256 GitHub publishes for the asset
// ("" if it does not).
func (a *Asset) WantDigest() string {
	want, ok := strings.CutPrefix(strings.ToLower(a.Digest), "sha256:")
	if !ok {
		return ""
	}
	return want
}

// FileSHA256 hashes a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 1<<30)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// safeJoin prevents zip-slip.
func safeJoin(dir, name string) (string, error) {
	name = filepath.FromSlash(name)
	p := filepath.Join(dir, name)
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(name) {
		return "", fmt.Errorf("недопустимый путь в архиве: %s", name)
	}
	return p, nil
}

// ExtractZip unpacks src into dstDir. If stripTop, a single top-level folder
// is removed from every path.
func ExtractZip(src, dstDir string, stripTop bool) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("архив повреждён: %w", err)
	}
	defer zr.Close()
	prefix := ""
	if stripTop {
		for _, f := range zr.File {
			parts := strings.SplitN(strings.ReplaceAll(f.Name, `\`, "/"), "/", 2)
			if len(parts) < 2 {
				prefix = ""
				break
			}
			if prefix == "" {
				prefix = parts[0] + "/"
			} else if prefix != parts[0]+"/" {
				prefix = ""
				break
			}
		}
	}
	var total int64
	for _, f := range zr.File {
		name := strings.TrimPrefix(strings.ReplaceAll(f.Name, `\`, "/"), prefix)
		if name == "" {
			continue
		}
		p, err := safeJoin(dstDir, name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(p, 0o755); err != nil {
				return err
			}
			continue
		}
		total += int64(f.UncompressedSize64)
		if total > 1<<30 {
			return errors.New("архив распаковывается в слишком большой объём")
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(p)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, 512<<20))
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ExtractFile extracts the first zip entry accepted by match into dst.
func ExtractFile(src string, match func(name string) bool, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("архив повреждён: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !match(filepath.Base(f.Name)) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		tmp := dst + ".new"
		out, err := os.Create(tmp)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(rc, 512<<20)); err != nil {
			out.Close()
			os.Remove(tmp)
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		os.Remove(dst)
		return os.Rename(tmp, dst)
	}
	return errors.New("в архиве не найден нужный файл")
}

// Fetch downloads a small file into memory.
func Fetch(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, errors.New(NetError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", req.URL.Host, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// NewerVersion reports whether latest (e.g. "v1.19.35") is newer than current.
func NewerVersion(current, latest string) bool {
	a, b := parseVer(current), parseVer(latest)
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return y > x
		}
	}
	return false
}

func parseVer(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(strings.ToLower(v)), "v")
	var out []int
	for _, p := range strings.Split(v, ".") {
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}
