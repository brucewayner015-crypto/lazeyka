package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/update"
)

// Лазейка updates itself from its GitHub repository: the "release" branch
// holds latest.json and the zipped exe. The download goes straight into
// Лазейка's own folder (only administrators write there, Defender skips it),
// is checked against the SHA-256 sums from latest.json, and the new exe
// installs itself the usual way (main.go: it asks the running copy to quit,
// puts itself in place and starts). A file Лазейка downloads itself carries
// no "from the internet" mark, so SmartScreen does not stop it either.

// SelfRepo is where updates come from.
const SelfRepo = "brucewayner015-crypto/lazeyka"

var selfBase = "https://raw.githubusercontent.com/" + SelfRepo + "/release/"

// selfManifest is latest.json.
type selfManifest struct {
	Version   string `json:"version"`
	File      string `json:"file"`       // the zip next to latest.json
	Size      int64  `json:"size"`       // of the zip
	SHA256    string `json:"sha256"`     // of the zip
	ExeSHA256 string `json:"exe_sha256"` // of Lazeyka.exe inside
	Notes     string `json:"notes"`
	Published string `json:"published"`
}

var (
	versionRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	shaRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	zipNameRe  = regexp.MustCompile(`^Lazeyka-\d+\.\d+\.\d+\.zip$`)
	errNoNewer = errors.New("у вас последняя версия")
)

func (m *selfManifest) validate() error {
	m.SHA256, m.ExeSHA256 = strings.ToLower(m.SHA256), strings.ToLower(m.ExeSHA256)
	switch {
	case !versionRe.MatchString(m.Version):
		return fmt.Errorf("непонятная версия %q", m.Version)
	case !zipNameRe.MatchString(m.File):
		return fmt.Errorf("непонятное имя файла %q", m.File)
	case !shaRe.MatchString(m.SHA256) || !shaRe.MatchString(m.ExeSHA256):
		return errors.New("нет контрольных сумм")
	case m.Size <= 0 || m.Size > 100<<20:
		return fmt.Errorf("странный размер %d", m.Size)
	}
	return nil
}

// SelfUpdateView answers /api/selfupdate.
type SelfUpdateView struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	Available bool      `json:"available"`
	Notes     string    `json:"notes,omitempty"`
	Checked   time.Time `json:"checked"`
	Error     string    `json:"error,omitempty"`
}

func (a *App) SelfUpdate() SelfUpdateView {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.self
	v.Current = Version
	v.Available = v.Latest != "" && update.NewerVersion(Version, v.Latest)
	return v
}

// fetchManifest reads latest.json, directly or through the VPN.
func (a *App) fetchManifest() (*selfManifest, error) {
	var lastErr error
	for _, c := range a.downloadClients(30 * time.Second) {
		ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
		b, err := update.Fetch(ctx, c, selfBase+"latest.json", 64<<10)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		var m selfManifest
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("latest.json: %w", err)
		}
		if err := m.validate(); err != nil {
			return nil, fmt.Errorf("latest.json: %w", err)
		}
		return &m, nil
	}
	return nil, lastErr
}

// CheckSelfUpdate looks for a newer Лазейка.
func (a *App) CheckSelfUpdate() SelfUpdateView {
	m, err := a.fetchManifest()
	a.mu.Lock()
	prev := a.self.Latest
	a.self.Checked = time.Now()
	a.self.Error = ""
	if err != nil {
		a.self.Error = "не удалось проверить: " + err.Error()
	} else {
		a.self.Latest, a.self.Notes = m.Version, m.Notes
	}
	a.mu.Unlock()
	v := a.SelfUpdate()
	if err != nil {
		logx.Debugf("обновление Лазейки: %v", err)
	} else if v.Available && v.Latest != prev {
		logx.Infof("доступна Лазейка %s (сейчас %s)", v.Latest, Version)
		if a.tray != nil {
			a.tray.Notify("Доступна Лазейка "+v.Latest, "Обновить можно в окне или в меню значка.", false)
		}
	}
	return v
}

// InstallSelfUpdate downloads the new version and starts its installation
// (a job: the window shows the progress).
func (a *App) InstallSelfUpdate() error {
	if !a.jobStart("self-update", "Обновление Лазейки") {
		return errors.New("обновление уже идёт")
	}
	go func() {
		err := a.installSelfUpdate()
		if err != nil {
			logx.Errorf("обновление Лазейки: %v", err)
		}
		a.jobDone("self-update", err, nil)
	}()
	return nil
}

func (a *App) installSelfUpdate() error {
	if a.Dev || !platform.IsWindows {
		return errors.New("обновление работает только в установленной Лазейке")
	}
	exe, version, err := a.downloadSelfUpdate()
	if err != nil {
		return err
	}
	a.jobSet("self-update", 1, "Устанавливаю Лазейку "+version+": окно откроется заново")
	logx.Infof("ставлю Лазейку %s", version)
	// the new exe asks us to quit, installs itself and starts
	if err := platform.StartDetached(exe, "--setup"); err != nil {
		return fmt.Errorf("не удалось запустить установку: %w", err)
	}
	return nil
}

// downloadSelfUpdate fetches the newer version into the temp folder and
// checks it; it returns the exe and its version.
func (a *App) downloadSelfUpdate() (exe, version string, err error) {
	m, err := a.fetchManifest()
	if err != nil {
		return "", "", fmt.Errorf("не удалось узнать последнюю версию: %w", err)
	}
	if !update.NewerVersion(Version, m.Version) {
		return "", "", errNoNewer
	}
	a.jobSet("self-update", 0, "Скачиваю Лазейку "+m.Version)
	if err := os.MkdirAll(a.P.Tmp, 0o755); err != nil {
		return "", "", err
	}
	zipPath := filepath.Join(a.P.Tmp, "lazeyka-"+m.Version+".zip")
	asset := &update.Asset{Name: m.File, URL: selfBase + m.File, Size: m.Size, Digest: "sha256:" + m.SHA256}
	var lastErr error
	for _, c := range a.downloadClients(10 * time.Minute) {
		ctx, cancel := context.WithTimeout(a.ctx, 10*time.Minute)
		lastErr = update.Download(ctx, c, asset, zipPath, func(done, total int64) {
			if total > 0 {
				a.jobSet("self-update", float64(done)/float64(total)*0.9, "Скачиваю Лазейку "+m.Version)
			}
		})
		cancel()
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		return "", "", lastErr
	}
	defer os.Remove(zipPath)
	exe = filepath.Join(a.P.Tmp, "Lazeyka-"+m.Version+".exe")
	if err := update.ExtractFile(zipPath, func(name string) bool { return strings.EqualFold(filepath.Base(name), "Lazeyka.exe") }, exe); err != nil {
		return "", "", fmt.Errorf("архив обновления: %w", err)
	}
	got, err := update.FileSHA256(exe)
	if err != nil {
		return "", "", err
	}
	if got != m.ExeSHA256 {
		os.Remove(exe)
		return "", "", errors.New("контрольная сумма Lazeyka.exe не совпала: файл повреждён или подменён")
	}
	return exe, m.Version, nil
}

// cleanupUpdates removes what earlier updates left in the temp folder.
func cleanupUpdates(p Paths) {
	for _, pattern := range []string{"Lazeyka-*.exe", "lazeyka-*.zip"} {
		matches, _ := filepath.Glob(filepath.Join(p.Tmp, pattern))
		for _, m := range matches {
			os.Remove(m)
		}
	}
}

// selfUpdateLoop checks once a little after the start, then twice a day.
func (a *App) selfUpdateLoop() {
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
		if a.Settings().App.CheckUpdates {
			a.CheckSelfUpdate()
		}
		t.Reset(12 * time.Hour)
	}
}
