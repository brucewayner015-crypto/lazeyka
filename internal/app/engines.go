package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
	"lazeyka/internal/update"
	"lazeyka/internal/zapret"
)

const (
	repoMihomo = "MetaCubeX/mihomo"
	repoZapret = "Flowseal/zapret-discord-youtube"
	ipsetURL   = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/ipset-service.txt"
)

var (
	mihomoAsset    = regexp.MustCompile(`^mihomo-windows-amd64-v1-v\d+\.\d+\.\d+\.zip$`)
	mihomoAssetOld = regexp.MustCompile(`^mihomo-windows-amd64-compatible-v\d+\.\d+\.\d+\.zip$`)
	zapretAsset    = regexp.MustCompile(`^zapret-discord-youtube-[\d.]+\.zip$`)
)

// latestRelease tries each client in turn.
func (a *App) latestRelease(repo string) (*update.Release, *http.Client, error) {
	var lastErr error
	for _, c := range a.downloadClients(60 * time.Second) {
		ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
		r, err := update.Latest(ctx, c, repo)
		cancel()
		if err == nil {
			return r, c, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

// downloadAsset puts asset into dst: straight from GitHub, then through the
// VPN if it is up, then from a copy the user downloaded by hand (Downloads or
// Desktop) whose SHA-256 matches the digest GitHub publishes. It returns the
// tag of the release the file came from.
func (a *App) downloadAsset(job, repo string, rel *update.Release, asset *update.Asset, pattern *regexp.Regexp, dst string) (string, error) {
	var lastErr error
	for _, c := range a.downloadClients(10 * time.Minute) {
		for attempt := 0; attempt < 2; attempt++ {
			ctx, cancel := context.WithTimeout(a.ctx, 10*time.Minute)
			err := update.Download(ctx, c, asset, dst, func(done, total int64) {
				if total > 0 {
					a.jobSet(job, float64(done)/float64(total), fmt.Sprintf("%s: %.1f из %.1f МБ", asset.Name, float64(done)/1e6, float64(total)/1e6))
				}
			})
			cancel()
			if err == nil {
				if asset.WantDigest() == "" {
					logx.Warnf("%s: GitHub не дал контрольную сумму, файл не проверен", asset.Name)
				}
				return rel.Tag, nil
			}
			lastErr = err
			if strings.Contains(err.Error(), "контрольная сумма") {
				return "", err // do not retry a tampered file through another route
			}
			if !update.Temporary(err) || a.ctx.Err() != nil {
				break
			}
			logx.Warnf("%v — пробую ещё раз", err)
			a.jobSet(job, -1, "Не получилось, пробую ещё раз…")
		}
	}
	logx.Warnf("%v", lastErr)
	a.jobSet(job, -1, "Ищу файл, скачанный вручную…")
	if tag, ok := a.localAsset(repo, rel, asset, pattern, dst); ok {
		return tag, nil
	}
	link := "https://github.com/" + repo + "/releases/download/" + rel.Tag + "/" + asset.Name
	return "", fmt.Errorf("%v.\n\nСкачайте этот файл любым другим способом (на телефоне, через другой VPN) и положите в папку «Загрузки» — Лазейка сама найдёт его, сверит контрольную сумму с GitHub и установит: %s", lastErr, link)
}

// "name (1).zip" -> "name.zip" (browsers number repeated downloads)
var dupSuffix = regexp.MustCompile(` \(\d+\)(\.[A-Za-z0-9]+)$`)

var verInName = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)*)\.zip$`)

// localAsset looks for a hand-downloaded engine archive in Downloads and on
// the Desktop. A file is used only if the SHA-256 of our own copy of it
// matches the digest GitHub publishes for that exact asset: the latest one,
// or another version, whose release is then looked up by tag.
func (a *App) localAsset(repo string, rel *update.Release, asset *update.Asset, pattern *regexp.Regexp, dst string) (string, bool) {
	for _, dir := range platform.UserFileDirs() {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			name := dupSuffix.ReplaceAllString(e.Name(), "$1")
			if !pattern.MatchString(name) {
				continue
			}
			want, tag := "", ""
			if name == asset.Name {
				want, tag = asset.WantDigest(), rel.Tag
			} else if r := a.releaseForAsset(repo, name); r != nil {
				for i := range r.Assets {
					if r.Assets[i].Name == name {
						want, tag = r.Assets[i].WantDigest(), r.Tag
					}
				}
			}
			if want == "" {
				continue // cannot verify: never use it
			}
			// hash our own copy: the original sits in a folder anyone can write to
			tmp := dst + ".local"
			if err := copyFile(filepath.Join(dir, e.Name()), tmp); err != nil {
				continue
			}
			got, err := update.FileSHA256(tmp)
			if err != nil || got != want {
				os.Remove(tmp)
				logx.Warnf("%s: контрольная сумма не совпала с GitHub, файл не используется", filepath.Join(dir, e.Name()))
				continue
			}
			os.Remove(dst)
			if err := os.Rename(tmp, dst); err != nil {
				os.Remove(tmp)
				continue
			}
			logx.Infof("взял %s из папки %s: контрольная сумма совпала с GitHub", name, dir)
			return tag, true
		}
	}
	return "", false
}

// releaseForAsset finds the release an archive name belongs to ("…1.19.34.zip").
func (a *App) releaseForAsset(repo, name string) *update.Release {
	m := verInName.FindStringSubmatch(name)
	if m == nil {
		return nil
	}
	for _, tag := range []string{"v" + m[1], m[1]} {
		for _, c := range a.downloadClients(30 * time.Second) {
			ctx, cancel := context.WithTimeout(a.ctx, 20*time.Second)
			r, err := update.ReleaseByTag(ctx, c, repo, tag)
			cancel()
			if err == nil {
				return r
			}
		}
	}
	return nil
}

func (a *App) ensureMihomo() error {
	if _, err := os.Stat(a.P.MihomoExe); err == nil {
		return nil
	}
	if a.Dev {
		return errors.New("в режиме разработки укажите путь к mihomo в LAZEYKA_MIHOMO")
	}
	if platform.IsAndroid {
		return errors.New("в приложении нет mihomo — переустановите Лазейку")
	}
	return a.installMihomo()
}

// InstallMihomo downloads the latest mihomo (public, runs as a job).
func (a *App) InstallMihomo() error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	wasOn := a.mihomo.Running()
	if wasOn {
		a.disconnectLocked()
	}
	err := a.installMihomo()
	if wasOn {
		if cerr := a.connectLocked(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

func (a *App) installMihomo() error {
	if !a.jobStart("mihomo", "Загрузка mihomo") {
		return errors.New("загрузка mihomo уже идёт")
	}
	err := func() error {
		a.jobSet("mihomo", -1, "Ищу последнюю версию на GitHub…")
		rel, _, err := a.latestRelease(repoMihomo)
		if err != nil {
			return fmt.Errorf("mihomo: %w", err)
		}
		asset, pattern := rel.Find(mihomoAsset), mihomoAsset
		if asset == nil {
			asset, pattern = rel.Find(mihomoAssetOld), mihomoAssetOld
		}
		if asset == nil {
			return fmt.Errorf("mihomo %s: в релизе нет сборки для Windows", rel.Tag)
		}
		zipPath := filepath.Join(a.P.Tmp, asset.Name)
		tag, err := a.downloadAsset("mihomo", repoMihomo, rel, asset, pattern, zipPath)
		if err != nil {
			return err
		}
		defer os.Remove(zipPath)
		a.jobSet("mihomo", 1, "Распаковка…")
		if err := update.ExtractFile(zipPath, func(n string) bool {
			n = strings.ToLower(n)
			return strings.HasPrefix(n, "mihomo") && strings.HasSuffix(n, ".exe")
		}, a.P.MihomoExe); err != nil {
			if platform.BlockedByAntivirus(err) {
				return fmt.Errorf("антивирус не дал сохранить mihomo. Добавьте папку %s в исключения Защитника Windows и включите VPN снова", a.P.Root)
			}
			return err
		}
		v := a.mihomo.Version()
		if v == "" {
			v = tag
		}
		_ = a.update(func(s *settings.Settings) error { s.App.MihomoVersion = v; return nil })
		logx.Infof("установлен mihomo %s", v)
		return nil
	}()
	a.jobDone("mihomo", err, nil)
	return err
}

// InstallZapret downloads/updates Flowseal's zapret bundle.
func (a *App) InstallZapret() error {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	return a.installZapret()
}

func (a *App) installZapret() error {
	if !platform.IsWindows {
		return errors.New("zapret работает только в Windows")
	}
	if !a.jobStart("zapret-install", "Загрузка zapret") {
		return errors.New("загрузка zapret уже идёт")
	}
	err := func() error {
		a.jobSet("zapret-install", -1, "Ищу последнюю версию на GitHub…")
		rel, _, err := a.latestRelease(repoZapret)
		if err != nil {
			return fmt.Errorf("zapret: %w", err)
		}
		asset := rel.Find(zapretAsset)
		if asset == nil {
			return fmt.Errorf("zapret %s: в релизе нет zip-архива", rel.Tag)
		}
		zipPath := filepath.Join(a.P.Tmp, asset.Name)
		tag, err := a.downloadAsset("zapret-install", repoZapret, rel, asset, zapretAsset, zipPath)
		if err != nil {
			return err
		}
		defer os.Remove(zipPath)
		a.jobSet("zapret-install", 1, "Распаковка…")
		staging := a.P.Zapret + ".new"
		os.RemoveAll(staging)
		if err := update.ExtractZip(zipPath, staging, true); err != nil {
			os.RemoveAll(staging)
			if platform.BlockedByAntivirus(err) {
				return fmt.Errorf("антивирус не дал распаковать zapret (драйвер WinDivert). %s", a.avHint())
			}
			return err
		}
		if !(zapret.Paths{Dir: staging}).Installed() {
			os.RemoveAll(staging)
			return errors.New("в архиве zapret нет winws.exe или стратегий")
		}
		// keep the user's own lists
		old := zapret.Paths{Dir: a.P.Zapret}
		for _, name := range []string{"list-general-user.txt", "list-exclude-user.txt", "ipset-exclude-user.txt"} {
			if b, err := os.ReadFile(filepath.Join(old.Lists(), name)); err == nil {
				_ = os.WriteFile(filepath.Join(staging, "lists", name), b, 0o644)
			}
		}
		wasRunning := a.zr.Running()
		a.zr.Stop()
		backup := a.P.Zapret + ".old"
		os.RemoveAll(backup)
		if _, err := os.Stat(a.P.Zapret); err == nil {
			if err := os.Rename(a.P.Zapret, backup); err != nil {
				return fmt.Errorf("не удалось заменить zapret (файлы заняты?): %w", err)
			}
		}
		if err := os.Rename(staging, a.P.Zapret); err != nil {
			os.Rename(backup, a.P.Zapret)
			return err
		}
		os.RemoveAll(backup)
		_ = a.update(func(s *settings.Settings) error { s.Zapret.Version = tag; return nil })
		logx.Infof("установлен zapret %s", tag)
		if wasRunning {
			go func() { time.Sleep(300 * time.Millisecond); a.StartZapret() }()
		}
		return nil
	}()
	a.jobDone("zapret-install", err, nil)
	return err
}

// EngineInfo is shown on the settings tab.
type EngineInfo struct {
	Mihomo       string `json:"mihomo"`
	MihomoLatest string `json:"mihomo_latest"`
	MihomoUpdate bool   `json:"mihomo_update"`
	Zapret       string `json:"zapret"`
	ZapretLatest string `json:"zapret_latest"`
	ZapretUpdate bool   `json:"zapret_update"`
	Checked      bool   `json:"checked"`
	Error        string `json:"error,omitempty"`
}

var engineCache EngineInfo

// Engines returns installed versions (and the last update check).
func (a *App) Engines() EngineInfo {
	s := a.Settings()
	a.mu.Lock()
	e := engineCache
	a.mu.Unlock()
	e.Mihomo, e.Zapret = s.App.MihomoVersion, s.Zapret.Version
	if _, err := os.Stat(a.P.MihomoExe); err != nil {
		e.Mihomo = ""
	} else if e.Mihomo == "" {
		// binary present but version unknown (placed by hand, settings reset):
		// ask it once and remember
		if v := a.mihomo.Version(); v != "" {
			e.Mihomo = v
			_ = a.update(func(s *settings.Settings) error { s.App.MihomoVersion = v; return nil })
		}
	}
	if !a.zpaths().Installed() {
		e.Zapret = ""
	}
	e.MihomoUpdate = e.Mihomo != "" && e.MihomoLatest != "" && update.NewerVersion(e.Mihomo, e.MihomoLatest)
	e.ZapretUpdate = e.Zapret != "" && e.ZapretLatest != "" && update.NewerVersion(e.Zapret, e.ZapretLatest)
	return e
}

// CheckEngineUpdates looks up the latest releases (and installs them if apply).
func (a *App) CheckEngineUpdates(apply bool) EngineInfo {
	var errs []string
	var e EngineInfo
	if r, _, err := a.latestRelease(repoMihomo); err == nil {
		e.MihomoLatest = r.Tag
	} else {
		errs = append(errs, err.Error())
	}
	if r, _, err := a.latestRelease(repoZapret); err == nil {
		e.ZapretLatest = r.Tag
	} else {
		errs = append(errs, err.Error())
	}
	e.Checked = true
	e.Error = strings.Join(errs, "; ")
	a.mu.Lock()
	engineCache = e
	a.mu.Unlock()
	info := a.Engines()
	if apply {
		if info.MihomoUpdate {
			if err := a.InstallMihomo(); err != nil {
				logx.Errorf("обновление mihomo: %v", err)
			}
		}
		if info.ZapretUpdate {
			if err := a.InstallZapret(); err != nil {
				logx.Errorf("обновление zapret: %v", err)
			}
		}
		info = a.Engines()
	} else if info.MihomoUpdate || info.ZapretUpdate {
		logx.Infof("доступны обновления: mihomo %s, zapret %s", info.MihomoLatest, info.ZapretLatest)
	}
	return info
}

// UpdateIPSet refreshes zapret's full IP list from Flowseal's repository.
func (a *App) UpdateIPSet() error {
	var data []byte
	var lastErr error
	for _, c := range a.downloadClients(60 * time.Second) {
		ctx, cancel := context.WithTimeout(a.ctx, 60*time.Second)
		data, lastErr = update.Fetch(ctx, c, ipsetURL, 64<<20)
		cancel()
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		return fmt.Errorf("не удалось скачать список IP: %w", lastErr)
	}
	if err := zapret.UpdateIPSet(a.zpaths(), data); err != nil {
		return err
	}
	if a.zr.Running() && a.Settings().Zapret.IPSet == zapret.IPSetLoaded {
		return a.StartZapret()
	}
	return nil
}

// Ensure the engines exist on first run (used by onboarding).
func (a *App) EnsureEngines() {
	go func() {
		if err := a.ensureMihomo(); err != nil {
			logx.Errorf("%v", err)
		}
		if platform.IsWindows && !a.zpaths().Installed() {
			a.opMu.Lock()
			err := a.installZapret()
			a.opMu.Unlock()
			if err != nil {
				logx.Errorf("%v", err)
			}
		}
	}()
}
