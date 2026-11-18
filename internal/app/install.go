package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
)

// SamePath compares Windows paths case-insensitively.
func SamePath(a, b string) bool {
	a, _ = filepath.Abs(a)
	b, _ = filepath.Abs(b)
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// InstalledVersion reads version.txt from the install folder.
func InstalledVersion(p Paths) string {
	b, err := os.ReadFile(filepath.Join(p.Root, "version.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

// Install puts the app into its protected folder and registers it:
// exe copy, icon, version file, folder permissions, scheduled tasks and
// shortcuts. It runs elevated.
//
// A returned warning is a problem the app can live with (it is still
// installed and should start); an error means it cannot run from there.
func Install(p Paths, srcExe string, icon []byte, autostart bool) (warning string, err error) {
	note, err := prepareRoot(p)
	if err != nil {
		return "", err
	}
	for _, d := range []string{p.Root, p.Data, p.Tmp, p.Logs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", err
		}
	}
	_ = logx.Default().SetFile(filepath.Join(p.Logs, "lazeyka.log"))
	logx.Infof("установка Лазейки %s из %s", Version, srcExe)
	if note != "" {
		logx.Warnf("%s", note)
	}
	if !SamePath(srcExe, p.Exe) {
		if err := copyFile(srcExe, p.Exe+".new"); err != nil {
			return "", fmt.Errorf("не удалось скопировать программу: %w", err)
		}
		os.Remove(p.Exe + ".old")
		if _, err := os.Stat(p.Exe); err == nil {
			// a running exe can be renamed but not overwritten
			if err := os.Rename(p.Exe, p.Exe+".old"); err != nil {
				os.Remove(p.Exe + ".new")
				return "", fmt.Errorf("не удалось заменить старую версию: %w", err)
			}
		}
		if err := os.Rename(p.Exe+".new", p.Exe); err != nil {
			os.Rename(p.Exe+".old", p.Exe)
			return "", err
		}
	}
	if len(icon) > 0 {
		_ = os.WriteFile(p.Icon, icon, 0o644)
	}
	if err := os.WriteFile(filepath.Join(p.Root, "version.txt"), []byte(Version), 0o644); err != nil {
		return "", err
	}
	if err := platform.HardenDir(p.Root, true); err != nil {
		logx.Warnf("права на папку: %v", err)
	}
	if err := platform.HardenDir(p.Data, false); err != nil {
		logx.Warnf("права на папку данных: %v", err)
	}
	// self-check: whatever icacls did, we must still be able to open our files
	for _, f := range []string{p.Exe, filepath.Join(p.Root, "version.txt"), p.Settings} {
		fh, err := os.Open(f)
		if err == nil {
			fh.Close()
			continue
		}
		if os.IsNotExist(err) {
			continue
		}
		logx.Errorf("после настройки прав не открывается %s (%v), возвращаю наследование прав", f, err)
		if rerr := platform.RepairDir(p.Root); rerr != nil {
			logx.Errorf("восстановление прав: %v", rerr)
		}
		break
	}
	if err := platform.InstallTasks(p.Exe, autostart, p.Tmp); err != nil {
		// not fatal: without the tasks Лазейка asks for admin rights on each
		// start and does not start with Windows, but it works
		logx.Errorf("планировщик задач: %v", err)
		warning = "Не удалось зарегистрировать задачу в планировщике, поэтому Лазейка будет спрашивать права администратора при каждом запуске и не запустится вместе с Windows.\n\n" + err.Error()
	}
	if err := platform.CreateShortcuts(p.Exe, p.Icon); err != nil {
		logx.Warnf("ярлыки: %v", err)
	}
	logx.Infof("установлено в %s", p.Root)
	return warning, nil
}

// prepareRoot: the folder lives in ProgramData, where any user may create
// things, so nothing we did not put there is trusted. A link in its place is
// removed; on a fresh install (no version.txt) a pre-existing folder is
// wiped. If something in it is locked, at least everything we would run or
// load (engines, their configs, settings) must go, or we stop.
func prepareRoot(p Paths) (note string, err error) {
	fi, err := os.Lstat(p.Root)
	if err != nil {
		return "", nil // nothing there yet
	}
	if !fi.IsDir() { // symlink, junction or a plain file
		if err := os.Remove(p.Root); err != nil {
			return "", fmt.Errorf("вместо папки %s лежит ссылка или файл, удалите его: %w", p.Root, err)
		}
		return "", nil
	}
	if InstalledVersion(p) != "" {
		return "", nil // our own installation: keep settings and engines
	}
	if err := os.RemoveAll(p.Root); err == nil {
		return "", nil
	}
	// files with a broken ACL (left by 0.1.1) may refuse; inherit and retry
	if platform.RepairDir(p.Root) == nil {
		if err := os.RemoveAll(p.Root); err == nil {
			return "", nil
		}
	}
	for _, d := range []string{p.Bin, p.Zapret, p.MihomoHome, p.Settings} {
		if err := os.RemoveAll(d); err != nil {
			return "", fmt.Errorf("не удалось очистить старую папку %s: %w\n\nПерезагрузите компьютер и запустите Lazeyka.exe снова", d, err)
		}
	}
	return "старая папка очищена не полностью (какой-то файл занят), программы и настройки из неё удалены", nil
}

// CleanupOld removes the previous exe left after an update.
func CleanupOld(p Paths) {
	os.Remove(p.Exe + ".old")
	cleanupUpdates(p)
}

// Uninstall removes tasks, shortcuts, the WinDivert driver service and all
// files, then quits.
func (a *App) Uninstall() {
	logx.Infof("удаление Лазейки")
	a.opMu.Lock()
	a.stopTraffic()
	a.mihomo.Stop()
	a.zr.Stop()
	a.opMu.Unlock()
	a.endNetFix("удаление Лазейки")
	RemoveSystemBits()
	logx.Default().Close() // the log is in the folder that goes away
	ScheduleDelete(a.P.Root, platform.UserUIDir())
	a.Quit()
}

// RemoveSystemBits deletes tasks, shortcuts and the WinDivert service.
func RemoveSystemBits() {
	if !platform.IsWindows {
		return
	}
	platform.RemoveTasks()
	platform.RemoveShortcuts()
	if len(platform.ProcessPIDs("winws.exe")) == 0 {
		for _, svc := range []string{"WinDivert", "WinDivert14"} {
			if platform.Service(svc).Exists {
				platform.StopDeleteService(svc)
			}
		}
	}
}

// ScheduleDelete removes the folders: now what it can, the rest (the running
// exe) when Windows restarts. It returns how much waits for the restart.
func ScheduleDelete(dirs ...string) int { return platform.DeleteLater(dirs...) }
