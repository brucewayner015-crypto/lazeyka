// Лазейка — VPN-клиент для Windows: mihomo (VLESS, AmneziaWG до 3.1,
// подписки, маршрутизация по спискам) и zapret от Flowseal в одном окне.
package main

import (
	"embed"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"lazeyka/internal/app"
	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
	"lazeyka/internal/settings"
	"lazeyka/internal/update"
	"lazeyka/internal/web"
)

//go:embed assets/icons
var iconFS embed.FS

func icon(name string) []byte {
	b, _ := iconFS.ReadFile("assets/icons/" + name)
	return b
}

func trayIcons() map[string][]byte {
	return map[string][]byte{
		"on":   icon("tray-on.ico"),
		"off":  icon("tray-off.ico"),
		"busy": icon("tray-busy.ico"),
		"err":  icon("tray-err.ico"),
	}
}

func main() {
	show := flag.Bool("show", false, "открыть окно")
	autostart := flag.Bool("autostart", false, "запуск при входе в Windows")
	setup := flag.Bool("setup", false, "установить или обновить")
	uninstall := flag.Bool("uninstall", false, "удалить")
	dev := flag.Bool("dev", false, "режим разработки (без TUN и Windows)")
	flag.Parse()
	update.UserAgent = "Lazeyka/" + app.Version

	if runtime.GOOS != "windows" || *dev {
		runDev()
		return
	}
	p := app.NewPaths(platform.DataRoot())
	exe, err := os.Executable()
	if err != nil {
		platform.MessageBox("Лазейка", "Не удалось определить путь к программе: "+err.Error(), true)
		return
	}

	if !platform.IsElevated() {
		launch(p, exe, *setup || *uninstall, *uninstall)
		return
	}

	if *uninstall {
		_ = app.SignalInstance(p, "quit")
		time.Sleep(2 * time.Second)
		app.RemoveSystemBits()
		msg := "Лазейка удалена."
		if app.ScheduleDelete(p.Root, platform.UserUIDir()) > 0 {
			msg += "\n\nНесколько занятых файлов исчезнут после перезагрузки компьютера."
		}
		platform.MessageBox("Лазейка", msg, false)
		return
	}

	got, release := platform.SingleInstance("Lazeyka.Instance.v1")
	needInstall := *setup || !app.SamePath(exe, p.Exe) || app.InstalledVersion(p) != app.Version || !platform.TaskExists(platform.TaskMain)
	if !got {
		if !needInstall {
			if err := app.SignalInstance(p, "show"); err != nil {
				platform.MessageBox("Лазейка", "Лазейка уже запущена, но не отвечает. Закройте её в трее или перезагрузите компьютер.", true)
			}
			return
		}
		// A newer copy is being installed: ask the running one to quit.
		_ = app.SignalInstance(p, "quit")
		for i := 0; i < 30 && !got; i++ {
			time.Sleep(500 * time.Millisecond)
			got, release = platform.SingleInstance("Lazeyka.Instance.v1")
		}
		if !got {
			platform.MessageBox("Лазейка", "Не удалось закрыть запущенную Лазейку для обновления. Закройте её через значок в трее и запустите установку снова.", true)
			return
		}
	}
	if needInstall {
		autostartOn := true
		if s, err := settings.Load(p.Settings); err == nil && s != nil {
			autostartOn = s.App.Autostart
		}
		// Install opens the log file itself, after it has checked the folder:
		// a file we hold open here could not be cleaned up on a fresh install.
		warning, err := app.Install(p, exe, icon("lazeyka.ico"), autostartOn)
		if err != nil {
			platform.MessageBox("Лазейка", "Не удалось установить Лазейку:\n\n"+err.Error(), true)
			if !app.SamePath(exe, p.Exe) {
				release()
				return
			}
		} else if warning != "" {
			platform.MessageBox("Лазейка", "Лазейка установлена, но есть проблема:\n\n"+warning, true)
		}
		if !app.SamePath(exe, p.Exe) {
			release()
			err := startInstalled(p)
			if err != nil {
				// most likely the folder permissions: put plain inheritance back and retry
				logx.Errorf("запуск установленной копии: %v", err)
				if rerr := platform.RepairDir(p.Root); rerr != nil {
					logx.Errorf("восстановление прав: %v", rerr)
				}
				err = startInstalled(p)
			}
			if err != nil {
				platform.MessageBox("Лазейка", "Установлено, но не удалось запустить:\n\n"+err.Error()+
					"\n\nЖурнал: "+p.Logs+`\lazeyka.log`, true)
			}
			return
		}
	}
	defer release()
	app.CleanupOld(p)
	run(p, *show, *autostart)
}

// startInstalled runs the installed copy (elevated, like us) with --show.
func startInstalled(p app.Paths) error {
	cmd := exec.Command(p.Exe, "--show")
	cmd.Dir = p.Root
	return cmd.Start()
}

// launch runs without admin rights: start the installed copy through the
// scheduled task (no UAC prompt) or ask for elevation to install/update.
func launch(p app.Paths, exe string, forceSetup, uninstall bool) {
	inst := app.InstalledVersion(p)
	if !forceSetup && inst != "" && !update.NewerVersion(inst, app.Version) {
		if _, err := os.Stat(p.Exe); err == nil {
			if err := platform.RunTask(platform.TaskMain); err == nil {
				return
			}
		}
	}
	arg := "--setup"
	if uninstall {
		arg = "--uninstall"
	}
	if err := platform.RunElevated(exe, arg); err != nil {
		platform.MessageBox("Лазейка", "Лазейке нужны права администратора: она управляет сетевым адаптером и драйвером zapret.\n\n"+err.Error(), true)
	}
}

func run(p app.Paths, show, autostart bool) {
	a, err := app.New(p, false)
	if err != nil {
		platform.MessageBox("Лазейка", "Не удалось запустить: "+err.Error(), true)
		return
	}
	srv, err := web.New(a)
	if err != nil {
		platform.MessageBox("Лазейка", "Не удалось запустить интерфейс: "+err.Error(), true)
		return
	}
	a.UIURL = srv.URL()
	go func() {
		if err := srv.Serve(); err != nil {
			logx.Errorf("интерфейс: %v", err)
		}
	}()
	var tray *platform.Tray
	tray = platform.NewTray(platform.TrayCallbacks{
		OnOpen: a.OpenUI,
		OnToggleVPN: func() {
			if a.Connected() {
				a.Disconnect()
			} else {
				a.Connect()
			}
		},
		OnToggleZapret: func() { a.SetZapretEnabled(!a.Settings().Zapret.Enabled) },
		OnQuit:         func() { tray.Quit() },
		OnEndSession:   func() { a.Shutdown() },
		Choices:        a.TrayChoices,
		OnServer:       a.TrayServer,
		OnStrategy:     a.TrayStrategy,
		OnUpdate:       a.TrayUpdate,
	}, trayIcons(), p.IconDir)
	a.SetTray(tray)
	a.OpenUIHook = func() {
		if err := platform.OpenUI(a.UIURL); err != nil {
			logx.Errorf("не удалось открыть окно: %v", err)
		}
	}
	a.QuitHook = tray.Quit
	a.Start(autostart)
	s := a.Settings()
	if show || !autostart || !s.App.StartMinimized || !s.App.Onboarded {
		go a.OpenUI()
	}
	if err := tray.Run(); err != nil {
		logx.Errorf("значок в трее: %v", err)
		platform.MessageBox("Лазейка", "Не удалось создать значок в трее: "+err.Error(), true)
	}
	a.Shutdown()
	srv.Close()
}

// runDev runs on Linux/macOS for development: no TUN, no tray, no zapret.
func runDev() {
	p := app.NewPaths(platform.DataRoot())
	a, err := app.New(p, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	srv, err := web.New(a)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	a.UIURL = srv.URL()
	go srv.Serve()
	fmt.Println("UI:", a.UIURL)
	_ = os.WriteFile(p.Data+"/ui-url.txt", []byte(a.UIURL), 0o600)
	tray := platform.NewTray(platform.TrayCallbacks{}, nil, p.IconDir)
	a.SetTray(tray)
	a.OpenUIHook = func() { fmt.Println("UI:", a.UIURL) }
	a.QuitHook = tray.Quit
	a.Start(false)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; tray.Quit() }()
	tray.Run()
	a.Shutdown()
	srv.Close()
}
