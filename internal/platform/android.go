//go:build lzandroid

package platform

// The Android build: the core is a Linux binary started by the Android app
// (see android/), which passes everything Android-specific through
// environment variables and the host socket.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // Android has no /usr/share/zoneinfo

	"lazeyka/internal/host"
)

// IsWindows is true on Windows.
const IsWindows = false

// IsAndroid is true in the Android build.
const IsAndroid = true

var (
	dnsMu      sync.Mutex
	dnsServers []string
)

// SetDNS sets the resolvers the core itself uses (the phone's current
// network DNS; Android has no /etc/resolv.conf for Go to read).
func SetDNS(servers []string) {
	var out []string
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(strings.Trim(s, "[]")); ip != nil {
			if ip.To4() == nil {
				continue // IPv6 is off in the VPN; the network's v4 resolver is enough
			}
			s = net.JoinHostPort(ip.String(), "53")
		}
		out = append(out, s)
	}
	out = append(out, "77.88.8.8:53", "8.8.8.8:53")
	dnsMu.Lock()
	dnsServers = out
	dnsMu.Unlock()
}

func init() {
	SetDNS(strings.Split(os.Getenv("LAZEYKA_DNS"), ","))
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dnsMu.Lock()
			list := append([]string{}, dnsServers...)
			dnsMu.Unlock()
			var d net.Dialer
			var last error
			for _, s := range list {
				dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				c, err := d.DialContext(dctx, network, s)
				cancel()
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
}

// DataRoot is the app's private files directory.
func DataRoot() string {
	if d := os.Getenv("LAZEYKA_HOME"); d != "" {
		return d
	}
	return "/data/local/tmp/lazeyka"
}

// UserUIDir is unused on Android.
func UserUIDir() string { return filepath.Join(DataRoot(), "ui") }

// SystemDir is unused on Android.
func SystemDir() string { return "/system/bin" }

func IsElevated() bool                   { return true }
func RunElevated(exe, args string) error { return errors.New("not supported on Android") }

// SingleInstance: the app starts one core.
func SingleInstance(name string) (bool, func()) { return true, func() {} }

// PrepareChild puts the child into its own process group and kills it with us.
func PrepareChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// AttachChild is a no-op on Android.
func AttachChild(pid int) {}

// OSVersion: "Android 14".
func OSVersion() string {
	if v := os.Getenv("LAZEYKA_OSVER"); v != "" {
		return "Android " + v
	}
	return "Android"
}

// DeviceModel is the phone model.
func DeviceModel() string {
	if v := os.Getenv("LAZEYKA_MODEL"); v != "" {
		return v
	}
	return "Android"
}

// MachineID identifies the phone (Settings.Secure.ANDROID_ID, per app).
func MachineID() string {
	if v := os.Getenv("LAZEYKA_DEVICE_ID"); v != "" {
		return v
	}
	h, _ := os.Hostname()
	return h
}

func CurrentUserSID() (string, error) { return fmt.Sprint(os.Getuid()), nil }

func DefaultRouteIfIndex(exclude string) int    { return 0 }
func DefaultRoutes(exclude string) []RouteIface { return nil }
func SetHostFlags(ifIdx int, forwarding, weakSend *bool) error {
	return errors.New("not supported on Android")
}
func SharedConnections() (public, private []string, err error) { return nil, nil, nil }
func InterfaceHostModel(ifIdx int) (HostModel, bool)           { return HostModel{}, false }
func IPEnableRouter() (uint32, bool)                           { return 0, false }

func MessageBox(title, text string, isError bool) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", title, text)
	if Host != nil {
		_ = Host.Tell("status", host.Status{Notify: true, Title: title, Text: text, Warn: isError})
	}
}

// OpenUI brings the app to the front.
func OpenUI(url string) error {
	if Host == nil {
		return host.ErrNoHost
	}
	return Host.Tell("show", nil)
}

func InstallTasks(exe string, autostart bool, tmpDir string) error { return nil }
func SetAutostart(exe string, on bool, tmpDir string) error        { return nil }
func RunTask(name string) error                                    { return errors.New("no tasks on Android") }
func TaskExists(name string) bool                                  { return false }
func RemoveTasks()                                                 {}
func CreateShortcuts(exe, icon string) error                       { return nil }
func RemoveShortcuts()                                             {}
func HardenDir(dir string, usersRead bool) error                   { return nil }
func Service(name string) ServiceInfo                              { return ServiceInfo{} }
func StopDeleteService(name string)                                {}
func ProcessPIDs(image string) []int                               { return nil }
func KillPID(pid int)                                              {}
func DeleteLater(dirs ...string) int                               { return 0 }

// Tray on Android is the app's notification.
type Tray struct {
	cb   TrayCallbacks
	quit chan struct{}
	once sync.Once
}

func NewTray(cb TrayCallbacks, icons map[string][]byte, iconDir string) *Tray {
	return &Tray{cb: cb, quit: make(chan struct{})}
}

// Run blocks until Quit.
func (t *Tray) Run() error { <-t.quit; return nil }

// Update refreshes the notification.
func (t *Tray) Update(st TrayState) {
	if Host == nil {
		return
	}
	_ = Host.Tell("status", host.Status{Mode: st.Mode, Title: "Лазейка", Text: st.Status, VPNOn: st.VPNOn, DPIOn: st.ZapretOn})
}

// Notify shows a one-off notification.
func (t *Tray) Notify(title, text string, warn bool) {
	if Host == nil {
		fmt.Println("notify:", title, "—", text)
		return
	}
	_ = Host.Tell("status", host.Status{Notify: true, Title: title, Text: text, Warn: warn})
}

func (t *Tray) Quit() { t.once.Do(func() { close(t.quit) }) }

// BlockedByAntivirus is Windows-only.
func BlockedByAntivirus(err error) bool { return false }

// RepairDir is Windows-only.
func RepairDir(dir string) error { return nil }

// UserFileDirs: the app cannot read the phone's Downloads without asking.
func UserFileDirs() []string { return nil }

// DefenderState: Windows only.
type DefenderState struct {
	Mode     string
	Active   bool
	Excluded bool
}

// DefenderStatus: Windows only.
func DefenderStatus(dir string) (DefenderState, error) {
	return DefenderState{}, errors.New("not supported on Android")
}

// StartDetached is unused on Android.
func StartDetached(exe string, args ...string) error {
	return errors.New("not supported on Android")
}
