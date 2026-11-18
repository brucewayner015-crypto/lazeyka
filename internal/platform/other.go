//go:build !windows && !lzandroid

package platform

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

// IsWindows is true on Windows.
const IsWindows = false

// IsAndroid is true in the Android build.
const IsAndroid = false

// DataRoot for development runs.
func DataRoot() string {
	if d := os.Getenv("LAZEYKA_HOME"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".lazeyka-dev")
}

// UserUIDir is unused outside Windows.
func UserUIDir() string { return filepath.Join(DataRoot(), "ui") }

// SystemDir is unused outside Windows.
func SystemDir() string { return "/usr/bin" }

func IsElevated() bool                   { return true }
func RunElevated(exe, args string) error { return fmt.Errorf("not supported on %s", runtime.GOOS) }

// SingleInstance always succeeds in development.
func SingleInstance(name string) (bool, func()) { return true, func() {} }

// PrepareChild puts the child into its own process group.
func PrepareChild(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// AttachChild is a no-op outside Windows.
func AttachChild(pid int) {}

func OSVersion() string               { return runtime.GOOS }
func MachineID() string               { h, _ := os.Hostname(); return h }
func CurrentUserSID() (string, error) { return fmt.Sprint(os.Getuid()), nil }

// DefaultRouteIfIndex is unused outside Windows.
func DefaultRouteIfIndex(exclude string) int { return 0 }

// DefaultRoutes: Windows only.
func DefaultRoutes(exclude string) []RouteIface { return nil }

// BindDialer: Windows only (elsewhere the app's own connections already
// leave past the VPN).
func BindDialer(d *net.Dialer, ifIdx int) {}

// SetHostFlags: Windows only.
func SetHostFlags(ifIdx int, forwarding, weakSend *bool) error {
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

// SharedConnections: Windows only.
func SharedConnections() (public, private []string, err error) { return nil, nil, nil }

func InterfaceHostModel(ifIdx int) (HostModel, bool) { return HostModel{}, false }
func IPEnableRouter() (uint32, bool)                 { return 0, false }

func MessageBox(title, text string, isError bool) { fmt.Fprintf(os.Stderr, "%s: %s\n", title, text) }

// OpenUI prints the URL in development.
func OpenUI(url string) error {
	fmt.Println("UI:", url)
	return nil
}

func InstallTasks(exe string, autostart bool, tmpDir string) error { return nil }
func SetAutostart(exe string, on bool, tmpDir string) error        { return nil }
func RunTask(name string) error                                    { return fmt.Errorf("no tasks on %s", runtime.GOOS) }
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

// Tray is a stand-in that just blocks until Quit.
type Tray struct {
	cb   TrayCallbacks
	quit chan struct{}
}

func NewTray(cb TrayCallbacks, icons map[string][]byte, iconDir string) *Tray {
	return &Tray{cb: cb, quit: make(chan struct{})}
}
func (t *Tray) Run() error                           { <-t.quit; return nil }
func (t *Tray) Update(st TrayState)                  {}
func (t *Tray) Notify(title, text string, warn bool) { fmt.Println("notify:", title, "—", text) }
func (t *Tray) Quit() {
	select {
	case <-t.quit:
	default:
		close(t.quit)
	}
}

// BlockedByAntivirus is Windows-only.
func BlockedByAntivirus(err error) bool { return false }

// RepairDir is Windows-only.
func RepairDir(dir string) error { return nil }

// UserFileDirs: ~/Downloads and ~/Desktop.
func UserFileDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, "Downloads"), filepath.Join(home, "Desktop")}
}

// DefenderState: Windows only.
type DefenderState struct {
	Mode     string
	Active   bool
	Excluded bool
}

// DefenderStatus: Windows only.
func DefenderStatus(dir string) (DefenderState, error) {
	return DefenderState{}, fmt.Errorf("not supported on %s", runtime.GOOS)
}

// StartDetached starts a program that outlives us.
func StartDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(exe)
	return cmd.Start()
}

// SetDNS is used on Android only.
func SetDNS(servers []string) {}
