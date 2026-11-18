//go:build windows

package platform

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// kernel32/user32/shell32/advapi32/ntdll/ole32 are KnownDLLs and always load
// from System32; iphlpapi is not, so it is loaded by absolute path.
var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	moduser32   = syscall.NewLazyDLL("user32.dll")
	modshell32  = syscall.NewLazyDLL("shell32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modntdll    = syscall.NewLazyDLL("ntdll.dll")
	modole32    = syscall.NewLazyDLL("ole32.dll")
	modiphlpapi = syscall.NewLazyDLL(filepath.Join(SystemDir(), "iphlpapi.dll"))

	procGetSystemDirectoryW      = modkernel32.NewProc("GetSystemDirectoryW")
	procGetWindowsDirectoryW     = modkernel32.NewProc("GetSystemWindowsDirectoryW")
	procCreateMutexW             = modkernel32.NewProc("CreateMutexW")
	procCreateJobObjectW         = modkernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = modkernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = modkernel32.NewProc("AssignProcessToJobObject")
	procShellExecuteW            = modshell32.NewProc("ShellExecuteW")
	procSHGetKnownFolderPath     = modshell32.NewProc("SHGetKnownFolderPath")
	procCoTaskMemFree            = modole32.NewProc("CoTaskMemFree")
	procMessageBoxW              = moduser32.NewProc("MessageBoxW")
	procGetShellWindow           = moduser32.NewProc("GetShellWindow")
	procGetWindowThreadProcessID = moduser32.NewProc("GetWindowThreadProcessId")
	procDuplicateTokenEx         = modadvapi32.NewProc("DuplicateTokenEx")
	procCreateProcessWithTokenW  = modadvapi32.NewProc("CreateProcessWithTokenW")
	procRtlGetVersion            = modntdll.NewProc("RtlGetVersion")
	procGetIPForwardTable        = modiphlpapi.NewProc("GetIpForwardTable")
)

var sysDirOnce sync.Once
var sysDir string

// SystemDir returns C:\Windows\System32 (from the API, not the environment).
func SystemDir() string {
	sysDirOnce.Do(func() {
		buf := make([]uint16, 300)
		n, _, _ := procGetSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 || int(n) > len(buf) {
			sysDir = `C:\Windows\System32`
			return
		}
		sysDir = syscall.UTF16ToString(buf[:n])
	})
	return sysDir
}

func windowsDir() string {
	buf := make([]uint16, 300)
	n, _, _ := procGetWindowsDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || int(n) > len(buf) {
		return `C:\Windows`
	}
	return syscall.UTF16ToString(buf[:n])
}

func sysExe(name string) string { return filepath.Join(SystemDir(), name) }

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	folderProgramData  = guid{0x62AB5D82, 0xFDC1, 0x4DC3, [8]byte{0xA9, 0xDD, 0x07, 0x0D, 0x1D, 0x49, 0x5D, 0x97}}
	folderLocalAppData = guid{0xF1B32785, 0x6FBA, 0x4FCF, [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}}
	folderProgramFiles = guid{0x905e63b6, 0xc1bf, 0x494e, [8]byte{0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a}}
	folderProgramX86   = guid{0x7C5A40EF, 0xA0FB, 0x4BFC, [8]byte{0x87, 0x4A, 0xC0, 0xF2, 0xE0, 0xB9, 0xFA, 0x8E}}
	folderDownloads    = guid{0x374DE290, 0x123F, 0x4565, [8]byte{0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}}
	folderDesktop      = guid{0xB4BFCC3A, 0xDB2C, 0x424C, [8]byte{0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41}}
)

// UserFileDirs are the user's Downloads and Desktop: where a file downloaded
// by hand (for example, an engine archive) ends up.
func UserFileDirs() []string {
	var out []string
	for _, id := range []*guid{&folderDownloads, &folderDesktop} {
		if d := knownFolder(id); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func knownFolder(id *guid) string {
	var p *uint16
	r, _, _ := procSHGetKnownFolderPath.Call(uintptr(unsafe.Pointer(id)), 0, 0, uintptr(unsafe.Pointer(&p)))
	if r != 0 || p == nil {
		return ""
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
	return utf16PtrToString(p)
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var s []uint16
	for ptr := unsafe.Pointer(p); ; ptr = unsafe.Add(ptr, 2) {
		c := *(*uint16)(ptr)
		if c == 0 {
			break
		}
		s = append(s, c)
		if len(s) > 32768 {
			break
		}
	}
	return string(utf16.Decode(s))
}

// DataRoot is C:\ProgramData\Lazeyka.
func DataRoot() string {
	pd := knownFolder(&folderProgramData)
	if pd == "" {
		pd = filepath.Join(filepath.VolumeName(windowsDir())+`\`, "ProgramData")
	}
	return filepath.Join(pd, "Lazeyka")
}

// UserUIDir is where the browser UI profile lives (per-user, unelevated).
func UserUIDir() string {
	la := knownFolder(&folderLocalAppData)
	if la == "" {
		la = os.Getenv("LOCALAPPDATA")
	}
	return filepath.Join(la, "Lazeyka", "ui")
}

// IsElevated reports whether the process token is elevated.
func IsElevated() bool {
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	var elevated, ret uint32
	if err := syscall.GetTokenInformation(tok, 20 /* TokenElevation */, (*byte)(unsafe.Pointer(&elevated)), 4, &ret); err != nil {
		return false
	}
	return elevated != 0
}

// RunElevated starts exe with args via UAC ("runas").
func RunElevated(exe, args string) error {
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(args)
	dir, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))
	r, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)), 1)
	if r <= 32 {
		if r == 5 {
			return errors.New("запуск с правами администратора отменён")
		}
		return fmt.Errorf("не удалось запустить с правами администратора (код %d)", r)
	}
	return nil
}

// SingleInstance returns false if another instance holds the mutex.
func SingleInstance(name string) (bool, func()) {
	n, _ := syscall.UTF16PtrFromString(`Local\` + name)
	h, _, err := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(n)))
	if h == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == 5 {
			return false, func() {}
		}
		return true, func() {}
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 183 { // ERROR_ALREADY_EXISTS
		syscall.CloseHandle(syscall.Handle(h))
		return false, func() {}
	}
	return true, func() { syscall.CloseHandle(syscall.Handle(h)) }
}

// --- child processes -------------------------------------------------------

type jobBasicLimit struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobExtendedLimit struct {
	Basic                 jobBasicLimit
	IO                    ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

var (
	jobOnce   sync.Once
	jobHandle uintptr
)

func initJob() {
	h, _, _ := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return
	}
	var info jobExtendedLimit
	info.Basic.LimitFlags = 0x2000 // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	r, _, _ := procSetInformationJobObject.Call(h, 9 /* JobObjectExtendedLimitInformation */, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		syscall.CloseHandle(syscall.Handle(h))
		return
	}
	jobHandle = h
}

// PrepareChild hides the console window of a child process.
func PrepareChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 /* CREATE_NO_WINDOW */}
}

// AttachChild ties a child to our lifetime: it dies when we exit or crash.
func AttachChild(pid int) {
	jobOnce.Do(initJob)
	if jobHandle == 0 {
		return
	}
	ph, err := syscall.OpenProcess(0x0100|0x0001, false, uint32(pid)) // SET_QUOTA | TERMINATE
	if err != nil {
		return
	}
	defer syscall.CloseHandle(ph)
	procAssignProcessToJobObject.Call(jobHandle, uintptr(ph))
}

// run executes a system tool hidden and returns combined output.
func run(timeout time.Duration, exe string, args ...string) (string, int, error) {
	cmd := exec.Command(exe, args...)
	PrepareChild(cmd)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		<-done
		return string(out), -1, fmt.Errorf("%s: истекло время ожидания", filepath.Base(exe))
	}
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			return string(out), -1, err
		}
	}
	return string(out), code, nil
}

// --- system info -----------------------------------------------------------

type osVersionInfoEx struct {
	Size             uint32
	Major, Minor     uint32
	Build, Platform  uint32
	CSDVersion       [128]uint16
	SPMajor, SPMinor uint16
	SuiteMask        uint16
	ProductType      byte
	Reserved         byte
}

// OSVersion returns "10.0.22631".
func OSVersion() string {
	var v osVersionInfoEx
	v.Size = uint32(unsafe.Sizeof(v))
	procRtlGetVersion.Call(uintptr(unsafe.Pointer(&v)))
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
}

// MachineID returns the Windows MachineGuid.
func MachineID() string {
	var hk syscall.Handle
	sub, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, sub, 0, syscall.KEY_READ|0x0100, &hk); err != nil {
		return ""
	}
	defer syscall.RegCloseKey(hk)
	name, _ := syscall.UTF16PtrFromString("MachineGuid")
	buf := make([]uint16, 128)
	n := uint32(len(buf) * 2)
	var typ uint32
	if err := syscall.RegQueryValueEx(hk, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// currentAccount returns DOMAIN\user of the process owner ("" if unknown).
func currentAccount() string {
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return ""
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	acc, dom, _, err := u.User.Sid.LookupAccount("")
	if err != nil || acc == "" {
		return ""
	}
	if dom == "" {
		return acc
	}
	return dom + `\` + acc
}

// CurrentUserSID returns the SID of the process owner.
func CurrentUserSID() (string, error) {
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return "", err
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String()
}

// ipv4Routes reads the IPv4 routing table.
func ipv4Routes() []route4 {
	var size uint32
	procGetIPForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	for try := 0; try < 3 && size > 0; try++ {
		size += 10 * 56 // routes may appear between the two calls
		buf := make([]byte, size)
		r, _, _ := procGetIPForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
		switch r {
		case 0:
			return parseForwardTable(buf)
		case 122: // ERROR_INSUFFICIENT_BUFFER: size now holds what is needed
			continue
		default:
			return nil
		}
	}
	return nil
}

// DefaultRoutes lists the interfaces that are up and have an IPv4 default
// route, best first, leaving out the interface named exclude (our TUN).
func DefaultRoutes(exclude string) []RouteIface {
	skip := -1
	if exclude != "" {
		if ifc, err := net.InterfaceByName(exclude); err == nil {
			skip = ifc.Index
		}
	}
	return defaultRoutes(ipv4Routes(), skip, interfaceInfo, interfaceMetric)
}

// DefaultRouteIfIndex returns the interface mihomo binds the VPN's own
// connections to: the best default route that is not a VPN adapter (the same
// choice mihomo's "auto-detect-interface" makes), ignoring our TUN.
func DefaultRouteIfIndex(exclude string) int {
	for _, r := range DefaultRoutes(exclude) {
		if r.Bindable() {
			return r.Index
		}
	}
	return 0
}

// mibIfRow2 mirrors MIB_IF_ROW2 (netioapi.h, 1352 bytes on 64-bit Windows).
type mibIfRow2 struct {
	InterfaceLUID               uint64
	InterfaceIndex              uint32
	InterfaceGUID               [16]byte
	Alias                       [257]uint16
	Description                 [257]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [32]byte
	PermanentPhysicalAddress    [32]byte
	MTU                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags uint8
	OperStatus                  uint32
	AdminStatus                 uint32
	MediaConnectState           uint32
	NetworkGUID                 [16]byte
	ConnectionType              uint32
	Counters                    [20]uint64 // link speeds and traffic counters
}

var procGetIfEntry2 = modiphlpapi.NewProc("GetIfEntry2")

// interfaceInfo returns an interface's name, IANA type and whether it is up.
func interfaceInfo(ifIdx uint32) (string, uint32, bool) {
	var row mibIfRow2
	if unsafe.Sizeof(row) == 1352 && unsafe.Offsetof(row.Type) == 1128 && unsafe.Offsetof(row.OperStatus) == 1156 {
		row.InterfaceIndex = ifIdx
		if r, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&row))); r == 0 {
			return syscall.UTF16ToString(row.Alias[:]), row.Type, row.OperStatus == 1 // IfOperStatusUp
		}
	}
	ifc, err := net.InterfaceByIndex(int(ifIdx))
	if err != nil {
		return "", 0, false
	}
	return ifc.Name, 0, ifc.Flags&net.FlagUp != 0
}

// mibIPInterfaceRow mirrors MIB_IPINTERFACE_ROW (netioapi.h, 168 bytes on
// 64-bit Windows; Go's alignment rules match C's for these field types).
type mibIPInterfaceRow struct {
	Family                               uint16
	InterfaceLUID                        uint64
	InterfaceIndex                       uint32
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   bool
	ForwardingEnabled                    bool
	WeakHostSend                         bool
	WeakHostReceive                      bool
	UseAutomaticMetric                   bool
	UseNeighborUnreachabilityDetection   bool
	ManagedAddressConfigurationSupported bool
	OtherStatefulConfigurationSupported  bool
	AdvertiseDefaultRoute                bool
	RouterDiscoveryBehavior              int32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMTUDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             int32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [16]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NlMtu                                uint32
	Connected                            bool
	SupportsWakeUpPatterns               bool
	SupportsNeighborDiscovery            bool
	SupportsRouterDiscovery              bool
	ReachableTime                        uint32
	TransmitOffload                      uint8
	ReceiveOffload                       uint8
	DisableDefaultRoutes                 bool
}

var (
	procInitializeIPInterfaceEntry = modiphlpapi.NewProc("InitializeIpInterfaceEntry")
	procGetIPInterfaceEntry        = modiphlpapi.NewProc("GetIpInterfaceEntry")
)

// interfaceMetric is the IPv4 interface metric (0 if unknown).
func interfaceMetric(ifIdx uint32) uint32 {
	var row mibIPInterfaceRow
	if unsafe.Sizeof(row) != 168 || unsafe.Offsetof(row.Metric) != 148 {
		return 0 // layout mismatch: better no metric than a wrong one
	}
	procInitializeIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.Family = 2 // AF_INET
	row.InterfaceIndex = ifIdx
	if r, _, _ := procGetIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
		return 0
	}
	return row.Metric
}

// InterfaceHostModel reads the IPv4 settings of an interface.
func InterfaceHostModel(ifIdx int) (HostModel, bool) {
	var row mibIPInterfaceRow
	if ifIdx <= 0 || unsafe.Sizeof(row) != 168 || unsafe.Offsetof(row.ForwardingEnabled) != 41 {
		return HostModel{}, false
	}
	procInitializeIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.Family = 2 // AF_INET
	row.InterfaceIndex = uint32(ifIdx)
	if r, _, _ := procGetIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
		return HostModel{}, false
	}
	hm := HostModel{Index: ifIdx, Forwarding: row.ForwardingEnabled, WeakSend: row.WeakHostSend, WeakRecv: row.WeakHostReceive}
	if ifc, err := net.InterfaceByIndex(ifIdx); err == nil {
		hm.Name = ifc.Name
	}
	return hm, true
}

var procSetIPInterfaceEntry = modiphlpapi.NewProc("SetIpInterfaceEntry")

// SetHostFlags switches IPv4 forwarding and weak host send of an interface
// (nil leaves a flag as it is). Needs administrator rights.
func SetHostFlags(ifIdx int, forwarding, weakSend *bool) error {
	var row mibIPInterfaceRow
	if ifIdx <= 0 || unsafe.Sizeof(row) != 168 || unsafe.Offsetof(row.ForwardingEnabled) != 41 || unsafe.Offsetof(row.SitePrefixLength) != 144 {
		return errors.New("неизвестная раскладка MIB_IPINTERFACE_ROW")
	}
	procInitializeIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.Family = 2 // AF_INET
	row.InterfaceIndex = uint32(ifIdx)
	if r, _, _ := procGetIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
		return syscall.Errno(r)
	}
	if forwarding != nil {
		row.ForwardingEnabled = *forwarding
	}
	if weakSend != nil {
		row.WeakHostSend = *weakSend
	}
	// SetIpInterfaceEntry rejects an IPv4 row with a site prefix length
	// (ERROR_INVALID_PARAMETER), and GetIpInterfaceEntry fills one in
	row.SitePrefixLength = 0
	if r, _, _ := procSetIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// IPEnableRouter is the system-wide IPv4 routing switch (1 = the computer
// forwards packets between all its interfaces).
func IPEnableRouter() (uint32, bool) {
	var key syscall.Handle
	path, _ := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`)
	if syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_READ, &key) != nil {
		return 0, false
	}
	defer syscall.RegCloseKey(key)
	name, _ := syscall.UTF16PtrFromString("IPEnableRouter")
	var typ, val, size uint32 = 0, 0, 4
	if syscall.RegQueryValueEx(key, name, nil, &typ, (*byte)(unsafe.Pointer(&val)), &size) != nil || typ != syscall.REG_DWORD {
		return 0, false
	}
	return val, true
}

// --- UI ----------------------------------------------------------------------

// MessageBox shows a blocking message box.
func MessageBox(title, text string, isError bool) {
	t, _ := syscall.UTF16PtrFromString(title)
	m, _ := syscall.UTF16PtrFromString(text)
	flags := uintptr(0x40 | 0x10000) // MB_ICONINFORMATION | MB_SETFOREGROUND
	if isError {
		flags = 0x10 | 0x10000
	}
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags)
}

func findBrowser() string {
	var cands []string
	for _, base := range []string{knownFolder(&folderProgramX86), knownFolder(&folderProgramFiles)} {
		if base == "" {
			continue
		}
		cands = append(cands,
			filepath.Join(base, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(base, `Google\Chrome\Application\chrome.exe`),
		)
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func quoteArg(s string) string { return syscall.EscapeArg(s) }

// OpenUI opens url in an app-style Edge window running without admin rights.
func OpenUI(url string) error {
	if br := findBrowser(); br != "" {
		args := []string{
			"--app=" + url,
			"--user-data-dir=" + UserUIDir(),
			"--no-first-run",
			"--no-default-browser-check",
			"--window-size=1120,800",
		}
		cl := quoteArg(br)
		for _, a := range args {
			cl += " " + quoteArg(a)
		}
		if err := startUnelevated(br, cl); err == nil {
			return nil
		}
	}
	// Fallback: the default browser through Explorer (also unelevated).
	cmd := exec.Command(filepath.Join(windowsDir(), "explorer.exe"), url)
	return cmd.Start()
}

// startUnelevated launches a process with the desktop shell's token, so a
// browser never runs with our administrator rights.
func startUnelevated(app, cmdline string) error {
	shell, _, _ := procGetShellWindow.Call()
	if shell == 0 {
		return errors.New("оболочка Windows не найдена")
	}
	var pid uint32
	procGetWindowThreadProcessID.Call(shell, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return errors.New("не найден процесс оболочки")
	}
	hp, err := syscall.OpenProcess(0x1000 /* QUERY_LIMITED_INFORMATION */, false, pid)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(hp)
	var tok syscall.Token
	if err := syscall.OpenProcessToken(hp, syscall.TOKEN_DUPLICATE, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var dup syscall.Handle
	const access = 0x0001 | 0x0002 | 0x0008 | 0x0080 | 0x0100
	r, _, e := procDuplicateTokenEx.Call(uintptr(tok), access, 0, 2, 1, uintptr(unsafe.Pointer(&dup)))
	if r == 0 {
		return e
	}
	defer syscall.CloseHandle(dup)
	cl, err := syscall.UTF16FromString(cmdline)
	if err != nil {
		return err
	}
	appName, _ := syscall.UTF16PtrFromString(app)
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	r, _, e = procCreateProcessWithTokenW.Call(uintptr(dup), 0, uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(&cl[0])), 0, 0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return e
	}
	syscall.CloseHandle(pi.Thread)
	syscall.CloseHandle(pi.Process)
	return nil
}

// --- scheduled tasks ---------------------------------------------------------

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func taskXML(exe, args, sid string, logon bool) []byte {
	triggers := ""
	if logon {
		// the logon trigger is documented with "DOMAIN\user"; the principal takes the SID
		who := currentAccount()
		if who == "" {
			who = sid
		}
		triggers = `<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + xmlEscape(who) + `</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>`
	}
	x := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Лазейка: запуск с правами администратора без запроса UAC</Description></RegistrationInfo>
  ` + triggers + `
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlEscape(sid) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEscape(exe) + `</Command>
      <Arguments>` + xmlEscape(args) + `</Arguments>
      <WorkingDirectory>` + xmlEscape(filepath.Dir(exe)) + `</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`
	u := utf16.Encode([]rune(x))
	out := make([]byte, 2+len(u)*2)
	out[0], out[1] = 0xFF, 0xFE
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2+i*2:], c)
	}
	return out
}

func createTask(name, exe, args, sid string, logon bool, tmpDir string) error {
	f := filepath.Join(tmpDir, "task-"+strconv.Itoa(os.Getpid())+".xml")
	if err := os.WriteFile(f, taskXML(exe, args, sid, logon), 0o600); err != nil {
		return err
	}
	defer os.Remove(f)
	out, code, err := run(30*time.Second, sysExe("schtasks.exe"), "/Create", "/TN", name, "/XML", f, "/F")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("schtasks /Create %s: код %d: %s", name, code, strings.TrimSpace(out))
	}
	return nil
}

// InstallTasks registers the on-demand task (and the logon one if autostart).
func InstallTasks(exe string, autostart bool, tmpDir string) error {
	sid, err := CurrentUserSID()
	if err != nil {
		return err
	}
	if err := createTask(TaskMain, exe, "--show", sid, false, tmpDir); err != nil {
		return err
	}
	return SetAutostart(exe, autostart, tmpDir)
}

// SetAutostart creates or removes the logon task.
func SetAutostart(exe string, on bool, tmpDir string) error {
	if !on {
		run(15*time.Second, sysExe("schtasks.exe"), "/Delete", "/TN", TaskAutostart, "/F")
		return nil
	}
	sid, err := CurrentUserSID()
	if err != nil {
		return err
	}
	return createTask(TaskAutostart, exe, "--autostart", sid, true, tmpDir)
}

// RunTask starts a scheduled task (works without admin rights).
func RunTask(name string) error {
	out, code, err := run(15*time.Second, sysExe("schtasks.exe"), "/Run", "/TN", name)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("schtasks /Run: код %d: %s", code, strings.TrimSpace(out))
	}
	return nil
}

// TaskExists reports whether a task is registered.
func TaskExists(name string) bool {
	_, code, err := run(15*time.Second, sysExe("schtasks.exe"), "/Query", "/TN", name)
	return err == nil && code == 0
}

// RemoveTasks deletes both tasks.
func RemoveTasks() {
	for _, n := range []string{TaskAutostart, TaskMain} {
		run(15*time.Second, sysExe("schtasks.exe"), "/Delete", "/TN", n, "/F")
	}
}

// --- install helpers ----------------------------------------------------------

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func powershell(script string) error {
	_, err := powershellOut(60*time.Second, script)
	return err
}

// powershellOut runs a script and returns what it printed.
func powershellOut(timeout time.Duration, script string) (string, error) {
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	ps := filepath.Join(SystemDir(), `WindowsPowerShell\v1.0\powershell.exe`)
	out, code, err := run(timeout, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	if err != nil {
		return out, err
	}
	if code != 0 {
		return out, fmt.Errorf("powershell: код %d: %s", code, strings.TrimSpace(out))
	}
	return out, nil
}

// SharedConnections lists the connections with Internet Connection Sharing
// on: the shared one (public) and the one it is shared to (private; the
// mobile hotspot shares this way too).
func SharedConnections() (public, private []string, err error) {
	const script = `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false
$ErrorActionPreference = 'SilentlyContinue'
$m = New-Object -ComObject HNetCfg.HNetShare
foreach ($c in $m.EnumEveryConnection) {
  $cfg = $m.INetSharingConfigurationForINetConnection.Invoke($c)
  if ($cfg.SharingEnabled) {
    ('{0}' + [char]9 + '{1}') -f $cfg.SharingConnectionType, $m.NetConnectionProps.Invoke($c).Name
  }
}`
	out, err := powershellOut(20*time.Second, script)
	if err != nil {
		return nil, nil, err
	}
	for _, line := range strings.Split(out, "\n") {
		kind, name, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "\ufeff")), "\t")
		if !ok || name == "" {
			continue
		}
		if kind == "0" { // ICSSHARINGTYPE_PUBLIC
			public = append(public, name)
		} else {
			private = append(private, name)
		}
	}
	return public, private, nil
}

// CreateShortcuts adds Start menu and desktop shortcuts.
func CreateShortcuts(exe, icon string) error {
	script := `$ws = New-Object -ComObject WScript.Shell
$paths = @(
  (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Лазейка.lnk'),
  (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Лазейка.lnk')
)
foreach ($p in $paths) {
  $s = $ws.CreateShortcut($p)
  $s.TargetPath = ` + psQuote(exe) + `
  $s.Arguments = '--show'
  $s.WorkingDirectory = ` + psQuote(filepath.Dir(exe)) + `
  $s.IconLocation = ` + psQuote(icon+",0") + `
  $s.Description = 'Лазейка — VPN и обход блокировок'
  $s.Save()
}`
	return powershell(script)
}

// RemoveShortcuts deletes the shortcuts.
func RemoveShortcuts() {
	powershell(`foreach ($p in @((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Лазейка.lnk'), (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Лазейка.lnk'))) { Remove-Item -LiteralPath $p -ErrorAction SilentlyContinue }`)
}

// HardenDir locks the folder down: SYSTEM and Administrators full control,
// optionally Users read & execute, nothing else. Then the elevated app cannot
// be tricked into running or loading a file someone else planted there.
//
// Only the folder itself gets explicit entries. Everything inside is reset to
// plain inheritance and follows it: putting "(OI)(CI)" grants on files with
// /T fails for files, and together with /inheritance:r that left files with an
// empty ACL that nobody, not even the app, could open (0.1.1).
func HardenDir(dir string, usersRead bool) error {
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s: не обычная папка", dir) // never follow a link with /T
	}
	icacls := sysExe("icacls.exe")
	// Administrators own everything; explicit entries anyone added inside are
	// dropped, so the whole tree inherits from the folder.
	run(120*time.Second, icacls, dir, "/setowner", "*S-1-5-32-544", "/T", "/C", "/L", "/Q")
	if out, code, err := run(120*time.Second, icacls, dir, "/reset", "/T", "/C", "/L", "/Q"); err != nil || code != 0 {
		return fmt.Errorf("icacls /reset: код %d: %v %s", code, err, strings.TrimSpace(out))
	}
	args := []string{dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"}
	if usersRead {
		args = append(args, "*S-1-5-32-545:(OI)(CI)RX")
	}
	args = append(args, "/C", "/L", "/Q") // the folder only; children inherit
	out, code, err := run(120*time.Second, icacls, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("icacls: код %d: %s", code, strings.TrimSpace(out))
	}
	// once more: anything created while the tree briefly inherited from
	// ProgramData (where users may create files) ends up owned by admins too
	run(120*time.Second, icacls, dir, "/setowner", "*S-1-5-32-544", "/T", "/C", "/L", "/Q")
	return nil
}

// RepairDir is the fallback when HardenDir went wrong: every entry inside
// goes back to plain inheritance from the folder, so files can be opened again.
func RepairDir(dir string) error {
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s: не обычная папка", dir)
	}
	out, code, err := run(120*time.Second, sysExe("icacls.exe"), filepath.Join(dir, "*"), "/reset", "/T", "/C", "/L", "/Q")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("icacls /reset: код %d: %s", code, strings.TrimSpace(out))
	}
	return nil
}

// --- services and processes ---------------------------------------------------

// Service queries a Windows service.
func Service(name string) ServiceInfo {
	out, code, err := run(10*time.Second, sysExe("sc.exe"), "query", name)
	if err != nil || code != 0 {
		return ServiceInfo{}
	}
	return ServiceInfo{Exists: true, Running: strings.Contains(out, "RUNNING") || strings.Contains(out, ": 4 ")}
}

// StopDeleteService stops and removes a service.
func StopDeleteService(name string) {
	run(20*time.Second, sysExe("sc.exe"), "stop", name)
	time.Sleep(500 * time.Millisecond)
	run(20*time.Second, sysExe("sc.exe"), "delete", name)
}

// ProcessPIDs lists PIDs of processes with the given image name.
func ProcessPIDs(image string) []int {
	out, _, err := run(15*time.Second, sysExe("tasklist.exe"), "/FI", "IMAGENAME eq "+image, "/FO", "CSV", "/NH")
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), `","`)
		if len(f) < 2 || !strings.EqualFold(strings.Trim(f[0], `"`), image) {
			continue
		}
		if pid, err := strconv.Atoi(strings.Trim(f[1], `"`)); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// KillPID force-kills a process.
func KillPID(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
		_ = p.Release()
	}
}

// StartDetached starts a program that must outlive us (an update that
// installs itself after we quit): outside any job we may be in, if allowed.
func StartDetached(exe string, args ...string) error {
	var err error
	for _, flags := range []uint32{0x01000000 | 0x00000200, 0x00000200} { // BREAKAWAY_FROM_JOB | NEW_PROCESS_GROUP
		cmd := exec.Command(exe, args...)
		cmd.Dir = filepath.Dir(exe)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
		if err = cmd.Start(); err == nil {
			_ = cmd.Process.Release()
			return nil
		}
	}
	return err
}

var procMoveFileExW = modkernel32.NewProc("MoveFileExW")

// DeleteLater removes folders: everything it can now, and what is still
// in use (our own exe, an open log) when Windows restarts — the way
// installers do it (MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT). It
// returns how many entries wait for the restart.
func DeleteLater(dirs ...string) int {
	pending := 0
	for _, d := range dirs {
		if len(d) < 10 { // never "C:\" or similar
			continue
		}
		if err := os.RemoveAll(d); err == nil {
			continue
		}
		// what is left is in use: files first, then the folders, deepest first
		var files, folders []string
		filepath.WalkDir(d, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				folders = append(folders, path)
			} else {
				files = append(files, path) // links are removed, never followed
			}
			return nil
		})
		for i := len(folders) - 1; i >= 0; i-- {
			files = append(files, folders[i])
		}
		for _, f := range files {
			if os.Remove(f) == nil {
				continue
			}
			p, err := syscall.UTF16PtrFromString(f)
			if err != nil {
				continue
			}
			if r, _, _ := procMoveFileExW.Call(uintptr(unsafe.Pointer(p)), 0, 0x4 /* MOVEFILE_DELAY_UNTIL_REBOOT */); r != 0 {
				pending++
			}
		}
	}
	return pending
}

// --- Microsoft Defender ------------------------------------------------------

// DefenderState: whether Microsoft Defender scans a folder.
type DefenderState struct {
	Mode     string // AMRunningMode: "Normal", "Passive Mode" (another antivirus is in charge)…
	Active   bool   // Defender is the antivirus in charge
	Excluded bool   // the folder is in its exclusions
}

// psPlain runs a short ASCII command (no encoding, nothing hidden).
func psPlain(timeout time.Duration, command string) (string, error) {
	ps := filepath.Join(SystemDir(), `WindowsPowerShell\v1.0\powershell.exe`)
	out, code, err := run(timeout, ps, "-NoProfile", "-NonInteractive", "-Command", command)
	if err != nil {
		return out, err
	}
	if code != 0 {
		return out, fmt.Errorf("powershell: код %d: %s", code, strings.TrimSpace(out))
	}
	return out, nil
}

// DefenderStatus asks Defender about a folder (needs administrator rights:
// the exclusion list is hidden from other users).
func DefenderStatus(dir string) (DefenderState, error) {
	out, err := psPlain(30*time.Second, "$s = Get-MpComputerStatus -ErrorAction Stop; 'mode=' + $s.AMRunningMode; "+
		"foreach ($e in (Get-MpPreference -ErrorAction Stop).ExclusionPath) { 'path=' + $e }")
	if err != nil {
		return DefenderState{}, err
	}
	var st DefenderState
	want := strings.TrimRight(filepath.Clean(dir), `\`)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "mode="); ok {
			st.Mode = v
		}
		if v, ok := strings.CutPrefix(line, "path="); ok && strings.EqualFold(strings.TrimRight(filepath.Clean(v), `\`), want) {
			st.Excluded = true
		}
	}
	// "Normal" and "EDR Block Mode" scan; passive and SxS passive do not
	st.Active = st.Mode == "" || !strings.Contains(strings.ToLower(st.Mode), "passive")
	return st, nil
}

// Лазейка only reads Defender's state (DefenderStatus) to show the user
// whether its folder is excluded; it never changes Defender's settings. The
// user adds the exclusion themselves if they want one — a program that
// silently turns off its own antivirus checks is exactly what Defender treats
// as a sign of malware, so doing it would make flags more likely, not fewer.

// BlockedByAntivirus reports a write refused or undone by Defender & co
// (ERROR_VIRUS_INFECTED, ERROR_VIRUS_DELETED).
func BlockedByAntivirus(err error) bool {
	return errors.Is(err, syscall.Errno(225)) || errors.Is(err, syscall.Errno(226))
}

// IsWindows is true on Windows.
const IsWindows = true

// IsAndroid is true in the Android build.
const IsAndroid = false

// SetDNS is used on Android only.
func SetDNS(servers []string) {}
