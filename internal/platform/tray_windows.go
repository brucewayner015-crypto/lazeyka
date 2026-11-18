//go:build windows

package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	procRegisterClassExW         = moduser32.NewProc("RegisterClassExW")
	procCreateWindowExW          = moduser32.NewProc("CreateWindowExW")
	procDefWindowProcW           = moduser32.NewProc("DefWindowProcW")
	procDestroyWindow            = moduser32.NewProc("DestroyWindow")
	procGetMessageW              = moduser32.NewProc("GetMessageW")
	procTranslateMessage         = moduser32.NewProc("TranslateMessage")
	procDispatchMessageW         = moduser32.NewProc("DispatchMessageW")
	procPostMessageW             = moduser32.NewProc("PostMessageW")
	procPostQuitMessage          = moduser32.NewProc("PostQuitMessage")
	procRegisterWindowMessageW   = moduser32.NewProc("RegisterWindowMessageW")
	procChangeWindowMessageFilEx = moduser32.NewProc("ChangeWindowMessageFilterEx")
	procCreatePopupMenu          = moduser32.NewProc("CreatePopupMenu")
	procAppendMenuW              = moduser32.NewProc("AppendMenuW")
	procSetMenuDefaultItem       = moduser32.NewProc("SetMenuDefaultItem")
	procTrackPopupMenu           = moduser32.NewProc("TrackPopupMenu")
	procDestroyMenu              = moduser32.NewProc("DestroyMenu")
	procGetCursorPos             = moduser32.NewProc("GetCursorPos")
	procSetForegroundWindow      = moduser32.NewProc("SetForegroundWindow")
	procLoadImageW               = moduser32.NewProc("LoadImageW")
	procGetSystemMetrics         = moduser32.NewProc("GetSystemMetrics")
	procShellNotifyIconW         = modshell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandleW         = modkernel32.NewProc("GetModuleHandleW")
)

const (
	wmNull            = 0x0000
	wmDestroy         = 0x0002
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEndSession      = 0x0016
	wmContextMenu     = 0x007B
	wmLButtonUp       = 0x0202
	wmLButtonDblClk   = 0x0203
	wmRButtonUp       = 0x0205
	wmApp             = 0x8000
	wmTray            = wmApp + 1
	wmUpdate          = wmApp + 2
	wmBalloon         = wmApp + 3

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2
	nifMsg    = 0x01
	nifIcon   = 0x02
	nifTip    = 0x04
	nifInfo   = 0x10

	mfString    = 0x0000
	mfGrayed    = 0x0001
	mfChecked   = 0x0008
	mfPopup     = 0x0010
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmNoNotify    = 0x0080
	tpmReturnCmd   = 0x0100

	idOpen   = 1
	idVPN    = 2
	idZapret = 3
	idQuit   = 4
	idUpdate = 5

	idAutoStrategy = 2999
	idServerBase   = 1000 // + item number
	idStrategyBase = 3000
	maxSubItems    = 120
)

// trayPick is what a submenu line stands for.
type trayPick struct {
	strategy bool
	key      string
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type point struct{ X, Y int32 }

type winMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type notifyIconData struct {
	Size            uint32
	Wnd             uintptr
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            uintptr
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        guid
	BalloonIcon     uintptr
}

// Tray is the notification-area icon with its menu.
type Tray struct {
	cb      TrayCallbacks
	mu      sync.Mutex
	state   TrayState
	balloon [2]string
	warn    bool
	hwnd    uintptr
	icons   map[string]uintptr
	cls     *uint16
	ready   chan struct{}
	added   bool
}

var (
	theTray        *Tray
	taskbarCreated uint32
	wndProcCB      = syscall.NewCallback(func(hwnd, msg, wparam, lparam uintptr) uintptr {
		if theTray == nil {
			r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
			return r
		}
		return theTray.wndProc(hwnd, uint32(msg), wparam, lparam)
	})
)

// NewTray prepares a tray icon; icons maps mode ("on","off","busy","err") to .ico bytes.
func NewTray(cb TrayCallbacks, icons map[string][]byte, iconDir string) *Tray {
	t := &Tray{cb: cb, icons: map[string]uintptr{}, ready: make(chan struct{})}
	os.MkdirAll(iconDir, 0o755)
	cx, _, _ := procGetSystemMetrics.Call(49) // SM_CXSMICON
	cy, _, _ := procGetSystemMetrics.Call(50)
	for mode, data := range icons {
		p := filepath.Join(iconDir, "tray-"+mode+".ico")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			continue
		}
		pp, _ := syscall.UTF16PtrFromString(p)
		h, _, _ := procLoadImageW.Call(0, uintptr(unsafe.Pointer(pp)), 1 /* IMAGE_ICON */, cx, cy, 0x10 /* LR_LOADFROMFILE */)
		if h != 0 {
			t.icons[mode] = h
		}
	}
	t.state = TrayState{Mode: "off", Tip: "Лазейка", Status: "Лазейка"}
	return t
}

// Run creates the hidden window and pumps messages until Quit. It must run
// on its own goroutine; it locks the OS thread.
func (t *Tray) Run() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	theTray = t
	hinst, _, _ := procGetModuleHandleW.Call(0)
	t.cls, _ = syscall.UTF16PtrFromString("LazeykaTrayWindow")
	wc := wndClassEx{WndProc: wndProcCB, Instance: hinst, ClassName: t.cls}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		close(t.ready)
		return fmt.Errorf("RegisterClassEx: %v", err)
	}
	title, _ := syscall.UTF16PtrFromString("Лазейка")
	hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(t.cls)), uintptr(unsafe.Pointer(title)),
		0, 0, 0, 0, 0, 0, 0, hinst, 0)
	if hwnd == 0 {
		close(t.ready)
		return fmt.Errorf("CreateWindowEx: %v", err)
	}
	t.mu.Lock()
	t.hwnd = hwnd
	t.mu.Unlock()
	tc, _ := syscall.UTF16PtrFromString("TaskbarCreated")
	r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tc)))
	taskbarCreated = uint32(r)
	// We run elevated; let Explorer (medium integrity) reach our window.
	for _, m := range []uint32{taskbarCreated, wmTray} {
		procChangeWindowMessageFilEx.Call(hwnd, uintptr(m), 1 /* MSGFLT_ALLOW */, 0)
	}
	t.addIcon()
	close(t.ready)
	var m winMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	return nil
}

// Update changes icon, tooltip and menu state (safe from any goroutine).
func (t *Tray) Update(st TrayState) {
	t.mu.Lock()
	t.state = st
	h := t.hwnd
	t.mu.Unlock()
	if h != 0 {
		procPostMessageW.Call(h, wmUpdate, 0, 0)
	}
}

// Notify shows a balloon/toast.
func (t *Tray) Notify(title, text string, warn bool) {
	t.mu.Lock()
	t.balloon = [2]string{title, text}
	t.warn = warn
	h := t.hwnd
	t.mu.Unlock()
	if h != 0 {
		procPostMessageW.Call(h, wmBalloon, 0, 0)
	}
}

// Quit removes the icon and ends Run.
func (t *Tray) Quit() {
	t.mu.Lock()
	h := t.hwnd
	t.mu.Unlock()
	if h != 0 {
		procPostMessageW.Call(h, wmClose, 0, 0)
	}
}

func copyUTF16(dst []uint16, s string) {
	u, _ := syscall.UTF16FromString(s)
	if len(u) > len(dst) {
		u = u[:len(dst)]
		u[len(u)-1] = 0
	}
	copy(dst, u)
}

func (t *Tray) nid() notifyIconData {
	var n notifyIconData
	n.Size = uint32(unsafe.Sizeof(n))
	n.Wnd = t.hwnd
	n.ID = 1
	return n
}

func (t *Tray) addIcon() {
	t.mu.Lock()
	st := t.state
	t.mu.Unlock()
	n := t.nid()
	n.Flags = nifMsg | nifIcon | nifTip
	n.CallbackMessage = wmTray
	n.Icon = t.iconFor(st.Mode)
	copyUTF16(n.Tip[:], st.Tip)
	r, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&n)))
	t.added = r != 0
}

func (t *Tray) iconFor(mode string) uintptr {
	if h, ok := t.icons[mode]; ok {
		return h
	}
	return t.icons["off"]
}

func (t *Tray) apply() {
	t.mu.Lock()
	st := t.state
	t.mu.Unlock()
	if !t.added {
		t.addIcon()
		return
	}
	n := t.nid()
	n.Flags = nifIcon | nifTip
	n.Icon = t.iconFor(st.Mode)
	copyUTF16(n.Tip[:], st.Tip)
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&n)))
}

func (t *Tray) showBalloon() {
	t.mu.Lock()
	b, warn := t.balloon, t.warn
	t.mu.Unlock()
	n := t.nid()
	n.Flags = nifInfo
	copyUTF16(n.InfoTitle[:], b[0])
	copyUTF16(n.Info[:], b[1])
	n.InfoFlags = 1 // NIIF_INFO
	if warn {
		n.InfoFlags = 2 // NIIF_WARNING
	}
	procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&n)))
}

func appendMenu(h uintptr, flags uint32, id int, text string) {
	if flags&mfSeparator != 0 {
		procAppendMenuW.Call(h, uintptr(flags), 0, 0)
		return
	}
	p, _ := syscall.UTF16PtrFromString(text)
	procAppendMenuW.Call(h, uintptr(flags), uintptr(id), uintptr(unsafe.Pointer(p)))
}

// appendPopup adds a submenu (DestroyMenu of the parent frees it too).
func appendPopup(h, sub uintptr, text string) {
	p, _ := syscall.UTF16PtrFromString(text)
	procAppendMenuW.Call(h, mfString|mfPopup, sub, uintptr(unsafe.Pointer(p)))
}

// menuText escapes "&" (an accelerator mark in menus) and puts the note
// after a tab, which menus align to the right.
func menuText(label, note string) string {
	t := strings.ReplaceAll(label, "&", "&&")
	if note != "" {
		t += "\t" + strings.ReplaceAll(note, "&", "&&")
	}
	return t
}

// subMenu builds a submenu of choices; picks maps the item ids back.
func subMenu(items []TrayItem, note string, base int, strategy bool, picks map[int]trayPick, top func(h uintptr)) uintptr {
	h, _, _ := procCreatePopupMenu.Call()
	if h == 0 {
		return 0
	}
	if top != nil {
		top(h)
	}
	if len(items) == 0 {
		if note != "" {
			appendMenu(h, mfString|mfGrayed, 0, menuText(note, ""))
		}
		return h
	}
	n := 0
	for _, it := range items {
		switch {
		case it.Separator:
			appendMenu(h, mfSeparator, 0, "")
		case it.Caption:
			appendMenu(h, mfString|mfGrayed, 0, menuText(it.Label, it.Note))
		default:
			if n >= maxSubItems {
				continue
			}
			id := base + n
			n++
			flags := uint32(mfString)
			if it.Checked {
				flags |= mfChecked
			}
			appendMenu(h, flags, id, menuText(it.Label, it.Note))
			picks[id] = trayPick{strategy: strategy, key: it.Key}
		}
	}
	return h
}

func (t *Tray) showMenu() {
	t.mu.Lock()
	st := t.state
	t.mu.Unlock()
	var ch TrayChoices
	if t.cb.Choices != nil {
		ch = t.cb.Choices()
	}
	h, _, _ := procCreatePopupMenu.Call()
	if h == 0 {
		return
	}
	defer procDestroyMenu.Call(h)
	picks := map[int]trayPick{}
	appendMenu(h, mfString|mfGrayed, 100, menuText(st.Status, ""))
	appendMenu(h, mfSeparator, 0, "")
	appendMenu(h, mfString, idOpen, "Открыть Лазейку")
	if ch.Update != "" {
		appendMenu(h, mfString, idUpdate, menuText("Обновить Лазейку до "+ch.Update, ""))
	}
	vpn := uint32(mfString)
	if st.VPNOn {
		vpn |= mfChecked
	}
	appendMenu(h, vpn, idVPN, "VPN и маршрутизация")
	if sub := subMenu(ch.Servers, ch.ServersNote, idServerBase, false, picks, nil); sub != 0 {
		appendPopup(h, sub, "Сервер для заблокированного")
	}
	zap := uint32(mfString)
	if st.ZapretOn {
		zap |= mfChecked
	}
	appendMenu(h, zap, idZapret, "zapret (YouTube, Discord)")
	top := func(sh uintptr) {
		if ch.CanAutoPick {
			appendMenu(sh, mfString, idAutoStrategy, "Подобрать автоматически")
			if len(ch.Strategies) > 0 {
				appendMenu(sh, mfSeparator, 0, "")
			}
		}
	}
	if sub := subMenu(ch.Strategies, ch.StrategiesNote, idStrategyBase, true, picks, top); sub != 0 {
		appendPopup(h, sub, "Стратегия zapret")
	}
	appendMenu(h, mfSeparator, 0, "")
	appendMenu(h, mfString, idQuit, "Выход")
	procSetMenuDefaultItem.Call(h, idOpen, 0)
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(t.hwnd)
	cmd, _, _ := procTrackPopupMenu.Call(h, tpmReturnCmd|tpmNoNotify|tpmRightButton, uintptr(pt.X), uintptr(pt.Y), 0, t.hwnd, 0)
	procPostMessageW.Call(t.hwnd, wmNull, 0, 0)
	if p, ok := picks[int(cmd)]; ok {
		t.dispatchPick(p)
		return
	}
	t.dispatch(int(cmd))
}

func (t *Tray) dispatchPick(p trayPick) {
	f := t.cb.OnServer
	if p.strategy {
		f = t.cb.OnStrategy
	}
	if f != nil {
		go f(p.key)
	}
}

func (t *Tray) dispatch(cmd int) {
	call := func(f func()) {
		if f != nil {
			go f()
		}
	}
	switch cmd {
	case idOpen:
		call(t.cb.OnOpen)
	case idVPN:
		call(t.cb.OnToggleVPN)
	case idZapret:
		call(t.cb.OnToggleZapret)
	case idQuit:
		call(t.cb.OnQuit)
	case idUpdate:
		call(t.cb.OnUpdate)
	case idAutoStrategy:
		if t.cb.OnStrategy != nil {
			go t.cb.OnStrategy("")
		}
	}
}

func (t *Tray) wndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	if msg == taskbarCreated && taskbarCreated != 0 {
		t.added = false
		t.addIcon()
		return 0
	}
	switch msg {
	case wmTray:
		switch uint32(lparam) {
		case wmLButtonUp, wmLButtonDblClk:
			t.dispatch(idOpen)
		case wmRButtonUp, wmContextMenu:
			t.showMenu()
		}
		return 0
	case wmUpdate:
		t.apply()
		return 0
	case wmBalloon:
		t.showBalloon()
		return 0
	case wmQueryEndSession:
		return 1
	case wmEndSession:
		if wparam != 0 && t.cb.OnEndSession != nil {
			t.cb.OnEndSession()
		}
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		n := t.nid()
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&n)))
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, uintptr(msg), wparam, lparam)
	return r
}
