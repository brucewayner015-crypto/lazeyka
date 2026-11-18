// Package platform isolates OS-specific code: elevation, scheduled tasks,
// tray icon, child-process handling and network interface lookup.
// Windows is the real target; other systems get stubs for development.
package platform

import (
	"encoding/binary"
	"sort"

	"lazeyka/internal/host"
)

// Host is the link to the Android app (nil elsewhere and until main connects).
var Host *host.Conn

// Scheduled task names.
const (
	TaskMain      = "Lazeyka"
	TaskAutostart = "Lazeyka Autostart"
)

// TrayState drives the tray icon and menu.
type TrayState struct {
	Mode     string // "on", "off", "busy", "err"
	Tip      string
	Status   string // first (disabled) menu line
	VPNOn    bool
	ZapretOn bool
}

// TrayCallbacks are invoked from the tray (in their own goroutine), except
// Choices: the tray calls it when the menu opens and waits for it.
type TrayCallbacks struct {
	OnOpen         func()
	OnToggleVPN    func()
	OnToggleZapret func()
	OnQuit         func()
	OnEndSession   func()
	Choices        func() TrayChoices
	OnServer       func(key string) // a server picked in the menu
	OnStrategy     func(key string) // a strategy picked; "" = pick automatically
	OnUpdate       func()           // "update Лазейка"
}

// TrayItem is a line of a tray submenu.
type TrayItem struct {
	Key       string // what OnServer/OnStrategy get
	Label     string
	Note      string // right-aligned: delay, check result
	Checked   bool
	Caption   bool // a grey heading, not clickable
	Separator bool
}

// TrayChoices fill the submenus when the menu opens. Empty lists show Note
// instead (VPN is off, zapret is not downloaded…).
type TrayChoices struct {
	Servers        []TrayItem
	ServersNote    string
	Strategies     []TrayItem
	StrategiesNote string
	CanAutoPick    bool   // "pick automatically" in the strategy submenu
	Update         string // a newer Лазейка to offer
}

// ServiceInfo describes a Windows service.
type ServiceInfo struct {
	Exists  bool
	Running bool
}

// ConflictingServices are other DPI-bypass tools that grab WinDivert.
var ConflictingServices = []string{"zapret", "GoodbyeDPI", "discordfix_zapret", "winws1", "winws2"}

// HostModel describes how Windows treats an interface's packets: with
// forwarding or weak host send on, a packet from this interface's address may
// be routed out of another one (for example into the VPN tunnel).
type HostModel struct {
	Name       string
	Index      int
	Forwarding bool
	WeakSend   bool
	WeakRecv   bool
}

// Interface types (IANA ifType) that matter for routing.
const (
	IfTypeLoopback    = 24
	IfTypePropVirtual = 53 // wintun: WireGuard, AmneziaVPN and most other VPN adapters
)

// RouteIface is an interface that is up and has an IPv4 default route.
type RouteIface struct {
	Index  int
	Name   string
	Type   uint32
	Metric uint64 // route + interface metric: Windows prefers the lowest
	Full   bool   // has 0.0.0.0/0 (VPNs often add 0.0.0.0/1 + 128.0.0.0/1 instead)
}

// Bindable: mihomo binds the VPN's own connections to the best interface of
// this kind ("the default interface"; it skips VPN adapters and loopback).
func (r RouteIface) Bindable() bool {
	return r.Full && r.Type != IfTypePropVirtual && r.Type != IfTypeLoopback
}

// OtherVPN: another VPN's adapter that takes the default route.
func (r RouteIface) OtherVPN() bool { return r.Type == IfTypePropVirtual }

// route4 is a row of the IPv4 routing table.
type route4 struct {
	dest, mask [4]byte
	ifIdx      uint32
	metric     uint32
}

// parseForwardTable decodes a MIB_IPFORWARDTABLE as GetIpForwardTable fills
// it: a row count, then 56-byte rows (addresses in network byte order).
func parseForwardTable(buf []byte) []route4 {
	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf[0:4]))
	const rowSize = 56
	var out []route4
	for i := 0; i < n; i++ {
		off := 4 + i*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		var r route4
		copy(r.dest[:], row[0:4])
		copy(r.mask[:], row[4:8])
		r.ifIdx = binary.LittleEndian.Uint32(row[16:20])
		r.metric = binary.LittleEndian.Uint32(row[36:40])
		out = append(out, r)
	}
	return out
}

// defaultRoutes picks the interfaces with a default route out of a routing
// table, best first. info tells an interface's name, type and whether it is
// up; ifMetric its metric. skip is our own TUN adapter.
func defaultRoutes(rows []route4, skip int, info func(uint32) (string, uint32, bool), ifMetric func(uint32) uint32) []RouteIface {
	type acc struct {
		r      RouteIface
		halves int // 1: 0.0.0.0/1, 2: 128.0.0.0/1
		down   bool
	}
	byIdx := map[uint32]*acc{}
	var order []uint32
	for _, row := range rows {
		if int(row.ifIdx) == skip {
			continue
		}
		full := row.dest == [4]byte{} && row.mask == [4]byte{}
		half := 0
		if row.mask == [4]byte{128} {
			switch row.dest {
			case [4]byte{}:
				half = 1
			case [4]byte{128}:
				half = 2
			}
		}
		if !full && half == 0 {
			continue
		}
		e := byIdx[row.ifIdx]
		if e == nil {
			name, typ, up := info(row.ifIdx)
			e = &acc{r: RouteIface{Index: int(row.ifIdx), Name: name, Type: typ, Metric: ^uint64(0)}, down: !up}
			byIdx[row.ifIdx] = e
			order = append(order, row.ifIdx)
		}
		if e.down {
			continue
		}
		e.halves |= half
		if full {
			e.r.Full = true
		}
		if m := uint64(row.metric) + uint64(ifMetric(row.ifIdx)); m < e.r.Metric {
			e.r.Metric = m
		}
	}
	var out []RouteIface
	for _, idx := range order {
		if e := byIdx[idx]; !e.down && (e.r.Full || e.halves == 3) {
			out = append(out, e.r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Metric < out[j].Metric })
	return out
}
