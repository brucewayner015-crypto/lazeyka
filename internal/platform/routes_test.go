package platform

import (
	"encoding/binary"
	"testing"
)

// table builds a MIB_IPFORWARDTABLE the way GetIpForwardTable fills it.
func table(rows ...route4) []byte {
	buf := make([]byte, 4+56*len(rows))
	binary.LittleEndian.PutUint32(buf, uint32(len(rows)))
	for i, r := range rows {
		row := buf[4+i*56:]
		copy(row[0:4], r.dest[:])
		copy(row[4:8], r.mask[:])
		binary.LittleEndian.PutUint32(row[16:20], r.ifIdx)
		binary.LittleEndian.PutUint32(row[36:40], r.metric)
	}
	return buf
}

func TestDefaultRoutes(t *testing.T) {
	ip := func(a, b, c, d byte) [4]byte { return [4]byte{a, b, c, d} }
	rows := parseForwardTable(table(
		route4{dest: ip(0, 0, 0, 0), mask: ip(0, 0, 0, 0), ifIdx: 11, metric: 25},    // Ethernet
		route4{dest: ip(192, 168, 0, 0), mask: ip(255, 255, 255, 0), ifIdx: 11},      // LAN, not default
		route4{dest: ip(0, 0, 0, 0), mask: ip(0, 0, 0, 0), ifIdx: 68, metric: 5},     // AmneziaVPN
		route4{dest: ip(0, 0, 0, 0), mask: ip(128, 0, 0, 0), ifIdx: 70, metric: 1},   // OpenVPN-style halves
		route4{dest: ip(128, 0, 0, 0), mask: ip(128, 0, 0, 0), ifIdx: 70, metric: 1}, //
		route4{dest: ip(0, 0, 0, 0), mask: ip(128, 0, 0, 0), ifIdx: 71, metric: 1},   // only one half: no default
		route4{dest: ip(0, 0, 0, 0), mask: ip(0, 0, 0, 0), ifIdx: 69, metric: 0},     // our TUN
		route4{dest: ip(0, 0, 0, 0), mask: ip(0, 0, 0, 0), ifIdx: 12, metric: 35},    // Wi-Fi, down
		route4{dest: ip(0, 0, 0, 0), mask: ip(0, 0, 0, 0), ifIdx: 13, metric: 50},    // Wi-Fi 2
	))
	if len(rows) != 9 || rows[1].dest != ip(192, 168, 0, 0) || rows[1].ifIdx != 11 {
		t.Fatalf("parse: %+v", rows)
	}
	info := func(idx uint32) (string, uint32, bool) {
		switch idx {
		case 11:
			return "Ethernet", 6, true
		case 12:
			return "Wi-Fi", 71, false
		case 13:
			return "Wi-Fi 2", 71, true
		case 68, 70, 71:
			return "VPN", IfTypePropVirtual, true
		}
		return "?", 0, true
	}
	got := defaultRoutes(rows, 69, info, func(uint32) uint32 { return 0 })
	var names []int
	for _, r := range got {
		names = append(names, r.Index)
	}
	if len(got) != 4 || got[0].Index != 70 || got[1].Index != 68 || got[2].Index != 11 || got[3].Index != 13 {
		t.Fatalf("routes: %v", names)
	}
	if got[0].Full || !got[1].Full || !got[0].OtherVPN() || got[0].Bindable() || got[1].Bindable() {
		t.Fatalf("kinds: %+v", got)
	}
	if !got[2].Bindable() || got[2].Name != "Ethernet" || got[2].Metric != 25 {
		t.Fatalf("ethernet: %+v", got[2])
	}
	if parseForwardTable([]byte{1, 0}) != nil || len(parseForwardTable(table()[:4])) != 0 {
		t.Fatal("short buffers")
	}
	// a truncated table stops at the last whole row
	if n := len(parseForwardTable(table(rows[0], rows[1])[:4+56+10])); n != 1 {
		t.Fatalf("truncated: %d", n)
	}
}
