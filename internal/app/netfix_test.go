package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazeyka/internal/platform"
)

// fakeNet is a computer with a few network cards.
type fakeNet struct {
	cards  map[int]*platform.HostModel
	routes []platform.RouteIface
	fail   map[int]bool
	sets   int
}

func (n *fakeNet) ops() netOps {
	return netOps{
		routes: func() []platform.RouteIface { return n.routes },
		model: func(idx int) (platform.HostModel, bool) {
			c, ok := n.cards[idx]
			if !ok {
				return platform.HostModel{}, false
			}
			return *c, true
		},
		set: func(idx int, fw, ws *bool) error {
			n.sets++
			if n.fail[idx] {
				return errors.New("access denied")
			}
			c := n.cards[idx]
			if fw != nil {
				c.Forwarding = *fw
			}
			if ws != nil {
				c.WeakSend = *ws
			}
			return nil
		},
		byName: func(name string) int {
			for idx, c := range n.cards {
				if c.Name == name {
					return idx
				}
			}
			return 0
		},
	}
}

func newFakeNet() *fakeNet {
	return &fakeNet{
		cards: map[int]*platform.HostModel{
			11: {Name: "Ethernet", Index: 11, Forwarding: true},
			12: {Name: "Wi-Fi", Index: 12, WeakSend: true, WeakRecv: true},
			68: {Name: "AmneziaVPN", Index: 68, Forwarding: true},
			20: {Name: "vEthernet (WSL)", Index: 20, Forwarding: true},
		},
		routes: []platform.RouteIface{
			{Index: 68, Name: "AmneziaVPN", Type: platform.IfTypePropVirtual, Full: true},
			{Index: 11, Name: "Ethernet", Type: 6, Full: true},
			{Index: 12, Name: "Wi-Fi", Type: 71, Full: true},
		},
		fail: map[int]bool{},
	}
}

func TestNetFixSession(t *testing.T) {
	n := newFakeNet()
	path := filepath.Join(t.TempDir(), "netfix.json")
	f := newNetFix(path, n.ops())

	changed, errs := f.begin()
	if len(errs) > 0 || strings.Join(changed, ",") != "«Ethernet»,«Wi-Fi»" {
		t.Fatalf("begin: %v %v", changed, errs)
	}
	if n.cards[11].Forwarding || n.cards[12].WeakSend || !n.cards[12].WeakRecv {
		t.Fatalf("cards after begin: %+v %+v", *n.cards[11], *n.cards[12])
	}
	// another VPN's adapter and cards without a default route stay as they are
	if !n.cards[68].Forwarding || !n.cards[20].Forwarding {
		t.Fatal("touched a card it should not")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state not saved: %v", err)
	}
	// nothing to do while the flags stay off
	if changed, _ := f.recheck(); len(changed) != 0 {
		t.Fatalf("recheck: %v", changed)
	}
	// sharing switched forwarding back on
	n.cards[11].Forwarding = true
	if changed, _ := f.recheck(); strings.Join(changed, ",") != "«Ethernet»" || n.cards[11].Forwarding {
		t.Fatalf("recheck after it came back: %v", changed)
	}

	restored, errs := f.end()
	if len(errs) > 0 || len(restored) != 2 {
		t.Fatalf("end: %v %v", restored, errs)
	}
	if !n.cards[11].Forwarding || n.cards[11].WeakSend || !n.cards[12].WeakSend || n.cards[12].Forwarding {
		t.Fatalf("cards after end: %+v %+v", *n.cards[11], *n.cards[12])
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("state file left behind")
	}
	// once the session is over the watcher must not switch anything off
	if changed, _ := f.recheck(); len(changed) != 0 || !n.cards[11].Forwarding {
		t.Fatal("recheck outside a session changed things")
	}
	if restored, _ := f.end(); len(restored) != 0 {
		t.Fatal("second end restored again")
	}
}

func TestNetFixRepairsAfterCrash(t *testing.T) {
	n := newFakeNet()
	path := filepath.Join(t.TempDir(), "netfix.json")
	if changed, _ := newNetFix(path, n.ops()).begin(); len(changed) != 2 {
		t.Fatal(changed)
	}
	// Лазейка was killed; Windows gave Ethernet another number meanwhile
	n.cards[15] = n.cards[11]
	n.cards[15].Index = 15
	delete(n.cards, 11)
	n.cards[11] = &platform.HostModel{Name: "Другая карта", Index: 11}

	restored, errs := newNetFix(path, n.ops()).end()
	if len(errs) > 0 || len(restored) != 2 {
		t.Fatalf("restore: %v %v", restored, errs)
	}
	if !n.cards[15].Forwarding || n.cards[11].Forwarding || !n.cards[12].WeakSend {
		t.Fatalf("restored the wrong card: %+v %+v", *n.cards[15], *n.cards[11])
	}
}

func TestNetFixKeepsWhatItCouldNotRestore(t *testing.T) {
	n := newFakeNet()
	path := filepath.Join(t.TempDir(), "netfix.json")
	f := newNetFix(path, n.ops())
	f.begin()
	n.fail[12] = true
	restored, errs := f.end()
	if len(restored) != 1 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "Wi-Fi") {
		t.Fatalf("end: %v %v", restored, errs)
	}
	// the next start tries again
	n.fail[12] = false
	restored, errs = newNetFix(path, n.ops()).end()
	if len(errs) > 0 || strings.Join(restored, ",") != "«Wi-Fi»" || !n.cards[12].WeakSend {
		t.Fatalf("retry: %v %v", restored, errs)
	}
}

func TestNetFixFailureLeavesOthersAlone(t *testing.T) {
	n := newFakeNet()
	n.fail[11] = true
	f := newNetFix(filepath.Join(t.TempDir(), "netfix.json"), n.ops())
	changed, errs := f.begin()
	if strings.Join(changed, ",") != "«Wi-Fi»" || len(errs) != 1 || !strings.Contains(errs[0].Error(), "Ethernet") {
		t.Fatalf("begin: %v %v", changed, errs)
	}
	// the watcher does not retry (and log) it every 15 seconds
	sets := n.sets
	if changed, errs := f.recheck(); len(changed) != 0 || len(errs) != 0 || n.sets != sets {
		t.Fatalf("recheck: %v %v %d", changed, errs, n.sets-sets)
	}
	// a new session tries again
	n.fail[11] = false
	if changed, _ := f.begin(); strings.Join(changed, ",") != "«Ethernet»" {
		t.Fatalf("new session: %v", changed)
	}
}

func TestJoinQuoted(t *testing.T) {
	for in, want := range map[string]string{
		"":            "",
		"«a»":         "«a»",
		"«a»,«b»":     "«a» и «b»",
		"«a»,«b»,«c»": "«a», «b» и «c»",
	} {
		var names []string
		if in != "" {
			names = strings.Split(in, ",")
		}
		if got := joinQuoted(names); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
