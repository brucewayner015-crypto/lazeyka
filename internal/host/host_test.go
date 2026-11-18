//go:build unix

package host

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// fakeApp plays the Android side: it answers tun_open with a pipe's write
// end as the "TUN" descriptor.
func fakeApp(t *testing.T, ln *net.UnixListener, pipeW *os.File) {
	go func() {
		c, err := ln.AcceptUnix()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		sc := bufio.NewScanner(c)
		// an unsolicited event first
		c.Write([]byte(`{"event":"toggle_vpn"}` + "\n"))
		for sc.Scan() {
			var req struct {
				ID   int64           `json:"id"`
				Op   string          `json:"op"`
				Args json.RawMessage `json:"args"`
			}
			if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
				t.Error(err)
				return
			}
			switch req.Op {
			case "tun_open":
				var p TunParams
				json.Unmarshal(req.Args, &p)
				if p.MTU != 1500 || len(p.BypassApps) != 1 {
					t.Errorf("params: %+v", p)
				}
				rights := syscall.UnixRights(int(pipeW.Fd()))
				msg := fmt.Sprintf(`{"id":%d,"ok":true}`+"\n", req.ID)
				// split the line in two writes: the fd travels with the first
				if _, _, err := c.WriteMsgUnix([]byte(msg[:5]), rights, nil); err != nil {
					t.Error(err)
				}
				time.Sleep(20 * time.Millisecond)
				c.Write([]byte(msg[5:]))
			case "apps":
				fmt.Fprintf(c, `{"id":%d,"ok":true,"data":[{"package":"ru.rostel","label":"Госуслуги"}]}`+"\n", req.ID)
			case "tun_close":
				fmt.Fprintf(c, `{"id":%d,"ok":false,"error":"нет интерфейса"}`+"\n", req.ID)
			case "status":
				// one-way, no reply
			}
		}
	}()
}

func TestBridge(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fakeApp(t, ln, pw)
	h, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-h.Events():
		if ev.Name != "toggle_vpn" {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
	if err := h.Tell("status", Status{Mode: "on"}); err != nil {
		t.Fatal(err)
	}
	f, err := h.OpenTun(TunParams{MTU: 1500, BypassApps: []string{"ru.rostel"}})
	if err != nil {
		t.Fatal(err)
	}
	// the received descriptor is a duplicate of the pipe's write end
	pw.Close()
	if _, err := f.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, _ := io.ReadAll(pr)
	if string(b) != "ok" {
		t.Fatalf("pipe got %q", b)
	}
	apps, err := h.Apps()
	if err != nil || len(apps) != 1 || apps[0].Label != "Госуслуги" {
		t.Fatalf("apps %v %v", apps, err)
	}
	if err := h.CloseTun(); err == nil || err.Error() != "нет интерфейса" {
		t.Fatalf("close: %v", err)
	}
}
