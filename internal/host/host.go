//go:build unix

// Package host talks to the Android app that runs Лазейка's core: the app
// owns what only Android code can do (the VPN interface from VpnService,
// notifications, the list of installed apps) and the core asks for it over a
// Unix socket.
//
// Protocol: one JSON object per line in both directions.
//
//	core → app: {"id":7,"op":"tun_open","args":{...}}   (requests carry an id)
//	app → core: {"id":7,"ok":true,"data":{...}}          (the reply, same id)
//	app → core: {"event":"toggle_vpn"}                   (events have no id)
//
// The reply to tun_open carries the TUN file descriptor as SCM_RIGHTS
// ancillary data on the same write.
package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

type reply struct {
	ID    int64           `json:"id"`
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
	fds   []int
}

type request struct {
	ID   int64  `json:"id,omitempty"`
	Op   string `json:"op"`
	Args any    `json:"args,omitempty"`
}

// Conn is the link to the app.
type Conn struct {
	c      *net.UnixConn
	wmu    sync.Mutex
	mu     sync.Mutex
	nextID int64
	wait   map[int64]chan reply
	events chan Event
	closed chan struct{}
	err    error
}

// Dial connects to the app's socket. Names starting with "@" are in the
// abstract namespace.
func Dial(name string) (*Conn, error) {
	addr := &net.UnixAddr{Name: name, Net: "unix"}
	uc, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, err
	}
	h := &Conn{c: uc, wait: map[int64]chan reply{}, events: make(chan Event, 32), closed: make(chan struct{})}
	go h.readLoop()
	return h, nil
}

// Events delivers app events; the channel closes when the app goes away.
func (h *Conn) Events() <-chan Event { return h.events }

// Done is closed when the connection is lost.
func (h *Conn) Done() <-chan struct{} { return h.closed }

func (h *Conn) readLoop() {
	defer func() {
		h.mu.Lock()
		for id, ch := range h.wait {
			close(ch)
			delete(h.wait, id)
		}
		h.mu.Unlock()
		close(h.events)
		close(h.closed)
		h.c.Close()
	}()
	var buf bytes.Buffer
	var fds []int
	data := make([]byte, 64<<10)
	oob := make([]byte, syscall.CmsgSpace(4*8))
	for {
		n, oobn, _, _, err := h.c.ReadMsgUnix(data, oob)
		if oobn > 0 {
			if msgs, perr := syscall.ParseSocketControlMessage(oob[:oobn]); perr == nil {
				for _, m := range msgs {
					if got, rerr := syscall.ParseUnixRights(&m); rerr == nil {
						fds = append(fds, got...)
					}
				}
			}
		}
		if n > 0 {
			buf.Write(data[:n])
		}
		for {
			line, ok := cutLine(&buf)
			if !ok {
				break
			}
			fds = h.dispatch(line, fds)
		}
		if err != nil {
			h.err = err
			for _, fd := range fds {
				syscall.Close(fd)
			}
			return
		}
	}
}

func cutLine(b *bytes.Buffer) ([]byte, bool) {
	i := bytes.IndexByte(b.Bytes(), '\n')
	if i < 0 {
		return nil, false
	}
	line := make([]byte, i)
	copy(line, b.Bytes()[:i])
	b.Next(i + 1)
	return line, true
}

// dispatch handles one line; descriptors received so far go to the first
// reply that is waiting for them (only tun_open replies carry one).
func (h *Conn) dispatch(line []byte, fds []int) []int {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return fds
	}
	var probe struct {
		ID    int64  `json:"id"`
		Event string `json:"event"`
	}
	if json.Unmarshal(line, &probe) != nil {
		return fds
	}
	if probe.Event != "" {
		var ev Event
		if json.Unmarshal(line, &ev) == nil {
			select {
			case h.events <- ev:
			default: // nobody listens fast enough: drop rather than block replies
			}
		}
		return fds
	}
	var r reply
	if json.Unmarshal(line, &r) != nil {
		return fds
	}
	r.fds, fds = fds, nil
	h.mu.Lock()
	ch := h.wait[r.ID]
	delete(h.wait, r.ID)
	h.mu.Unlock()
	if ch == nil {
		for _, fd := range r.fds {
			syscall.Close(fd)
		}
		return fds
	}
	ch <- r
	return fds
}

func (h *Conn) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	h.wmu.Lock()
	defer h.wmu.Unlock()
	_ = h.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = h.c.Write(b)
	return err
}

// Call sends a request and waits for the reply.
func (h *Conn) Call(op string, args any, timeout time.Duration) (json.RawMessage, []int, error) {
	if h == nil {
		return nil, nil, ErrNoHost
	}
	ch := make(chan reply, 1)
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	h.wait[id] = ch
	h.mu.Unlock()
	if err := h.send(request{ID: id, Op: op, Args: args}); err != nil {
		h.mu.Lock()
		delete(h.wait, id)
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("%w: %v", ErrNoHost, err)
	}
	select {
	case r, ok := <-ch:
		if !ok {
			return nil, nil, ErrNoHost
		}
		if !r.OK {
			for _, fd := range r.fds {
				syscall.Close(fd)
			}
			if r.Error == "" {
				r.Error = op + ": ошибка в приложении"
			}
			return nil, nil, errors.New(r.Error)
		}
		return r.Data, r.fds, nil
	case <-time.After(timeout):
		h.mu.Lock()
		delete(h.wait, id)
		h.mu.Unlock()
		return nil, nil, fmt.Errorf("приложение не ответило на %s за %s", op, timeout)
	}
}

// Tell sends a one-way message (no reply expected).
func (h *Conn) Tell(op string, args any) error {
	if h == nil {
		return ErrNoHost
	}
	return h.send(request{Op: op, Args: args})
}

// OpenTun asks the app for a VPN interface. The app may first have to ask
// the user for the VPN permission, so the wait is long.
func (h *Conn) OpenTun(p TunParams) (*os.File, error) {
	_, fds, err := h.Call("tun_open", p, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	if len(fds) == 0 {
		return nil, errors.New("приложение не передало VPN-интерфейс")
	}
	for _, fd := range fds[1:] {
		syscall.Close(fd)
	}
	return os.NewFile(uintptr(fds[0]), "tun"), nil
}

// CloseTun tells the app to drop the VPN interface.
func (h *Conn) CloseTun() error {
	_, _, err := h.Call("tun_close", nil, 15*time.Second)
	return err
}

// Apps lists installed applications that use the network.
func (h *Conn) Apps() ([]AppInfo, error) {
	data, _, err := h.Call("apps", nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	var out []AppInfo
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}
