//go:build !unix

package host

import (
	"encoding/json"
	"os"
	"time"
)

// Conn exists only on Unix (Android); elsewhere every call fails.
type Conn struct{}

func Dial(name string) (*Conn, error)          { return nil, ErrNoHost }
func (h *Conn) Events() <-chan Event           { return nil }
func (h *Conn) Done() <-chan struct{}          { return nil }
func (h *Conn) Tell(op string, args any) error { return ErrNoHost }
func (h *Conn) Call(op string, args any, timeout time.Duration) (json.RawMessage, []int, error) {
	return nil, nil, ErrNoHost
}
func (h *Conn) OpenTun(p TunParams) (*os.File, error) { return nil, ErrNoHost }
func (h *Conn) CloseTun() error                       { return ErrNoHost }
func (h *Conn) Apps() ([]AppInfo, error)              { return nil, ErrNoHost }
