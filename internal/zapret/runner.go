package zapret

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
)

// Runner owns one winws.exe process.
type Runner struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	stopping  bool
	startedAt time.Time
	strategy  string

	// OnExit is called when winws exits on its own (not via Stop).
	OnExit func(err error, uptime time.Duration)

	// Exe replaces winws.exe (Android: ByeDPI), Label names it in the log.
	Exe   string
	Label string
}

func (r *Runner) label() string {
	if r.Label != "" {
		return r.Label
	}
	return "zapret"
}

// Start launches winws with args. It is a no-op if already running.
func (r *Runner) Start(p Paths, strategy string, args []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil {
		return nil
	}
	exe, dir := p.Winws(), p.Bin()
	if r.Exe != "" {
		exe, dir = r.Exe, filepath.Dir(r.Exe)
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = dir
	lw := &logx.LineWriter{Src: "zapret"}
	cmd.Stdout, cmd.Stderr = lw, lw
	platform.PrepareChild(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("не удалось запустить %s: %w", filepath.Base(exe), err)
	}
	platform.AttachChild(cmd.Process.Pid)
	done := make(chan struct{})
	r.cmd, r.done, r.stopping, r.startedAt, r.strategy = cmd, done, false, time.Now(), strategy
	logx.Infof("%s запущен: %s (pid %d)", r.label(), strategy, cmd.Process.Pid)
	go func() {
		err := cmd.Wait()
		r.mu.Lock()
		expected := r.stopping
		uptime := time.Since(r.startedAt)
		if r.cmd == cmd {
			r.cmd = nil
		}
		r.mu.Unlock()
		close(done)
		if !expected {
			logx.Warnf("%s завершился сам через %s: %v", r.label(), uptime.Round(time.Second), err)
			if r.OnExit != nil {
				r.OnExit(err, uptime)
			}
		}
	}()
	return nil
}

// Stop terminates winws and waits for it to exit.
func (r *Runner) Stop() {
	r.mu.Lock()
	cmd, done := r.cmd, r.done
	if cmd == nil {
		r.mu.Unlock()
		return
	}
	r.stopping = true
	_ = cmd.Process.Kill()
	r.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logx.Warnf("%s не завершился за 5 секунд", r.label())
	}
	r.mu.Lock()
	if r.cmd == cmd {
		r.cmd = nil
	}
	r.mu.Unlock()
	logx.Infof("%s остановлен", r.label())
}

// Running reports whether winws is alive.
func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmd != nil
}

// PID of the running winws (0 if none).
func (r *Runner) PID() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil || r.cmd.Process == nil {
		return 0
	}
	return r.cmd.Process.Pid
}

// Strategy currently running.
func (r *Runner) Strategy() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return ""
	}
	return r.strategy
}

// Uptime of the running process.
func (r *Runner) Uptime() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
		return 0
	}
	return time.Since(r.startedAt)
}
