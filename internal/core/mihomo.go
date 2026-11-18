package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"lazeyka/internal/logx"
	"lazeyka/internal/platform"
)

// Mihomo runs the mihomo core process.
type Mihomo struct {
	Bin  string
	Home string

	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	stopping  bool
	startedAt time.Time
	lastErr   string

	// OnExit is called when mihomo exits on its own.
	OnExit func(err error, uptime time.Duration, lastErr string)
	// OnLine sees every log line (from mihomo's output goroutine: keep it quick).
	OnLine func(level, msg string)
	// ExtraFiles are passed to the next Start as descriptors 3, 4… (Android:
	// the VPN interface).
	ExtraFiles []*os.File
	// Env is added to the environment of mihomo.
	Env []string
}

var versionRe = regexp.MustCompile(`v\d+\.\d+\.\d+`)

// Version returns "v1.19.34" or "".
func (m *Mihomo) Version() string {
	cmd := exec.Command(m.Bin, "-v")
	platform.PrepareChild(cmd)
	out, err := runWithTimeout(cmd, 10*time.Second)
	if err != nil {
		return ""
	}
	return versionRe.FindString(string(out))
}

// Test validates a config file with "mihomo -t".
func (m *Mihomo) Test(configPath string) error {
	cmd := exec.Command(m.Bin, "-t", "-d", m.Home, "-f", configPath)
	platform.PrepareChild(cmd)
	out, err := runWithTimeout(cmd, 30*time.Second)
	text := string(out)
	if err == nil && strings.Contains(text, "successful") {
		return nil
	}
	// pick the most useful line
	var msg string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if strings.Contains(l, "level=error") || strings.Contains(l, "level=fatal") || strings.Contains(strings.ToLower(l), "error") {
			if m := regexp.MustCompile(`msg="(.*)"`).FindStringSubmatch(l); m != nil {
				l = m[1]
			}
			msg = l
		}
	}
	if msg == "" {
		msg = strings.TrimSpace(text)
		if len(msg) > 400 {
			msg = msg[len(msg)-400:]
		}
	}
	if msg == "" && err != nil {
		msg = err.Error()
	}
	return fmt.Errorf("mihomo не принял конфиг: %s", msg)
}

func runWithTimeout(cmd *exec.Cmd, d time.Duration) ([]byte, error) {
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	platform.AttachChild(cmd.Process.Pid)
	ch := make(chan error, 1)
	go func() { ch <- cmd.Wait() }()
	select {
	case err := <-ch:
		return buf.Bytes(), err
	case <-time.After(d):
		cmd.Process.Kill()
		<-ch
		return buf.Bytes(), fmt.Errorf("истекло время ожидания")
	}
}

// Start launches mihomo with configPath.
func (m *Mihomo) Start(configPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		return nil
	}
	cmd := exec.Command(m.Bin, "-d", m.Home, "-f", configPath)
	cmd.Dir = m.Home
	cmd.ExtraFiles, m.ExtraFiles = m.ExtraFiles, nil
	if len(m.Env) > 0 {
		cmd.Env = append(os.Environ(), m.Env...)
	}
	lw := &logx.LineWriter{Src: "mihomo"}
	lw.OnLine = func(level, msg string) {
		if level == "error" {
			m.mu.Lock()
			m.lastErr = msg
			m.mu.Unlock()
		}
		if m.OnLine != nil {
			m.OnLine(level, msg)
		}
	}
	cmd.Stdout, cmd.Stderr = lw, lw
	platform.PrepareChild(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("не удалось запустить mihomo: %w", err)
	}
	platform.AttachChild(cmd.Process.Pid)
	done := make(chan struct{})
	m.cmd, m.done, m.stopping, m.startedAt, m.lastErr = cmd, done, false, time.Now(), ""
	logx.Infof("mihomo запущен (pid %d)", cmd.Process.Pid)
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		expected := m.stopping
		uptime := time.Since(m.startedAt)
		last := m.lastErr
		if m.cmd == cmd {
			m.cmd = nil
		}
		m.mu.Unlock()
		close(done)
		if !expected {
			logx.Warnf("mihomo завершился сам через %s: %v", uptime.Round(time.Second), err)
			if m.OnExit != nil {
				m.OnExit(err, uptime, last)
			}
		}
	}()
	return nil
}

// Stop terminates mihomo.
func (m *Mihomo) Stop() {
	m.mu.Lock()
	cmd, done := m.cmd, m.done
	if cmd == nil {
		m.mu.Unlock()
		return
	}
	m.stopping = true
	_ = cmd.Process.Kill()
	m.mu.Unlock()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		logx.Warnf("mihomo не завершился за 8 секунд")
	}
	m.mu.Lock()
	if m.cmd == cmd {
		m.cmd = nil
	}
	m.mu.Unlock()
	logx.Infof("mihomo остановлен")
}

// Running reports whether the process is alive.
func (m *Mihomo) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil
}

// LastError is the last error line printed by mihomo.
func (m *Mihomo) LastError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

// WaitReady polls the API until it answers.
func WaitReady(ctx context.Context, api *API, m *Mihomo, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !m.Running() {
			if e := m.LastError(); e != "" {
				return fmt.Errorf("mihomo завершился при запуске: %s", e)
			}
			return fmt.Errorf("mihomo завершился при запуске")
		}
		c, cancel := context.WithTimeout(ctx, time.Second)
		_, err := api.Version(c)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if e := m.LastError(); e != "" {
		return fmt.Errorf("mihomo не ответил за %s: %s", timeout, e)
	}
	return fmt.Errorf("mihomo не ответил за %s", timeout)
}
