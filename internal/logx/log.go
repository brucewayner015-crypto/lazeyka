// Package logx keeps an in-memory ring of recent log lines for the UI and
// mirrors them to a size-rotated file.
package logx

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Entry is a single log line.
type Entry struct {
	ID    int64     `json:"id"`
	Time  time.Time `json:"time"`
	Src   string    `json:"src"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
}

// Logger is safe for concurrent use.
type Logger struct {
	mu      sync.Mutex
	ring    []Entry
	max     int
	nextID  int64
	path    string
	file    *os.File
	size    int64
	maxSize int64
	debug   bool
}

var std = &Logger{max: 3000, maxSize: 4 << 20}

// Default returns the process-wide logger.
func Default() *Logger { return std }

// SetFile starts mirroring log lines to path (rotated at ~4 MB, one backup).
func (l *Logger) SetFile(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if l.file != nil {
		l.file.Close()
	}
	st, _ := f.Stat()
	l.path, l.file = path, f
	if st != nil {
		l.size = st.Size()
	}
	return nil
}

// SetDebug enables debug-level lines in the ring.
func (l *Logger) SetDebug(on bool) {
	l.mu.Lock()
	l.debug = on
	l.mu.Unlock()
}

// Close closes the log file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}

var urlRe = regexp.MustCompile(`(https?)://([^/\s"'?#]+)[^\s"']*`)

// shortenURLs keeps only scheme and host of every link: download URLs carry
// long signatures, and subscription links carry the owner's secret token,
// which must not end up in logs or in a report sent to someone.
// Redact shortens URLs in text shown to the user: subscription links carry
// a secret token in their path.
func Redact(msg string) string { return shortenURLs(msg) }

func shortenURLs(msg string) string {
	return urlRe.ReplaceAllStringFunc(msg, func(u string) string {
		m := urlRe.FindStringSubmatch(u)
		short := m[1] + "://" + m[2]
		if len(u) > len(short)+1 {
			short += "/…"
		}
		return short
	})
}

// Add records a line.
func (l *Logger) Add(src, level, msg string) {
	msg = strings.TrimRight(msg, "\r\n")
	if msg == "" {
		return
	}
	msg = shortenURLs(msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	if level == "debug" && !l.debug {
		return
	}
	l.nextID++
	e := Entry{ID: l.nextID, Time: time.Now(), Src: src, Level: level, Msg: msg}
	if len(l.ring) >= l.max {
		copy(l.ring, l.ring[len(l.ring)-l.max+1:])
		l.ring = l.ring[:l.max-1]
	}
	l.ring = append(l.ring, e)
	if l.file != nil {
		line := fmt.Sprintf("%s [%s] %-5s %s\r\n", e.Time.Format("2006-01-02 15:04:05"), src, strings.ToUpper(level), msg)
		n, _ := l.file.WriteString(line)
		l.size += int64(n)
		if l.size > l.maxSize {
			l.rotate()
		}
	}
}

func (l *Logger) rotate() {
	l.file.Close()
	_ = os.Remove(l.path + ".1")
	_ = os.Rename(l.path, l.path+".1")
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		l.file = nil
		return
	}
	l.file, l.size = f, 0
}

// Since returns entries with ID greater than id (at most limit, newest last).
func (l *Logger) Since(id int64, limit int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, 64)
	for _, e := range l.ring {
		if e.ID > id {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Tail returns the last n entries from src ("" = any).
func (l *Logger) Tail(src string, n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, n)
	for i := len(l.ring) - 1; i >= 0 && len(out) < n; i-- {
		if src == "" || l.ring[i].Src == src {
			out = append(out, l.ring[i])
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Infof logs an app-level info line.
func Infof(format string, a ...any) { std.Add("app", "info", fmt.Sprintf(format, a...)) }

// Warnf logs an app-level warning.
func Warnf(format string, a ...any) { std.Add("app", "warn", fmt.Sprintf(format, a...)) }

// Errorf logs an app-level error.
func Errorf(format string, a ...any) { std.Add("app", "error", fmt.Sprintf(format, a...)) }

// Debugf logs an app-level debug line.
func Debugf(format string, a ...any) { std.Add("app", "debug", fmt.Sprintf(format, a...)) }

// LineWriter splits a child process's output into log lines.
type LineWriter struct {
	Src    string
	Logger *Logger
	mu     sync.Mutex
	buf    bytes.Buffer
	// OnLine, if set, sees every parsed line (used to detect startup errors).
	OnLine func(level, msg string)
}

var mihomoLine = regexp.MustCompile(`level=(\w+)\s+msg="((?:[^"\\]|\\.)*)"`)

// Write implements io.Writer.
func (w *LineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			// incomplete line: put it back
			w.buf.Reset()
			w.buf.WriteString(line)
			if w.buf.Len() > 64<<10 { // pathological: flush anyway
				w.emit(w.buf.String())
				w.buf.Reset()
			}
			break
		}
		w.emit(line)
	}
	return len(p), nil
}

func (w *LineWriter) emit(line string) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return
	}
	level, msg := "info", line
	if m := mihomoLine.FindStringSubmatch(line); m != nil {
		level = strings.ToLower(m[1])
		msg = strings.ReplaceAll(m[2], `\"`, `"`)
	} else {
		low := strings.ToLower(line)
		switch {
		case strings.Contains(low, "error") || strings.Contains(low, "fatal") || strings.Contains(low, "ошибка"):
			level = "error"
		case strings.Contains(low, "warn"):
			level = "warn"
		}
	}
	switch level {
	case "warning":
		level = "warn"
	case "fatal", "panic":
		level = "error"
	}
	lg := w.Logger
	if lg == nil {
		lg = std
	}
	lg.Add(w.Src, level, msg)
	if w.OnLine != nil {
		w.OnLine(level, msg)
	}
}
