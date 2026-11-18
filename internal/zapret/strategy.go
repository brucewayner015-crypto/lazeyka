// Package zapret runs Flowseal's zapret-discord-youtube strategies with
// winws.exe directly (no .bat, no Windows service), keeps its lists and
// probes which strategy works on the current connection.
package zapret

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Strategy is one general*.bat file.
type Strategy struct {
	File string `json:"file"`
	Name string `json:"name"`
}

// Paths of a zapret installation.
type Paths struct{ Dir string }

func (p Paths) Bin() string   { return filepath.Join(p.Dir, "bin") }
func (p Paths) Lists() string { return filepath.Join(p.Dir, "lists") }
func (p Paths) Winws() string { return filepath.Join(p.Dir, "bin", "winws.exe") }

// Missing lists the engine files that are not there. Antivirus programs
// often quarantine WinDivert, which shows up here.
func (p Paths) Missing() []string {
	var miss []string
	for _, f := range []string{"winws.exe", "WinDivert.dll", "WinDivert64.sys", "cygwin1.dll"} {
		if _, err := os.Stat(filepath.Join(p.Bin(), f)); err != nil {
			miss = append(miss, f)
		}
	}
	return miss
}

// Installed reports whether winws.exe and at least one strategy exist.
func (p Paths) Installed() bool {
	if _, err := os.Stat(p.Winws()); err != nil {
		return false
	}
	s, _ := ListStrategies(p.Dir)
	return len(s) > 0
}

var numRe = regexp.MustCompile(`\d+`)

func naturalKey(s string) string {
	return numRe.ReplaceAllStringFunc(strings.ToLower(s), func(n string) string {
		return fmt.Sprintf("%08s", n)
	})
}

// ListStrategies returns the strategy .bat files in natural order,
// "general.bat" first.
func ListStrategies(dir string) ([]Strategy, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Strategy
	for _, e := range ents {
		n := e.Name()
		low := strings.ToLower(n)
		if e.IsDir() || !strings.HasSuffix(low, ".bat") || strings.HasPrefix(low, "service") {
			continue
		}
		out = append(out, Strategy{File: n, Name: strings.TrimSuffix(n, filepath.Ext(n))})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].File), strings.ToLower(out[j].File)
		if a == "general.bat" {
			return true
		}
		if b == "general.bat" {
			return false
		}
		return naturalKey(a) < naturalKey(b)
	})
	return out, nil
}

// ParseBat extracts the winws.exe argument tokens from a strategy file.
// Variables such as %BIN% are left in place for ExpandArgs.
func ParseBat(content string) ([]string, error) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	start := -1
	for i, l := range lines {
		low := strings.ToLower(l)
		if strings.Contains(low, "winws.exe") && !strings.HasPrefix(strings.TrimSpace(low), "::") && !strings.HasPrefix(strings.TrimSpace(low), "rem ") {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("в файле стратегии нет запуска winws.exe")
	}
	var b strings.Builder
	for i := start; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], " \t")
		cont := strings.HasSuffix(l, "^")
		if cont {
			l = strings.TrimSuffix(l, "^")
		}
		b.WriteString(l)
		b.WriteByte(' ')
		if !cont {
			break
		}
	}
	joined := b.String()
	idx := strings.Index(strings.ToLower(joined), "winws.exe")
	rest := joined[idx+len("winws.exe"):]
	rest = strings.TrimPrefix(rest, `"`)
	tokens := splitCmd(rest)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("в стратегии нет параметров winws")
	}
	return tokens, nil
}

// splitCmd splits a cmd.exe-style argument string: whitespace separates
// arguments, double quotes group and are removed, and outside quotes a caret
// escapes the next character ("^!" is winws's built-in fake, passed as "!").
func splitCmd(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, has, esc := false, false, false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			has, esc = true, false
		case r == '^' && !inQ:
			esc = true
		case r == '"':
			inQ = !inQ
			has = true
		case (r == ' ' || r == '\t') && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

var varRe = regexp.MustCompile(`%([A-Za-z_~][A-Za-z0-9_]*)%`)

// ExpandArgs substitutes %VAR% placeholders (case-insensitive names).
func ExpandArgs(tokens []string, vars map[string]string) ([]string, error) {
	lv := map[string]string{}
	for k, v := range vars {
		lv[strings.ToLower(k)] = v
	}
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		var missing string
		e := varRe.ReplaceAllStringFunc(t, func(m string) string {
			name := strings.ToLower(m[1 : len(m)-1])
			if v, ok := lv[name]; ok {
				return v
			}
			missing = m
			return m
		})
		if missing != "" {
			return nil, fmt.Errorf("неизвестная переменная %s в стратегии — обновите приложение", missing)
		}
		out = append(out, e)
	}
	return out, nil
}

// GameFilterVars mirrors service.bat: disabled filters use dummy port 12.
func GameFilterVars(mode string) map[string]string {
	const all = "1024-65535"
	tcp, udp := "12", "12"
	switch mode {
	case "all":
		tcp, udp = all, all
	case "tcp":
		tcp = all
	case "udp":
		udp = all
	}
	gf := "12"
	if tcp != "12" {
		gf = tcp
	} else if udp != "12" {
		gf = udp
	}
	return map[string]string{"GameFilter": gf, "GameFilterTCP": tcp, "GameFilterUDP": udp}
}

// BuildArgs reads a strategy file and returns ready winws arguments.
func BuildArgs(p Paths, file, gameFilter string, ifIndex int) ([]string, error) {
	if strings.ContainsAny(file, `/\`) || strings.Contains(file, "..") {
		return nil, fmt.Errorf("неверное имя стратегии")
	}
	content, err := os.ReadFile(filepath.Join(p.Dir, file))
	if err != nil {
		return nil, fmt.Errorf("стратегия %s не найдена", file)
	}
	tokens, err := ParseBat(string(content))
	if err != nil {
		return nil, err
	}
	vars := GameFilterVars(gameFilter)
	vars["BIN"] = p.Bin() + string(filepath.Separator)
	vars["LISTS"] = p.Lists() + string(filepath.Separator)
	vars["~dp0"] = p.Dir + string(filepath.Separator)
	args, err := ExpandArgs(tokens, vars)
	if err != nil {
		return nil, err
	}
	if ifIndex > 0 {
		args = append([]string{"--wf-iface=" + strconv.Itoa(ifIndex)}, args...)
	}
	return args, nil
}
