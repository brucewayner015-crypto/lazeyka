package zapret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListStrategies(t *testing.T) {
	s, err := ListStrategies("testdata")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range s {
		names = append(names, x.File)
	}
	got := strings.Join(names, "|")
	want := "general.bat|general (ALT).bat|general (ALT11).bat|general (FAKE TLS AUTO).bat"
	if got != want {
		t.Fatalf("got %s", got)
	}
}

func TestBuildArgsAllStrategies(t *testing.T) {
	src := "/home/claude/flowseal/zapret-discord-youtube"
	files, _ := filepath.Glob(filepath.Join(src, "general*.bat"))
	if len(files) == 0 {
		files, _ = filepath.Glob("testdata/general*.bat")
	}
	p := Paths{Dir: `C:\ProgramData\Lazeyka\zapret`}
	for _, f := range files {
		content, _ := os.ReadFile(f)
		toks, err := ParseBat(string(content))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		vars := GameFilterVars("disabled")
		vars["BIN"] = p.Dir + `\bin\`
		vars["LISTS"] = p.Dir + `\lists\`
		vars["~dp0"] = p.Dir + `\`
		args, err := ExpandArgs(toks, vars)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		joined := strings.Join(args, " ")
		if !strings.HasPrefix(args[0], "--wf-tcp=") || strings.Contains(joined, "%") || strings.Contains(joined, `"`) || strings.Contains(joined, "^") {
			t.Fatalf("%s: bad args %q", filepath.Base(f), args)
		}
		if !strings.Contains(joined, `--hostlist=C:\ProgramData\Lazeyka\zapret\lists\list-general.txt`) {
			t.Fatalf("%s: lists not expanded: %s", filepath.Base(f), joined)
		}
		if !strings.Contains(joined, "--new") {
			t.Fatalf("%s: no profiles", filepath.Base(f))
		}
		if !strings.Contains(joined, ",12 ") && !strings.Contains(joined, "=12 ") {
			t.Fatalf("%s: game filter dummy port missing: %s", filepath.Base(f), joined[:200])
		}
	}
	t.Logf("checked %d strategies", len(files))
}

func TestBuildArgsWithIface(t *testing.T) {
	p := Paths{Dir: "testdata"}
	args, err := BuildArgs(p, "general.bat", "all", 7)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "--wf-iface=7" {
		t.Fatal(args[0])
	}
	if !strings.Contains(strings.Join(args, " "), "1024-65535") {
		t.Fatal("game filter all not applied")
	}
	if _, err := BuildArgs(p, `..\x.bat`, "", 0); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestListsAndIPSet(t *testing.T) {
	dir := t.TempDir()
	p := Paths{Dir: dir}
	os.MkdirAll(p.Lists(), 0o755)
	data, _ := os.ReadFile("testdata/lists/ipset-all.txt.backup")
	os.WriteFile(filepath.Join(p.Lists(), "ipset-all.txt"), []byte("203.0.113.113/32\n"), 0o644)
	os.WriteFile(filepath.Join(p.Lists(), "ipset-all.txt.backup"), data, 0o644)
	if IPSetMode(p) != IPSetNone {
		t.Fatal(IPSetMode(p))
	}
	if err := SetIPSetMode(p, IPSetLoaded); err != nil || IPSetMode(p) != IPSetLoaded {
		t.Fatal(err, IPSetMode(p))
	}
	if err := SetIPSetMode(p, IPSetAny); err != nil || IPSetMode(p) != IPSetAny {
		t.Fatal(err)
	}
	if err := SetIPSetMode(p, IPSetLoaded); err != nil || IPSetMode(p) != IPSetLoaded {
		t.Fatal(err)
	}
	if err := SetExcludeIPs(p, []string{"198.51.100.7", "2001:db8::1", "198.51.100.7"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(p.Lists(), "ipset-exclude-user.txt"))
	s := string(b)
	if strings.Count(s, "198.51.100.7/32") != 1 || !strings.Contains(s, "2001:db8::1/128") || !strings.Contains(s, placeholderIP) {
		t.Fatal(s)
	}
	if err := WriteUserList(p, "ipset-exclude-user.txt", "10.0.0.0/8\n"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(p.Lists(), "ipset-exclude-user.txt"))
	if !strings.Contains(string(b), "198.51.100.7/32") || !strings.Contains(string(b), "10.0.0.0/8") {
		t.Fatal(string(b))
	}
	user, _ := ReadUserList(p, "ipset-exclude-user.txt")
	if strings.Contains(user, "198.51.100.7") {
		t.Fatal("managed block leaked into user view")
	}
}

func TestBest(t *testing.T) {
	best, ok := Best([]StrategyScore{
		{File: "a", Summary: Summary{OK: 5, AvgMs: 300}},
		{File: "b", Summary: Summary{OK: 7, AvgMs: 900}},
		{File: "c", Summary: Summary{OK: 7, AvgMs: 200}},
		{File: "d", Summary: Summary{OK: 9}, Err: "crashed"},
	})
	if !ok || best.File != "c" {
		t.Fatal(best)
	}
}

func TestNormalizeUserList(t *testing.T) {
	out, bad := NormalizeUserList("list-general-user.txt", "# my list\r\n  президент.рф \nhttps://www.Example.com/watch?v=1\n^strict.example\n\n*.wild.example\nбред домен\n")
	want := "# my list\nxn--d1abbgf6aiiy.xn--p1ai\nwww.example.com\n^strict.example\n\nwild.example"
	if out != want || len(bad) != 1 || bad[0] != "бред домен" {
		t.Errorf("hosts: %q %q", out, bad)
	}
	out, bad = NormalizeUserList("ipset-exclude-user.txt", "1.2.3.4\n10.1.2.3/8\n# c\nnot-an-ip\n2001:db8::1\n")
	if out != "1.2.3.4\n10.0.0.0/8\n# c\n2001:db8::1" || len(bad) != 1 {
		t.Errorf("ips: %q %q", out, bad)
	}
}

func TestManagedHosts(t *testing.T) {
	p := Paths{Dir: t.TempDir()}
	if err := WriteUserList(p, "list-general-user.txt", "my.example\n"); err != nil {
		t.Fatal(err)
	}
	if err := SetManagedHosts(p, []string{"githubusercontent.com", "sub.example.net", "githubusercontent.com"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(p.Lists(), "list-general-user.txt"))
	s := string(b)
	if strings.Count(s, "githubusercontent.com") != 1 || !strings.Contains(s, "sub.example.net") || !strings.Contains(s, "my.example") {
		t.Fatal(s)
	}
	// the user sees and edits only their own lines; our block survives the edit
	user, _ := ReadUserList(p, "list-general-user.txt")
	if user != "my.example" {
		t.Fatalf("user view: %q", user)
	}
	if err := WriteUserList(p, "list-general-user.txt", "other.example\n"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(p.Lists(), "list-general-user.txt"))
	if !strings.Contains(string(b), "sub.example.net") || !strings.Contains(string(b), "other.example") || strings.Contains(string(b), "my.example") {
		t.Fatal(string(b))
	}
	// unchanged hosts: file not rewritten
	st1, _ := os.Stat(filepath.Join(p.Lists(), "list-general-user.txt"))
	SetManagedHosts(p, []string{"sub.example.net", "githubusercontent.com"})
	st2, _ := os.Stat(filepath.Join(p.Lists(), "list-general-user.txt"))
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("rewritten without changes")
	}
}
