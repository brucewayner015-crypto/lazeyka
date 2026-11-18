package core

import (
	"os"
	"testing"

	"lazeyka/internal/settings"
)

// DUMP_CONFIG=/tmp/out.yaml go test ./internal/core -run Dump
// Optional DUMP_SETTINGS=path/settings.json builds from a real settings file.
func TestDumpSample(t *testing.T) {
	if os.Getenv("DUMP_CONFIG") == "" {
		t.Skip()
	}
	s := sampleSettings(t)
	if p := os.Getenv("DUMP_SETTINGS"); p != "" {
		var err error
		if s, err = settings.Load(p); err != nil {
			t.Fatal(err)
		}
	}
	rt := testRuntime()
	rt.TunEnabled = true
	b, err := Build(s, rt)
	if err != nil {
		t.Fatal(err)
	}
	checkRefs(t, b.Config)
	if err := os.WriteFile(os.Getenv("DUMP_CONFIG"), b.Config, 0o644); err != nil {
		t.Fatal(err)
	}
	for k, v := range b.Files {
		t.Logf("%s: %s", k, v)
	}
}
