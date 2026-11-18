package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// releaseServer stands in for the release branch on GitHub.
func releaseServer(t *testing.T, version string, exe []byte, tamper func(*selfManifest)) *httptest.Server {
	t.Helper()
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("Lazeyka.exe")
	w.Write(exe)
	zw.Close()
	name := "Lazeyka-" + version + ".zip"
	m := selfManifest{Version: version, File: name, Size: int64(zb.Len()), SHA256: sum(zb.Bytes()), ExeSHA256: sum(exe), Notes: "Новое: проверка"}
	if tamper != nil {
		tamper(&m)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(m) })
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) { w.Write(zb.Bytes()) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	old := selfBase
	selfBase = srv.URL + "/"
	t.Cleanup(func() { selfBase = old })
	return srv
}

func newTestApp(t *testing.T) *App {
	t.Helper()
	a, err := New(NewPaths(t.TempDir()), true)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSelfUpdateDownloads(t *testing.T) {
	exe := []byte("MZ new lazeyka")
	releaseServer(t, "99.0.0", exe, nil)
	a := newTestApp(t)
	v := a.CheckSelfUpdate()
	if !v.Available || v.Latest != "99.0.0" || v.Notes != "Новое: проверка" || v.Error != "" {
		t.Fatalf("check: %+v", v)
	}
	if st := a.Status(); st.Update != "99.0.0" {
		t.Fatalf("status update %q", st.Update)
	}
	path, ver, err := a.downloadSelfUpdate()
	if err != nil || ver != "99.0.0" {
		t.Fatal(ver, err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, exe) {
		t.Fatal("exe differs")
	}
	cleanupUpdates(a.P)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("left behind")
	}
}

func TestSelfUpdateRefusesBadFiles(t *testing.T) {
	exe := []byte("MZ new lazeyka")
	releaseServer(t, "99.0.0", exe, func(m *selfManifest) { m.ExeSHA256 = strings.Repeat("0", 64) })
	a := newTestApp(t)
	if _, _, err := a.downloadSelfUpdate(); err == nil || !strings.Contains(err.Error(), "не совпала") {
		t.Fatalf("exe checksum: %v", err)
	}

	releaseServer(t, "99.0.0", exe, func(m *selfManifest) { m.SHA256 = strings.Repeat("1", 64) })
	if _, _, err := a.downloadSelfUpdate(); err == nil || !strings.Contains(err.Error(), "контрольная сумма") {
		t.Fatalf("zip checksum: %v", err)
	}

	releaseServer(t, "99.0.0", exe, func(m *selfManifest) { m.File = "../evil.exe" })
	if v := a.CheckSelfUpdate(); v.Error == "" || v.Available {
		t.Fatalf("bad name accepted: %+v", v)
	}

	releaseServer(t, Version, exe, nil) // the same version
	if _, _, err := a.downloadSelfUpdate(); err != errNoNewer {
		t.Fatalf("same version: %v", err)
	}
	if v := a.CheckSelfUpdate(); v.Available {
		t.Fatalf("same version offered: %+v", v)
	}
}
