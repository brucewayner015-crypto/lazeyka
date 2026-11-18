package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"lazeyka/internal/update"
)

func TestLocalAssetFromDownloads(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dl := filepath.Join(home, "Downloads")
	os.MkdirAll(dl, 0o755)
	payload := []byte("pretend this is mihomo")
	sum := sha256.Sum256(payload)
	// browsers number repeated downloads: "name (1).zip"
	os.WriteFile(filepath.Join(dl, "mihomo-windows-amd64-v1-v1.19.34 (1).zip"), payload, 0o644)
	os.WriteFile(filepath.Join(dl, "unrelated.zip"), []byte("x"), 0o644)

	p := NewPaths(t.TempDir())
	os.MkdirAll(p.Tmp, 0o755)
	a := &App{P: p, ctx: context.Background()}
	rel := &update.Release{Tag: "v1.19.34"}
	asset := &update.Asset{Name: "mihomo-windows-amd64-v1-v1.19.34.zip", Digest: "sha256:" + hex.EncodeToString(sum[:])}
	dst := filepath.Join(p.Tmp, asset.Name)

	tag, ok := a.localAsset(repoMihomo, rel, asset, mihomoAsset, dst)
	if !ok || tag != "v1.19.34" {
		t.Fatalf("not found: %q %v", tag, ok)
	}
	if b, _ := os.ReadFile(dst); string(b) != string(payload) {
		t.Fatal("wrong content")
	}

	// a file whose hash does not match GitHub's digest is never used
	os.Remove(dst)
	asset.Digest = "sha256:" + hex.EncodeToString(make([]byte, 32))
	if _, ok := a.localAsset(repoMihomo, rel, asset, mihomoAsset, dst); ok {
		t.Fatal("accepted a file with the wrong hash")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("left a file behind")
	}
	// no digest from GitHub: cannot verify, so not used either
	asset.Digest = ""
	if _, ok := a.localAsset(repoMihomo, rel, asset, mihomoAsset, dst); ok {
		t.Fatal("accepted an unverifiable file")
	}
}
