package settings

import "testing"

func TestMigrationLiftsAutomaticZapretPause(t *testing.T) {
	s := Default()
	s.Version = 1
	s.Zapret.PauseWithVPN = "on"
	s.Normalize()
	if s.Version != 2 || s.Zapret.PauseWithVPN != "" {
		t.Fatalf("v1: %d %q", s.Version, s.Zapret.PauseWithVPN)
	}
	// from version 2 on the choice is kept
	s.Zapret.PauseWithVPN = "on"
	s.Normalize()
	if s.Zapret.PauseWithVPN != "on" {
		t.Fatalf("v2: %q", s.Zapret.PauseWithVPN)
	}
	s = Default()
	s.Version = 1
	s.Zapret.PauseWithVPN = "off"
	s.Normalize()
	if s.Zapret.PauseWithVPN != "off" {
		t.Fatalf("off: %q", s.Zapret.PauseWithVPN)
	}
}
