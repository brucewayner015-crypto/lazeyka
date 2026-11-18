package core

import (
	"embed"
	"time"
)

// A copy of the routing lists taken when this version was built. It is used
// when the lists cannot be downloaded on the first start (GitHub is often
// unreachable from Russia without a VPN): routing works right away, and
// mihomo replaces the copy with fresh lists once it can reach GitHub.
//
//go:embed rules/*.mrs
var ruleSnapshot embed.FS

// RuleSnapshotDate is when the built-in copy was taken.
var RuleSnapshotDate = time.Date(2026, time.November, 17, 12, 0, 0, 0, time.UTC)

// RuleSnapshot returns the built-in copy of a rule set.
func RuleSnapshot(name string) ([]byte, bool) {
	b, err := ruleSnapshot.ReadFile("rules/" + name + ".mrs")
	return b, err == nil && len(b) > 0
}
