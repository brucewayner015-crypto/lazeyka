package app

import (
	"strings"
	"testing"
	"time"

	"lazeyka/internal/logx"
)

func TestLoopMeter(t *testing.T) {
	var m loopMeter
	now := time.Now()
	for i := 1; i < loopThreshold; i++ {
		if m.hit(now.Add(time.Duration(i) * 100 * time.Millisecond)) {
			t.Fatalf("fired early at %d", i)
		}
	}
	if !m.hit(now.Add(2 * time.Second)) {
		t.Fatal("storm not detected")
	}
	if m.hit(now.Add(3 * time.Second)) {
		t.Fatal("fired twice")
	}
	// a few stray lines spread over minutes are not a storm
	m.reset(now, 0)
	for i := 0; i < 40; i++ {
		if m.hit(now.Add(time.Duration(i) * 30 * time.Second)) {
			t.Fatal("sparse lines counted as a storm")
		}
	}
	// lines right after a fix are ignored
	m.reset(now, 15*time.Second)
	for i := 0; i < 50; i++ {
		if m.hit(now.Add(time.Duration(i) * 100 * time.Millisecond)) {
			t.Fatal("counted during the quiet time")
		}
	}
}

func TestErrorsHideSubscriptionLinks(t *testing.T) {
	a := &App{jobs: map[string]*Job{"j": {Running: true}}}
	a.jobDone("j", errorString(`не удалось обновить подписку: mihomo: Get "https://203.0.113.10/s/Zx9TestTokenAbCdEf1234": EOF`), nil)
	if strings.Contains(a.jobs["j"].Error, "Zx9TestToken") {
		t.Fatal(a.jobs["j"].Error)
	}
	a.setVPN("error", `Get "https://sub.example.com/api/sub/secret-token": EOF`)
	if strings.Contains(a.vpnErr, "secret-token") || !strings.Contains(a.vpnErr, "https://sub.example.com") {
		t.Fatal(a.vpnErr)
	}
	if logx.Redact("нет ссылок") != "нет ссылок" {
		t.Fatal("plain text changed")
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
