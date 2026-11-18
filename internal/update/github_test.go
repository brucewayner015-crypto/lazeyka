package update

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestNetError(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://release-assets.githubusercontent.com/x?sig=SECRET&jwt=LONG", Err: errors.New("net/http: TLS handshake timeout")}
	got := NetError(err)
	if strings.Contains(got, "SECRET") || !strings.HasPrefix(got, "release-assets.githubusercontent.com: TLS-соединение") {
		t.Fatal(got)
	}
	if !Temporary(errors.New("загрузка x: " + got)) {
		t.Fatal("handshake timeout should be retried")
	}
	if Temporary(errors.New("контрольная сумма не совпала")) {
		t.Fatal("checksum mismatch must not be retried")
	}
}
