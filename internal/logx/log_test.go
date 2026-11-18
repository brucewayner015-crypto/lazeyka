package logx

import "testing"

func TestShortenURLs(t *testing.T) {
	in := `initial proxy provider sub-1 error: Get "https://vpn.example.app/api/sub/SECRETTOKEN?x=1": net/http: TLS handshake timeout; see https://github.com/x and http://h:8080`
	want := `initial proxy provider sub-1 error: Get "https://vpn.example.app/…": net/http: TLS handshake timeout; see https://github.com/… and http://h:8080`
	if got := shortenURLs(in); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}
