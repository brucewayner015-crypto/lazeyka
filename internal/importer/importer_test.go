package importer

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

const awg31 = `[Interface]
Address = 10.8.1.2/32
DNS = 1.1.1.1, 1.0.0.1
PrivateKey = cGFzc3dvcmRwYXNzd29yZHBhc3N3b3JkcGFzc3dvcmQ=
Jc = 3
Jmin = 64
Jmax = 406
S1 = 20
S2 = 21
S3 = 22
S4 = 15
H1 = 123456-123500
H2 = 223456-223500
H3 = 323456-323500
H4 = 423456-423500
I1 = <rc 17><t><r 1000><r 57>
HeaderProtectionKey = aGVhZGVycHJvdGVjdGlvbmtleWhlYWRlcnByb3RlY3Q=
ContentPaddingAddition = 10-60
RekeyAfterTime = 110-130
RandomTrailers = true
DisableCookies = false

[Peer]
PublicKey = c2VydmVycHVibGlja2V5c2VydmVycHVibGlja2V5MDE=
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHM=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.10:51820
PersistentKeepalive = 22-30
`

func TestAWG31(t *testing.T) {
	p, info, err := ParseAWGConf(awg31, "test")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "3.1" {
		t.Fatalf("version %q", info.Version)
	}
	opt := p["amnezia-wg-option"].(map[string]any)
	if opt["version"] != 3 {
		t.Fatalf("want version 3, got %v", opt["version"])
	}
	if opt["header-protection-key"] != "aGVhZGVycHJvdGVjdGlvbmtleWhlYWRlcnByb3RlY3Q=" {
		t.Fatal("hpk")
	}
	if opt["random-trailers"] != true {
		t.Fatal("random-trailers")
	}
	if _, ok := opt["disable-cookies"]; ok {
		t.Fatal("disable-cookies=false must be omitted")
	}
	if opt["h1"] != "123456-123500" || opt["s3"] != 22 || opt["jc"] != 3 {
		t.Fatalf("opts %v", opt)
	}
	if p["persistent-keepalive"] != 22 {
		t.Fatalf("keepalive %v", p["persistent-keepalive"])
	}
	if p["server"] != "203.0.113.10" || p["port"] != 51820 || p["ip"] != "10.8.1.2" {
		t.Fatalf("endpoint %v", p)
	}
	if p["remote-dns-resolve"] != true {
		t.Fatal("dns")
	}
}

func TestAWG10AndWG(t *testing.T) {
	conf := `[Interface]
PrivateKey = a
Address = 10.0.0.2/32, fd00::2/128
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = b
Endpoint = [2001:db8::1]:443
`
	p, info, err := ParseAWGConf(conf, "x")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "1.0" || p["ipv6"] != "fd00::2" || p["server"] != "2001:db8::1" {
		t.Fatalf("%v %v", info, p)
	}
	wg := strings.NewReplacer("Jc = 4\n", "", "Jmin = 40\n", "", "Jmax = 70\n", "", "S1 = 0\n", "", "S2 = 0\n", "", "H1 = 1\n", "", "H2 = 2\n", "", "H3 = 3\n", "", "H4 = 4\n", "").Replace(conf)
	p, info, err = ParseAWGConf(wg, "x")
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "WireGuard" {
		t.Fatal(info.Version)
	}
	if _, ok := p["amnezia-wg-option"]; ok {
		t.Fatal("plain WG must not have amnezia options")
	}
}

func TestParseVLESSLink(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@198.51.100.7:443?type=xhttp&security=reality&sni=www.example.com&fp=chrome&pbk=PUBKEY&sid=ab12&path=%2Fx&mode=auto#My%20NL"
	r := Parse(link, "")
	if len(r.Items) != 1 || len(r.Errors) != 0 {
		t.Fatalf("%+v", r)
	}
	s := r.Items[0].Server
	if s.Name != "My NL" || s.Host != "198.51.100.7" || s.Port != 443 || s.Info != "VLESS · XHTTP · Reality" {
		t.Fatalf("%+v", s)
	}
	renamed := RenameLink(link, "Свой: NL 1")
	if !strings.HasSuffix(renamed, "#%D0%A1%D0%B2%D0%BE%D0%B9%3A%20NL%201") {
		t.Fatal(renamed)
	}
}

func TestVMessRename(t *testing.T) {
	js := `{"v":"2","ps":"old","add":"example.org","port":"443","id":"uuid","net":"ws","tls":"tls"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
	info, err := InspectLink(link)
	if err != nil || info.Host != "example.org" || info.Port != 443 {
		t.Fatalf("%v %+v", err, info)
	}
	nl := RenameLink(link, "new")
	info, _ = InspectLink(nl)
	if info.Name != "new" {
		t.Fatal(info.Name)
	}
}

func qCompress(b []byte) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(b)
	w.Close()
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, z.Bytes()...)
}

func TestAmneziaVPNLink(t *testing.T) {
	awgLast, _ := json.Marshal(map[string]any{"config": awg31, "hostName": "203.0.113.10"})
	xrayCfg := map[string]any{
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "203.0.113.10", "port": 443,
				"users": []any{map[string]any{"id": "uuid-1", "flow": "xtls-rprx-vision", "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{"serverName": "www.googletagmanager.com", "publicKey": "PBK", "shortId": "abcd", "fingerprint": "chrome"},
			},
		}},
	}
	xrayLast, _ := json.Marshal(xrayCfg)
	root := map[string]any{
		"description": "Мой сервер",
		"hostName":    "203.0.113.10",
		"containers": []any{
			map[string]any{"container": "amnezia-awg2", "awg": map[string]any{"last_config": string(awgLast), "port": "51820"}},
			map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": string(xrayLast)}},
			map[string]any{"container": "amnezia-dns"},
		},
	}
	rb, _ := json.Marshal(root)
	link := "vpn://" + base64.RawURLEncoding.EncodeToString(qCompress(rb))
	r := Parse(link, "")
	if len(r.Errors) != 0 || len(r.Items) != 2 {
		t.Fatalf("%+v", r)
	}
	if r.Items[0].Server.Kind != "awg" || r.Items[0].Server.Info != "AmneziaWG 3.1" {
		t.Fatalf("%+v", r.Items[0].Server)
	}
	x := r.Items[1].Server
	if x.Kind != "link" || !strings.Contains(x.Link, "pbk=PBK") || !strings.Contains(x.Link, "flow=xtls-rprx-vision") || x.Info != "VLESS · TCP · Reality · Vision" {
		t.Fatalf("%+v", x)
	}
	if !strings.HasPrefix(x.Name, "Мой сервер") {
		t.Fatal(x.Name)
	}
}

func TestXrayXHTTPExtra(t *testing.T) {
	cfg := `{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"address":"h.example","port":8443,"id":"u","encryption":"mlkem768x25519plus.native.0rtt.abc"},
	"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"s.example","password":"PW","shortId":""},
	"xhttpSettings":{"path":"/p","mode":"stream-one","extra":{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"}}}}}]}`
	links, err := XrayToLinks([]byte(cfg), "X")
	if err != nil {
		t.Fatal(err)
	}
	l := links[0]
	for _, want := range []string{"type=xhttp", "pbk=PW", "mode=stream-one", "extra=", "encryption=mlkem768x25519plus", "#X"} {
		if !strings.Contains(l, want) {
			t.Fatalf("missing %s in %s", want, l)
		}
	}
}

func TestSubscriptionAndBase64(t *testing.T) {
	r := Parse("https://sub.example.com/api/sub/abc?x=1", "")
	if len(r.Items) != 1 || r.Items[0].Subscription == nil || r.Items[0].Subscription.Name != "sub.example.com" {
		t.Fatalf("%+v", r)
	}
	body := "vless://u@1.2.3.4:443?security=reality&type=xhttp&pbk=k#a\ntrojan://p@5.6.7.8:443#b\n"
	r = Parse(base64.StdEncoding.EncodeToString([]byte(body)), "")
	if len(r.Items) != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestGarbage(t *testing.T) {
	r := Parse("hello world", "")
	if len(r.Items) != 0 || len(r.Errors) == 0 {
		t.Fatalf("%+v", r)
	}
}

func TestAWGTogglesAsAmneziaWritesThem(t *testing.T) {
	conf := strings.Replace(strings.Replace(awg31, "RandomTrailers = true", "RandomTrailers = on", 1), "DisableCookies = false", "DisableCookies = off", 1)
	p, info, err := ParseAWGConf(conf, "x")
	if err != nil {
		t.Fatal(err)
	}
	opt := p["amnezia-wg-option"].(map[string]any)
	if opt["random-trailers"] != true || opt["disable-cookies"] != nil || info.Version != "3.1" {
		t.Fatal(opt, info)
	}
}

// A vpn:// key of the Amnezia service (no server inside): a clear way out
// instead of "unknown JSON".
func TestAmneziaServiceKey(t *testing.T) {
	for _, c := range []struct{ json, want, not string }{
		{`{"name":"Amnezia Premium","description":"Amnezia Premium","config_version":2,"api_config":{"service_type":"amnezia-premium","service_protocol":"awg","user_country_code":"ru"},"auth_data":{"api_key":"test-key-not-real"}}`,
			"cp.amnezia.org", "Free"},
		{`{"name":"Amnezia Free","config_version":2,"api_config":{"service_type":"amnezia-free","service_protocol":"awg"},"auth_data":{"api_key":"x"}}`,
			"Amnezia Free", "cp.amnezia.org"},
		{`{"config_version":1,"api_endpoint":"https://example.invalid/","api_key":"x","name":"Old free"}`,
			"Amnezia", "неизвестный"},
	} {
		link := "vpn://" + base64.RawURLEncoding.EncodeToString(qCompress([]byte(c.json)))
		r := Parse(link, "")
		if len(r.Items) != 0 || len(r.Errors) != 1 || !strings.Contains(r.Errors[0], c.want) || strings.Contains(r.Errors[0], c.not) {
			t.Errorf("%s: %+v", c.json[:30], r)
		}
	}
}
