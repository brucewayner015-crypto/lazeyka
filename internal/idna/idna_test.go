package idna

import "testing"

func TestToASCII(t *testing.T) {
	cases := map[string]string{
		"пример.испытание": "xn--e1afmkfd.xn--80akhbyknj4f", // RFC 3492/IANA test domain
		"президент.рф":     "xn--d1abbgf6aiiy.xn--p1ai",
		"Президент.РФ":     "xn--d1abbgf6aiiy.xn--p1ai",
		"bücher.de":        "xn--bcher-kva.de",
		"münchen.de":       "xn--mnchen-3ya.de",
		"example.com":      "example.com",
		"my_host.lan":      "my_host.lan",
		"сайт。рф":          "xn--80aswg.xn--p1ai",
	}
	for in, want := range cases {
		got, err := ToASCII(in)
		if err != nil || got != want {
			t.Errorf("ToASCII(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "a..b", "бред домен", "a,b.com", "x/y.com", "ex ample.com"} {
		if got, err := ToASCII(bad); err == nil {
			t.Errorf("ToASCII(%q) = %q, want error", bad, got)
		}
	}
}
