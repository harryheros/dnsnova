package upstream

import "testing"

// Any upstream address typed into the settings: parsing never panics, and
// what parses has a known scheme and a usable port.
func FuzzParseSpec(f *testing.F) {
	for _, s := range []string{"https://1.1.1.1/dns-query", "tls://dns.google", "quic://dns.adguard-dns.com", "8.8.8.8", "udp://[2001:db8::1]:5353", "tls://one.one.one.one#1.1.1.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		s, err := ParseSpec(raw)
		if err != nil {
			return
		}
		switch s.Scheme {
		case "udp", "tcp", "tls", "https", "quic":
		default:
			t.Fatalf("%q: scheme %q", raw, s.Scheme)
		}
		if s.Port < 1 || s.Port > 65535 || s.Host == "" {
			t.Fatalf("%q: host %q port %d", raw, s.Host, s.Port)
		}
	})
}
