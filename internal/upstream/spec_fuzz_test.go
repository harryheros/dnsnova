package upstream

import (
	"sort"
	"testing"
)

// Any upstream address typed into the settings: parsing never panics, and
// what parses has a usable host and port and a scheme New can build a
// transport for. (The check once listed the schemes by hand; h3 was added to
// the parser later and the list was not, so the weekly fuzz run reported
// "h3://0" as an unknown scheme. Asking New keeps the two in step.)
func FuzzParseSpec(f *testing.F) {
	for _, s := range []string{"https://1.1.1.1/dns-query", "h3://1.1.1.1/dns-query", "tls://dns.google", "quic://dns.adguard-dns.com", "8.8.8.8", "udp://[2001:db8::1]:5353", "tls://one.one.one.one#1.1.1.1"} {
		f.Add(s)
	}
	d := NewDialer(nil)
	f.Fuzz(func(t *testing.T, raw string) {
		s, err := ParseSpec(raw)
		if err != nil {
			return
		}
		if _, err := New(s, d, nil); err != nil {
			t.Fatalf("%q parses (scheme %q) but has no transport: %v", raw, s.Scheme, err)
		}
		if s.Port < 1 || s.Port > 65535 || s.Host == "" {
			t.Fatalf("%q: host %q port %d", raw, s.Host, s.Port)
		}
	})
}

// TestEverySchemeHasATransport: each scheme the parser accepts parses with
// its default port and gets a transport.
func TestEverySchemeHasATransport(t *testing.T) {
	var schemes []string
	for scheme := range defaultPorts {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)
	if len(schemes) != 6 {
		t.Errorf("schemes %v: update this test and the docs when adding one", schemes)
	}
	for _, scheme := range schemes {
		s, err := ParseSpec(scheme + "://192.0.2.1")
		if err != nil {
			t.Errorf("%s: %v", scheme, err)
			continue
		}
		if s.Scheme != scheme || s.Port != defaultPorts[scheme] {
			t.Errorf("%s: parsed as scheme %q port %d", scheme, s.Scheme, s.Port)
		}
		if _, err := New(s, NewDialer(nil), nil); err != nil {
			t.Errorf("%s: no transport: %v", scheme, err)
		}
	}
}
