package config

import (
	"strings"
	"testing"
)

func TestParseForwardZones(t *testing.T) {
	got, err := ParseForwardZones([]string{
		"Corp.Example. 10.0.0.53 10.0.0.54:5353",
		"lan 192.168.1.1",
		"168.192.in-addr.arpa 192.168.1.1",
		"secure.example tls://dns.corp.example#10.0.0.53 https://dns.corp.example/dns-query",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].Name != "corp.example" || len(got[0].Servers) != 2 || got[1].Name != "lan" {
		t.Fatalf("%+v", got)
	}
	for _, bad := range []struct{ entry, want string }{
		{"corp.example", "write a domain and its servers"},
		{"corp..example 10.0.0.53", "not a valid domain"},
		{"*.corp.example 10.0.0.53", "not a valid domain"},
		{"localhost 10.0.0.53", "answered by DNSNova itself"},
		{"app.localhost 10.0.0.53", "answered by DNSNova itself"},
		{"_dns.resolver.arpa 10.0.0.53", "answered by DNSNova itself"},
		{"corp.example dc1.corp.example", "plain DNS upstreams must be IP addresses"},
		{"corp.example ftp://10.0.0.53", "unsupported scheme"},
	} {
		_, err := ParseForwardZones([]string{bad.entry})
		if err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%q: %v", bad.entry, err)
		}
	}
	if _, err := ParseForwardZones([]string{"a.example 10.0.0.1", "A.example. 10.0.0.2"}); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Errorf("duplicate: %v", err)
	}
}
