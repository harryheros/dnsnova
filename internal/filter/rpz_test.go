package filter

import (
	"strings"
	"testing"
)

// An RPZ zone as threat feeds publish it (URLhaus, ThreatFox, HaGeZi).
const rpzSample = `$TTL 300
$ORIGIN rpz.feed.example.
@ IN SOA localhost. root.localhost. (
        2026111401 ; serial
        3600 600 86400 300 )
  IN NS localhost.
; malware
evil.test CNAME .                 ; NXDOMAIN
*.evil.test CNAME .
nodata.test 300 IN CNAME *.
dropped.test CNAME rpz-drop.
sink.test A 0.0.0.0
sink6.test IN AAAA ::
walled.test A 192.0.2.80
Full.Test.rpz.feed.example. CNAME .
other.zone.example. CNAME .
fine.test CNAME rpz-passthru.
24.0.2.0.192.rpz-ip CNAME .
ns.bad.test.rpz-nsdname CNAME .
32.1.2.0.10.rpz-client-ip CNAME rpz-drop.
redirect.test CNAME landing.example.
`

func TestParseRPZ(t *testing.T) {
	b := NewBuilder()
	c, err := Parse(strings.NewReader(rpzSample), b)
	if err != nil {
		t.Fatal(err)
	}
	s := b.Set()
	for _, name := range []string{"evil.test", "x.evil.test", "a.b.evil.test", "nodata.test", "dropped.test",
		"sink.test", "sink6.test", "walled.test", "full.test", "redirect.test"} {
		if !s.Blocked(wireOf(t, name)) {
			t.Errorf("%s not blocked", name)
		}
	}
	for _, name := range []string{"sub.dropped.test", "fine.test", "other.zone.example", "bad.test",
		"localhost", "rpz.feed.example", "landing.example", "2026111401.test"} {
		if strings.Contains(name, ".") && s.Blocked(wireOf(t, name)) {
			t.Errorf("%s blocked", name)
		}
	}
	// Taken: evil.test, *.evil.test, nodata, dropped, sink, sink6, walled,
	// full.test, redirect.test. Skipped: a name outside the zone, passthru
	// and the IP, NS name and client triggers. The SOA and NS are neither.
	if c.Block != 9 || c.Skipped != 5 || c.Allow != 0 {
		t.Fatalf("counts %+v", c)
	}
}
