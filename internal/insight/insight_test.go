package insight

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestDomain(t *testing.T) {
	for in, want := range map[string]string{
		"mail.Google.com.":             "google.com",
		"www.bbc.co.uk.":               "bbc.co.uk",
		"com.":                         "com",
		"4.3.2.1.in-addr.arpa.":        "in-addr.arpa (reverse lookups)",
		"b.a.8.b.d.0.1.0.0.2.ip6.arpa": "ip6.arpa (reverse lookups)",
		".":                            ".",
		"printer.lan.":                 "printer.lan",
	} {
		if got := Domain(in); got != want {
			t.Errorf("Domain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTopHidesRareNames(t *testing.T) {
	now := time.Date(2026, 1, 1, 10, 30, 0, 0, time.UTC)
	top := NewTop(true, 169, now)
	// popular.com from 40 networks, private.example from one network many times.
	for i := 0; i < 40; i++ {
		ip := netip.MustParseAddr(fmt.Sprintf("198.%d.%d.7", i/200, i))
		top.Add("popular.com", ip)
	}
	for i := 0; i < 500; i++ {
		top.Add("private.example", netip.MustParseAddr("203.0.113.5"))
		top.Add("private.example", netip.MustParseAddr("203.0.113.99")) // same /24
	}
	l := top.List(time.Hour, now, 10)
	if len(l) != 1 || l[0].Name != "popular.com" || l[0].Count != 40 {
		t.Fatalf("list = %+v", l)
	}
	// After the hour closes the counts are kept, the networks are not
	// merged across hours.
	top.Roll(now.Add(time.Hour))
	for i := 0; i < 3; i++ {
		top.Add("popular.com", netip.MustParseAddr("192.0.2.1"))
	}
	l = top.List(24*time.Hour, now.Add(time.Hour), 10)
	if len(l) != 1 || l[0].Count != 43 {
		t.Fatalf("after roll = %+v", l)
	}
	if l := top.List(time.Hour, now.Add(3*time.Hour), 10); len(l) != 0 {
		t.Fatalf("old hours in 1h list: %+v", l)
	}
}

func TestTopBounded(t *testing.T) {
	now := time.Now()
	top := NewTop(false, 2, now)
	ip := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < 200000; i++ {
		top.Add(fmt.Sprintf("r%d.example", i), ip)
	}
	n := 0
	for i := range top.live {
		n += len(top.live[i].m)
	}
	if n > shards*shardCap {
		t.Fatalf("%d live entries", n)
	}
	for h := 1; h <= 5; h++ {
		top.Roll(now.Add(time.Duration(h) * time.Hour))
	}
	if len(top.past) != 2 {
		t.Fatalf("kept %d hours", len(top.past))
	}
}

func TestQueryLog(t *testing.T) {
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	l := NewQueryLog()
	ip4, ip6 := netip.MustParseAddr("203.0.113.77"), netip.MustParseAddr("2001:db8:1:2::9")
	l.Add(Query{Time: now, Name: "off.example"}, ip4)
	if l.State(now).Count != 0 {
		t.Fatal("recorded while off")
	}
	l.Start(15*time.Minute, false, now)
	l.Add(Query{Time: now.Add(time.Minute), Name: "a.example"}, ip4)
	l.Add(Query{Time: now.Add(2 * time.Minute), Name: "b.example"}, ip6)
	r := l.Recent(10, "", now.Add(3*time.Minute))
	if len(r) != 2 || r[0].Client != "2001:db8:1::/48" || r[1].Client != "203.0.113.x" {
		t.Fatalf("recent = %+v", r)
	}
	if r := l.Recent(10, "a.ex", now.Add(3*time.Minute)); len(r) != 1 {
		t.Fatalf("filter: %+v", r)
	}
	// It stops by itself, and the records go an hour later.
	l.Add(Query{Time: now.Add(16 * time.Minute), Name: "late.example"}, ip4)
	if st := l.State(now.Add(16 * time.Minute)); st.On || st.Count != 2 {
		t.Fatalf("after expiry: %+v", st)
	}
	if st := l.State(now.Add(15*time.Minute + QueryLogKeep)); st.Count != 0 {
		t.Fatalf("records kept: %+v", st)
	}
	l.Start(time.Hour, true, now)
	l.Add(Query{Time: now, Name: "x"}, ip4)
	if r := l.Recent(1, "", now); r[0].Client != "203.0.113.77" {
		t.Fatalf("full ip: %+v", r)
	}
	l.Stop(now)
	if st := l.State(now); st.On || st.Count != 0 {
		t.Fatalf("after stop: %+v", st)
	}
}
