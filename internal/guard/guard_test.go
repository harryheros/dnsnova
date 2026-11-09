package guard

import (
	"net/netip"
	"testing"
	"time"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestKeys(t *testing.T) {
	if ClientKey(ip("2001:db8:0:1::1")) != ClientKey(ip("2001:db8:0:ff::9")) {
		t.Fatal("IPv6 clients are grouped by /56")
	}
	if ClientKey(ip("2001:db8:0:100::1")) == ClientKey(ip("2001:db8:0:1::1")) {
		t.Fatal("different /56 must differ")
	}
	if NetworkKey(ip("192.0.2.1")) != NetworkKey(ip("192.0.2.200")) || NetworkKey(ip("::ffff:192.0.2.9")) != NetworkKey(ip("192.0.2.1")) {
		t.Fatal("IPv4 networks are grouped by /24")
	}
}

func TestBucketBurstAndBoundedMemory(t *testing.T) {
	now := int64(0)
	b := NewBucket[netip.Addr](10, 5, 640, hashAddr)
	b.now = func() int64 { return now }
	ok := 0
	for i := 0; i < 20; i++ {
		if b.Allow(ip("192.0.2.1")) {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("burst allowed %d, want 5", ok)
	}
	now += 1e8 // 100 ms = 1 token at 10/s
	if !b.Allow(ip("192.0.2.1")) || b.Allow(ip("192.0.2.1")) {
		t.Fatal("refill")
	}
	for i := 0; i < 5000; i++ {
		b.Allow(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}))
	}
	if n := b.Len(); n > 640+64 {
		t.Fatalf("bucket holds %d keys, cap is about 640", n)
	}
	if NewBucket[netip.Addr](0, 0, 10, hashAddr) != nil {
		t.Fatal("rate 0 disables the limiter")
	}
	var off *Bucket[netip.Addr]
	if !off.Allow(ip("192.0.2.1")) {
		t.Fatal("nil limiter allows everything")
	}
}

func TestGuardOrderAndModes(t *testing.T) {
	g := New(Limits{Private: true, Allow: ACL{netip.MustParsePrefix("10.0.0.0/8")}, ClientQPS: 1, ClientBurst: 2})
	if g.Admit(ip("192.0.2.1")) != DenyACL || g.Permitted(ip("192.0.2.1")) {
		t.Fatal("private mode must deny unlisted clients")
	}
	if g.Admit(ip("10.1.1.1")) != Allow || g.Admit(ip("10.1.1.1")) != Allow || g.Admit(ip("10.1.1.1")) != DenyClient {
		t.Fatal("client limit")
	}
	if g.Admit(ip("10.1.1.2")) != Allow {
		t.Fatal("another client has its own budget")
	}

	pub := New(Limits{NetworkQPS: 1, NetworkBurst: 3})
	got := []Verdict{}
	for i := 1; i <= 4; i++ {
		got = append(got, pub.Admit(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})))
	}
	if got[2] != Allow || got[3] != DenyNetwork {
		t.Fatalf("network limit across clients of one /24: %v", got)
	}
	if !pub.Permitted(ip("203.0.113.1")) {
		t.Fatal("public mode accepts everyone")
	}

	glob := New(Limits{GlobalQPS: 2})
	if glob.Admit(ip("192.0.2.1")) != Allow || glob.Admit(ip("192.0.2.2")) != Allow || glob.Admit(ip("192.0.2.3")) != DenyGlobal {
		t.Fatal("global limit")
	}
}

func TestRRL(t *testing.T) {
	r := NewRRL(2, 2)
	victim := ip("203.0.113.5")
	name := "\x07example\x03com"
	var acts []RRLAction
	for i := 0; i < 8; i++ {
		acts = append(acts, r.Check(victim, name, 1, 0))
	}
	send, slip, drop := 0, 0, 0
	for _, a := range acts {
		switch a {
		case Send:
			send++
		case Slip:
			slip++
		case Drop:
			drop++
		}
	}
	if send != 2 || slip != 3 || drop != 3 {
		t.Fatalf("send=%d slip=%d drop=%d", send, slip, drop)
	}
	if r.Check(victim, "\x05other\x03com", 1, 0) != Send {
		t.Fatal("a different answer has its own budget")
	}
	// NXDOMAIN for random names shares one budget per network
	r = NewRRL(1, 0)
	if r.Check(victim, "\x03aaa\x03com", 1, 3) != Send || r.Check(victim, "\x03bbb\x03com", 1, 3) != Drop {
		t.Fatal("NXDOMAIN grouping")
	}
	var off *RRL
	if off.Check(victim, name, 1, 0) != Send {
		t.Fatal("nil RRL sends everything")
	}
}

func TestDenyList(t *testing.T) {
	deny := ACL{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:bad::/48")}
	pub := New(Limits{Deny: deny})
	for ip, want := range map[string]Verdict{"198.51.100.7": DenyACL, "2001:db8:bad::1": DenyACL, "::ffff:198.51.100.8": DenyACL, "203.0.113.1": Allow} {
		if v := pub.Admit(netip.MustParseAddr(ip)); v != want {
			t.Errorf("public %s: %v, want %v", ip, v, want)
		}
	}
	// In private mode the deny list wins over the allow list.
	priv := New(Limits{Private: true, Allow: ACL{netip.MustParsePrefix("198.51.0.0/16")}, Deny: deny})
	if priv.Permitted(netip.MustParseAddr("198.51.100.7")) || !priv.Permitted(netip.MustParseAddr("198.51.1.1")) {
		t.Error("private mode with a deny list")
	}
}

func TestPrivateAllowsThisMachine(t *testing.T) {
	g := New(Limits{Private: true, Allow: ACL{netip.MustParsePrefix("192.168.1.0/24")}})
	for ip, want := range map[string]bool{"127.0.0.1": true, "::1": true, "192.168.1.9": true, "192.168.2.9": false, "203.0.113.5": false} {
		if got := g.Permitted(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: permitted %v, want %v", ip, got, want)
		}
	}
}

// TestGlobalBelowOne: a rate under one query per second lets a query
// through now and then, instead of none ever.
func TestGlobalBelowOne(t *testing.T) {
	g := NewGlobal(0.5)
	if !g.Allow() {
		t.Fatal("first query refused")
	}
	if g.Allow() {
		t.Fatal("second query at once allowed with 0.5 per second")
	}
	g.last -= int64(3 * time.Second)
	if !g.Allow() {
		t.Fatal("still refused after 3 seconds")
	}
}
