package recursor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// A fake, unsigned internet for testing iteration: servers by address,
// each serving zones written as text.

type fakeZone struct {
	apex string
	recs []rr
}

type fakeServer struct {
	zones   []*fakeZone
	refuse  bool // answer REFUSED
	silent  bool // never answer
	tc      bool // truncate UDP answers
	entNX   bool // NXDOMAIN for empty non-terminals (a broken server)
	extra   []rr // added to every answer (poisoning attempts)
	queries atomic.Int64
	tcp     atomic.Int64
	seen    sync.Map // qname -> true
}

type fakeNet struct {
	servers map[netip.Addr]*fakeServer
}

// zone parses lines of "name type data" (names relative to nothing: full).
func zone(apex string, lines ...string) *fakeZone {
	z := &fakeZone{apex: dotted(apex)}
	for _, l := range lines {
		f := strings.Fields(l)
		name := dotted(f[0])
		var t uint16
		var data []byte
		switch f[1] {
		case "A":
			data = netip.MustParseAddr(f[2]).AsSlice()
			t = m.TypeA
		case "AAAA":
			data = netip.MustParseAddr(f[2]).AsSlice()
			t = m.TypeAAAA
		case "NS", "CNAME", "DNAME":
			data = append([]byte(dotted(f[2])), 0)
			t = map[string]uint16{"NS": m.TypeNS, "CNAME": m.TypeCNAME, "DNAME": typeDNAME}[f[1]]
		case "TXT":
			data = append([]byte{byte(len(f[2]))}, f[2]...)
			t = typeTXT
		}
		z.recs = append(z.recs, rr{name: name, typ: t, class: 1, ttl: 300, data: data})
	}
	soa := append(append([]byte(dotted("ns."+apex)), 0), append([]byte(dotted("h."+apex)), 0)...)
	soa = append(soa, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 60)
	z.recs = append(z.recs, rr{name: z.apex, typ: m.TypeSOA, class: 1, ttl: 300, data: soa})
	return z
}

func (s *fakeServer) answer(q *message) []byte {
	if s.refuse {
		return buildMessage(q.id, m.FlagQR|m.RcodeRefused, q.qname, q.qtype, nil, nil, nil, false, false, nil)
	}
	var z *fakeZone
	for _, c := range s.zones {
		if isSub(q.qname, c.apex) && (z == nil || len(c.apex) > len(z.apex)) {
			z = c
		}
	}
	if z == nil {
		return buildMessage(q.id, m.FlagQR|m.RcodeRefused, q.qname, q.qtype, nil, nil, nil, false, false, nil)
	}
	flags := uint16(m.FlagQR | m.FlagAA)
	soa := []rr{z.recs[len(z.recs)-1]}
	// a delegation on the way down?
	for n := q.qname; n != z.apex && isSub(n, z.apex); n = parent(n) {
		var ns, glue []rr
		for _, r := range z.recs {
			if r.name == n && r.typ == m.TypeNS {
				ns = append(ns, r)
				host := lower(nameOf(r.data))
				for _, g := range z.recs {
					if g.name == host && (g.typ == m.TypeA || g.typ == m.TypeAAAA) {
						glue = append(glue, g)
					}
				}
			}
		}
		if len(ns) > 0 && !(q.qtype == typeDS && n == q.qname) {
			return buildMessage(q.id, m.FlagQR, q.qname, q.qtype, nil, ns, append(glue, s.extra...), false, false, nil)
		}
	}
	var an []rr
	name := q.qname
	for hop := 0; hop < 8; hop++ {
		found := false
		for _, r := range z.recs {
			if r.name == name && (r.typ == q.qtype || r.typ == m.TypeCNAME && q.qtype != m.TypeCNAME) {
				an = append(an, r)
				found = true
				if r.typ == m.TypeCNAME {
					name = lower(nameOf(r.data))
				}
			}
		}
		if !found || !isSub(name, z.apex) {
			break
		}
		if an[len(an)-1].typ != m.TypeCNAME {
			break
		}
	}
	if len(an) > 0 {
		return buildMessage(q.id, flags, q.qname, q.qtype, append(an, s.extra...), nil, nil, false, false, nil)
	}
	exists := false
	for _, r := range z.recs {
		if r.name == q.qname || (isSub(r.name, q.qname) && !s.entNX) {
			exists = true
		}
	}
	if exists {
		return buildMessage(q.id, flags, q.qname, q.qtype, nil, soa, s.extra, false, false, nil)
	}
	return buildMessage(q.id, flags|m.RcodeNXDomain, q.qname, q.qtype, nil, soa, s.extra, false, false, nil)
}

func (n *fakeNet) send(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
	s := n.servers[addr.Addr()]
	if s == nil {
		return nil, context.DeadlineExceeded
	}
	s.queries.Add(1)
	if tcp {
		s.tcp.Add(1)
	}
	if s.silent {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	msg, err := parseMessage(q)
	if err != nil {
		return nil, err
	}
	s.seen.Store(m.NameString(msg.qname), true)
	resp := s.answer(msg)
	if s.tc && !tcp {
		resp = resp[:m.HeaderLen]
		resp[2] |= byte(m.FlagTC >> 8)
		resp[5] = 0
		return buildMessage(msg.id, m.FlagQR|m.FlagAA|m.FlagTC, msg.qname, msg.qtype, nil, nil, nil, false, false, nil), nil
	}
	return resp, nil
}

var (
	rootA = netip.MustParseAddr("192.0.2.1")
	comA  = netip.MustParseAddr("192.0.2.2")
	exA   = netip.MustParseAddr("192.0.2.10")
	ex2A  = netip.MustParseAddr("192.0.2.11")
	orgA  = netip.MustParseAddr("192.0.2.3")
	hostA = netip.MustParseAddr("192.0.2.20")
	bankA = netip.MustParseAddr("192.0.2.30")
)

func world() *fakeNet {
	return &fakeNet{servers: map[netip.Addr]*fakeServer{
		rootA: {zones: []*fakeZone{zone(".",
			". NS a.root.",
			"a.root. A 192.0.2.1",
			"com. NS ns.com.", "ns.com. A 192.0.2.2",
			"org. NS ns.org.", "ns.org. A 192.0.2.3",
		)}},
		comA: {zones: []*fakeZone{zone("com.",
			"example.com. NS ns1.example.com.", "ns1.example.com. A 192.0.2.10",
			"example.com. NS ns2.example.com.", "ns2.example.com. A 192.0.2.11",
			"glueless.com. NS ns.host.org.",
			"bank.com. NS ns.bank.com.", "ns.bank.com. A 192.0.2.30",
			"loopa.com. NS ns.loopb.com.",
			"loopb.com. NS ns.loopa.com.",
		)}},
		orgA: {zones: []*fakeZone{zone("org.",
			"host.org. NS ns.host.org.", "ns.host.org. A 192.0.2.20",
		)}},
		exA: {zones: []*fakeZone{zone("example.com.",
			"www.example.com. A 198.51.100.1",
			"alias.example.com. CNAME www.example.com.",
			"out.example.com. CNAME www.bank.com.",
			"loop1.example.com. CNAME loop2.example.com.",
			"loop2.example.com. CNAME loop1.example.com.",
			"a.b.c.example.com. A 198.51.100.9",
		)}},
		ex2A: {zones: []*fakeZone{zone("example.com.",
			"www.example.com. A 198.51.100.1",
			"alias.example.com. CNAME www.example.com.",
			"out.example.com. CNAME www.bank.com.",
			"loop1.example.com. CNAME loop2.example.com.",
			"loop2.example.com. CNAME loop1.example.com.",
			"a.b.c.example.com. A 198.51.100.9",
		)}},
		hostA: {zones: []*fakeZone{
			zone("host.org.", "ns.host.org. A 192.0.2.20"),
			zone("glueless.com.", "www.glueless.com. A 198.51.100.2"),
		}},
		bankA: {zones: []*fakeZone{zone("bank.com.", "www.bank.com. A 203.0.113.1")}},
	}}
}

func newTest(t *testing.T, n *fakeNet, min bool) *Recursor {
	t.Helper()
	r := New(Config{QNameMinimisation: min, RootHints: []netip.Addr{rootA}, Allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.send = n.send
	return r
}

func ask(t *testing.T, r *Recursor, name string, qtype uint16) *message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := buildQuery(77, dotted(name), qtype, true)
	q[2] |= 1 // RD
	resp, err := r.Exchange(ctx, q)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	msg, err := parseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func addrs(msg *message) []string {
	var out []string
	for _, a := range msg.answer {
		if a.typ == m.TypeA {
			ip, _ := netip.AddrFromSlice(a.data)
			out = append(out, ip.String())
		}
	}
	return out
}

func TestIterate(t *testing.T) {
	for _, min := range []bool{true, false} {
		n := world()
		r := newTest(t, n, min)
		msg := ask(t, r, "www.example.com.", m.TypeA)
		if msg.rcode != 0 || len(addrs(msg)) != 1 || addrs(msg)[0] != "198.51.100.1" || msg.flags&m.FlagRA == 0 || msg.aa() {
			t.Fatalf("min=%v: %+v", min, msg)
		}
		before := r.Stats.Queries.Load()
		ask(t, r, "WWW.example.com.", m.TypeA)
		if r.Stats.Queries.Load() != before {
			t.Fatal("cached answer not used")
		}
		// a CNAME inside the zone and one to another zone
		if msg := ask(t, r, "alias.example.com.", m.TypeA); len(msg.answer) != 2 || addrs(msg)[0] != "198.51.100.1" {
			t.Fatalf("alias: %+v", msg.answer)
		}
		if msg := ask(t, r, "out.example.com.", m.TypeA); len(msg.answer) != 2 || addrs(msg)[0] != "203.0.113.1" {
			t.Fatalf("out of zone CNAME: %+v", msg.answer)
		}
		if msg := ask(t, r, "nope.example.com.", m.TypeA); msg.rcode != m.RcodeNXDomain || len(msg.authority) != 1 {
			t.Fatalf("NXDOMAIN: %+v", msg)
		}
		if msg := ask(t, r, "www.example.com.", typeTXT); msg.rcode != 0 || len(msg.answer) != 0 || len(msg.authority) != 1 {
			t.Fatalf("NODATA: %+v", msg)
		}
		if msg := ask(t, r, "b.c.example.com.", m.TypeA); msg.rcode != 0 {
			t.Fatalf("empty non-terminal: %+v", msg)
		}
		// glueless delegation: the name server's address is looked up first
		if msg := ask(t, r, "www.glueless.com.", m.TypeA); len(addrs(msg)) != 1 {
			t.Fatalf("glueless: %+v", msg)
		}
		if msg := ask(t, r, "loop1.example.com.", m.TypeA); msg.rcode != m.RcodeServFail {
			t.Fatalf("CNAME loop: %+v", msg)
		}
	}
}

func TestQNameMinimisation(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	ask(t, r, "a.b.c.example.com.", m.TypeA)
	if _, ok := n.servers[rootA].seen.Load("a.b.c.example.com."); ok {
		t.Fatal("the root saw the whole name")
	}
	if _, ok := n.servers[comA].seen.Load("a.b.c.example.com."); ok {
		t.Fatal("com saw the whole name")
	}
	// a broken server that says NXDOMAIN for an empty non-terminal: asked
	// again with the whole name
	n = world()
	n.servers[exA].entNX, n.servers[ex2A].entNX = true, true
	r = newTest(t, n, true)
	if msg := ask(t, r, "a.b.c.example.com.", m.TypeA); len(addrs(msg)) != 1 {
		t.Fatalf("fallback to the full name: %+v", msg)
	}
}

func TestLameAndDeadServers(t *testing.T) {
	for _, broken := range []string{"refuse", "silent"} {
		n := world()
		if broken == "refuse" {
			n.servers[exA].refuse = true
		} else {
			n.servers[exA].silent = true
		}
		r := newTest(t, n, true)
		for i := 0; i < 3; i++ {
			r.sets.clear()
			r.negs.clear()
			if msg := ask(t, r, "www.example.com.", m.TypeA); len(addrs(msg)) != 1 {
				t.Fatalf("%s: %+v", broken, msg)
			}
		}
		// the broken server is avoided after a while
		if q := n.servers[exA].queries.Load(); q > 3 {
			t.Errorf("%s: asked %d times", broken, q)
		}
	}
	// every server dead: an error, quickly
	n := world()
	n.servers[exA].silent, n.servers[ex2A].silent = true, true
	r := newTest(t, n, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	q := buildQuery(1, dotted("www.example.com."), 1, true)
	if _, err := r.Exchange(ctx, q); err == nil || time.Since(start) > 4*time.Second {
		t.Fatalf("all dead: %v after %v", err, time.Since(start))
	}
}

func TestTruncatedUsesTCP(t *testing.T) {
	n := world()
	n.servers[exA].tc, n.servers[ex2A].tc = true, true
	r := newTest(t, n, true)
	if msg := ask(t, r, "www.example.com.", m.TypeA); len(addrs(msg)) != 1 {
		t.Fatalf("%+v", msg)
	}
	if n.servers[exA].tcp.Load()+n.servers[ex2A].tcp.Load() == 0 {
		t.Fatal("TCP not used")
	}
}

func TestPoisoningIgnored(t *testing.T) {
	n := world()
	evil := []rr{
		{name: dotted("www.bank.com."), typ: m.TypeA, class: 1, ttl: 86400, data: []byte{6, 6, 6, 6}},
		{name: dotted("bank.com."), typ: m.TypeNS, class: 1, ttl: 86400, data: append([]byte(dotted("ns.evil.example.com.")), 0)},
	}
	n.servers[exA].extra, n.servers[ex2A].extra = evil, evil
	r := newTest(t, n, true)
	ask(t, r, "www.example.com.", m.TypeA)
	ask(t, r, "nope.example.com.", m.TypeA)
	if msg := ask(t, r, "www.bank.com.", m.TypeA); len(addrs(msg)) != 1 || addrs(msg)[0] != "203.0.113.1" {
		t.Fatalf("poisoned: %+v", msg.answer)
	}
	if n.servers[bankA].queries.Load() == 0 {
		t.Fatal("the real server was not asked")
	}
}

func TestNameServerLoopEnds(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := r.Exchange(ctx, buildQuery(1, dotted("www.loopa.com."), 1, true))
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("NS loop: %v after %v", err, time.Since(start))
	}
	if q := r.Stats.Queries.Load(); q > maxQueriesPerTask {
		t.Fatalf("%d queries", q)
	}
}

func TestManyGluelessNameServers(t *testing.T) {
	// NXNSAttack: a referral to many name servers in other zones
	n := world()
	lines := []string{}
	for i := 0; i < 40; i++ {
		lines = append(lines, "attack.com. NS ns"+string(rune('a'+i%26))+string(rune('a'+i/26))+".victim.org.")
	}
	n.servers[comA].zones = append(n.servers[comA].zones, zone("com.", append(lines,
		"example.com. NS ns1.example.com.", "ns1.example.com. A 192.0.2.10")...))
	r := newTest(t, n, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.Exchange(ctx, buildQuery(1, dotted("www.attack.com."), 1, true))
	if q := n.servers[orgA].queries.Load(); q > 12 {
		t.Fatalf("%d queries about the victim's names", q)
	}
}

func TestSpecialNames(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	if msg := ask(t, r, "localhost.", m.TypeA); len(addrs(msg)) != 1 || addrs(msg)[0] != "127.0.0.1" {
		t.Fatalf("localhost: %+v", msg)
	}
	for _, name := range []string{"x.onion.", "printer.local.", "1.1.168.192.in-addr.arpa.", "a.invalid.", "router.home.arpa."} {
		if msg := ask(t, r, name, m.TypeA); msg.rcode != m.RcodeNXDomain {
			t.Errorf("%s: %d", name, msg.rcode)
		}
	}
	if q := r.Stats.Queries.Load(); q != 0 {
		t.Fatalf("%d queries sent for local names", q)
	}
}

func TestAddressesNotAsked(t *testing.T) {
	r := New(Config{BlockPrivate: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c := r.cfg.Load()
	for _, a := range []string{"127.0.0.1", "0.0.0.0", "::1", "169.254.1.1", "fe80::1", "224.0.0.1", "10.1.2.3", "192.168.1.1", "100.64.0.1", "0.1.2.3", "fd00::1"} {
		if r.allowed(c, netip.MustParseAddr(a)) {
			t.Errorf("%s allowed", a)
		}
	}
	if !r.allowed(c, netip.MustParseAddr("8.8.8.8")) {
		t.Error("public address refused")
	}
	if r.allowed(c, netip.MustParseAddr("2001:db8::1")) {
		t.Error("IPv6 used while off")
	}
}

// TestBrokenIPv6 has every domain's name servers on IPv4 and on IPv6, where
// IPv6 silently drops everything (a route that leads nowhere). Asking over
// IPv6 first would cost a timeout for many names.
func TestBrokenIPv6(t *testing.T) {
	n := world()
	com := n.servers[comA].zones[0]
	for i := range 15 {
		v4 := netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + i)})
		v6 := netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", 0x100+i))
		z := fmt.Sprintf("z%d.com.", i)
		more := zone("com.", z+" NS ns."+z, "ns."+z+" A "+v4.String(), "ns."+z+" AAAA "+v6.String())
		com.recs = append(com.recs, more.recs...)
		n.servers[v4] = &fakeServer{zones: []*fakeZone{zone(z, "www."+z+" A 198.51.100.7")}}
		n.servers[v6] = &fakeServer{silent: true}
	}
	r := New(Config{IPv6: true, RootHints: []netip.Addr{rootA},
		Allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.send = n.send
	r.hostV6 = func() bool { return true } // configured, but broken
	start := time.Now()
	for i := range 15 {
		if msg := ask(t, r, fmt.Sprintf("www.z%d.com", i), m.TypeA); msg.rcode != m.RcodeNoError || len(msg.answer) == 0 {
			t.Fatalf("z%d: rcode %d", i, msg.rcode)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("15 names took %v: broken IPv6 is waited for", d)
	}
}

// TestServerRecovers: a server that timed out ranks behind the others, but
// only for a while; after infraForget it is tried again.
func TestServerRecovers(t *testing.T) {
	in := newInfra()
	now := time.Unix(1_900_000_000, 0)
	bad, good := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	in.ok(good, 80*time.Millisecond, now)
	for range 3 {
		in.fail(bad, now)
	}
	if in.score(bad, "example.", now) <= in.score(good, "example.", now) {
		t.Fatal("a server that just timed out must rank behind one that answers")
	}
	later := now.Add(infraForget + time.Minute)
	if d := in.score(bad, "example.", later); d > unknownRTT+time.Second {
		t.Fatalf("still penalised %v after %v: it would never be tried again", d, infraForget)
	}
}

// dualStack is world() plus 15 domains whose name servers have IPv4 and
// IPv6 addresses; the IPv6 ones never answer.
func dualStack() *fakeNet {
	n := world()
	com := n.servers[comA].zones[0]
	for i := range 15 {
		v4 := netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + i)})
		v6 := netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", 0x100+i))
		z := fmt.Sprintf("z%d.com.", i)
		more := zone("com.", z+" NS ns."+z, "ns."+z+" A "+v4.String(), "ns."+z+" AAAA "+v6.String())
		com.recs = append(com.recs, more.recs...)
		n.servers[v4] = &fakeServer{zones: []*fakeZone{zone(z, "www."+z+" A 198.51.100.7")}}
		n.servers[v6] = &fakeServer{silent: true}
	}
	return n
}

func dualStackRecursor(n *fakeNet, send func(context.Context, netip.AddrPort, []byte, bool) ([]byte, error)) *Recursor {
	r := New(Config{IPv6: true, RootHints: []netip.Addr{rootA},
		Allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.send = send
	return r
}

// TestIPv6Unusable: a machine without an IPv6 address that reaches the
// internet never tries IPv6; one where sending over IPv6 is refused (a
// firewall rule, IPv6 turned off) stops trying after the first refusal.
func TestIPv6Unusable(t *testing.T) {
	for _, c := range []struct {
		name   string
		hostV6 bool
		err    error
		most   int64
	}{
		{"no address", false, nil, 0},
		{"firewall", true, syscall.EPERM, 1},
		{"turned off", true, syscall.EAFNOSUPPORT, 1},
		{"no address to send from", true, syscall.EADDRNOTAVAIL, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := dualStack()
			var v6 atomic.Int64
			r := dualStackRecursor(n, func(ctx context.Context, ap netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
				if ap.Addr().Is6() {
					v6.Add(1)
					if c.err != nil {
						return nil, &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", c.err)}
					}
				}
				return n.send(ctx, ap, q, tcp)
			})
			r.hostV6 = func() bool { return c.hostV6 }
			// put the IPv6 servers first, as if they had answered fast before
			for i := range 15 {
				r.infra.ok(netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", 0x100+i)), time.Millisecond, time.Now())
			}
			r.v6ok.Store(time.Now().UnixNano())
			for i := range 15 {
				if msg := ask(t, r, fmt.Sprintf("www.z%d.com", i), m.TypeA); msg.rcode != m.RcodeNoError || len(msg.answer) == 0 {
					t.Fatalf("z%d: rcode %d", i, msg.rcode)
				}
			}
			if got := v6.Load(); got > c.most {
				t.Fatalf("%d queries over IPv6, want at most %d", got, c.most)
			}
		})
	}
}

// TestIPv6Works: where IPv6 works it keeps being used.
func TestIPv6Works(t *testing.T) {
	n := dualStack()
	for i := range 15 {
		z := fmt.Sprintf("z%d.com.", i)
		n.servers[netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", 0x100+i))] = &fakeServer{zones: []*fakeZone{zone(z, "www."+z+" A 198.51.100.7")}}
	}
	var v6 atomic.Int64
	r := dualStackRecursor(n, func(ctx context.Context, ap netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
		if ap.Addr().Is6() {
			v6.Add(1)
		}
		return n.send(ctx, ap, q, tcp)
	})
	r.hostV6 = func() bool { return true }
	for i := range 15 {
		r.infra.ok(netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", 0x100+i)), time.Millisecond, time.Now())
	}
	r.v6ok.Store(time.Now().UnixNano())
	for i := range 15 {
		if msg := ask(t, r, fmt.Sprintf("www.z%d.com", i), m.TypeA); msg.rcode != m.RcodeNoError {
			t.Fatalf("z%d: rcode %d", i, msg.rcode)
		}
	}
	if v6.Load() < 10 {
		t.Fatalf("only %d queries over working, faster IPv6", v6.Load())
	}
}

// TestServerTableBounded: the table of name servers stops growing.
func TestServerTableBounded(t *testing.T) {
	in := newInfra()
	now := time.Now()
	for i := range maxServers + 5000 {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		in.ok(a, time.Millisecond, now)
	}
	if n := in.size(); n > maxServers {
		t.Fatalf("%d servers remembered, limit %d", n, maxServers)
	}
}
