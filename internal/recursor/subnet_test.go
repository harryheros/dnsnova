package recursor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// geoNet answers www.example.com differently to questions that carry the
// client subnet cnNet, as a GeoDNS name server does, and records which
// questions to example.com's servers carried it.
type geoNet struct {
	*fakeNet
	mu       sync.Mutex
	withECS  int
	asked    int
	ecsTypes []uint16
}

var cnNet = netip.MustParsePrefix("203.0.113.0/24")

func (n *geoNet) send(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
	resp, err := n.fakeNet.send(ctx, addr, q, tcp)
	a := addr.Addr()
	if err != nil || (a != exA && a != ex2A) {
		return resp, err
	}
	qm, _ := parseMessage(q)
	hasECS := bytes.Contains(q, m.ClientSubnet(cnNet))
	n.mu.Lock()
	n.asked++
	if hasECS {
		n.withECS++
		n.ecsTypes = append(n.ecsTypes, qm.qtype)
	}
	n.mu.Unlock()
	if !hasECS {
		return resp, nil
	}
	msg, err := parseMessage(resp)
	if err != nil {
		return resp, nil
	}
	for i := range msg.answer {
		if msg.answer[i].typ == m.TypeA {
			msg.answer[i].data = []byte{192, 0, 2, 99} // the answer for that network
		}
	}
	return buildMessage(msg.id, msg.flags, msg.qname, msg.qtype, msg.answer, msg.authority, msg.additional, true, false, nil), nil
}

func askSubnet(t *testing.T, r *Recursor, name string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := buildQuery(78, dotted(name), m.TypeA, true, nil)
	q[2] |= 1
	resp, err := r.ExchangeSubnet(ctx, q, m.ClientSubnet(cnNet))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	msg, err := parseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	return addrs(msg)
}

// ExchangeSubnet asks name servers for the client's network, and its
// answers never reach other clients through the cache, in either direction.
func TestExchangeSubnet(t *testing.T) {
	n := &geoNet{fakeNet: world()}
	r := newTest(t, n.fakeNet, false)
	r.send = n.send

	if got := addrs(ask(t, r, "www.example.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("ordinary answer: %v", got)
	}
	before := n.asked
	if got := askSubnet(t, r, "www.example.com"); len(got) != 1 || got[0] != "192.0.2.99" {
		t.Fatalf("answer for the network: %v (the ordinary one was cached and used?)", got)
	}
	if n.asked == before || n.withECS == 0 {
		t.Fatal("the name server was not asked with the client subnet")
	}
	for _, typ := range n.ecsTypes {
		if typ != m.TypeA {
			t.Fatalf("client subnet sent with a %s question", m.TypeString(typ))
		}
	}
	// the network's answer did not go into the cache
	if got := addrs(ask(t, r, "www.example.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("ordinary answer after a subnet lookup: %v", got)
	}
	// and every subnet lookup asks again, while the delegation is reused
	asked := n.asked
	askSubnet(t, r, "www.example.com")
	if n.asked != asked+1 {
		t.Fatalf("%d questions for a repeated subnet lookup, want 1 (to example.com's server only)", n.asked-asked)
	}
	// starting with an empty cache: the subnet answer stays out of it
	r.ClearCache()
	askSubnet(t, r, "www.example.com")
	if got := addrs(ask(t, r, "www.example.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("ordinary answer after a first subnet lookup: %v", got)
	}
}

// A trace with WithSubnet asks name servers for that network.
func TestTraceSubnet(t *testing.T) {
	n := &geoNet{fakeNet: world()}
	r := newTest(t, n.fakeNet, false)
	r.send = n.send
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tr := r.Trace(WithSubnet(ctx, m.ClientSubnet(cnNet)), "\x03www\x07example\x03com", m.TypeA)
	if tr.Error != "" || len(tr.Answers) != 1 || !bytes.Contains([]byte(tr.Answers[0]), []byte("192.0.2.99")) {
		t.Fatalf("trace for the network: %+v", tr)
	}
	tr = r.Trace(ctx, "\x03www\x07example\x03com", m.TypeA)
	if len(tr.Answers) != 1 || !bytes.Contains([]byte(tr.Answers[0]), []byte("198.51.100.1")) {
		t.Fatalf("ordinary trace: %+v", tr.Answers)
	}
}

// Under a zone that is not signed nothing is: no DS question is asked for
// the zones below it, so a parent server that mishandles DS questions in an
// unsigned zone (sending them down to the child, as some do) cannot break
// the lookup.
func TestNoDSBelowUnsigned(t *testing.T) {
	n := world()
	ds := 0
	send := func(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
		qm, err := parseMessage(q)
		if err == nil && qm.qtype == typeDS {
			ds++
			if qm.qname == dotted("example.com") { // answered with a referral to the child
				aq := buildQuery(qm.id, qm.qname, m.TypeA, true, nil)
				resp, err := n.send(ctx, addr, aq, tcp)
				if err != nil {
					return nil, err
				}
				rm, _ := parseMessage(resp)
				return buildMessage(rm.id, rm.flags, qm.qname, typeDS, rm.answer, rm.authority, rm.additional, true, false, nil), nil
			}
		}
		return n.send(ctx, addr, q, tcp)
	}
	r := New(Config{DNSSEC: true, RootHints: []netip.Addr{rootA}, Allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.anchors.Store(&rrset{}) // no trust anchor: the root, and so everything, is not signed
	r.send = send
	msg := ask(t, r, "www.example.com", m.TypeA)
	if got := addrs(msg); msg.rcode != m.RcodeNoError || len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("rcode %d answers %v", msg.rcode, got)
	}
	if ds != 0 {
		t.Fatalf("%d DS questions below an unsigned root", ds)
	}
}

// A parent server that sends a DS question down to the child is skipped:
// another of the parent's servers is asked, and the chain validates.
func TestDSReferralNextServer(t *testing.T) {
	r, n := newSignedTest(t)
	misled := 0
	r.send = func(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
		qm, err := parseMessage(q)
		if err == nil && qm.qtype == typeDS && qm.qname == dotted("ed.com") && misled == 0 {
			misled++
			aq := buildQuery(qm.id, qm.qname, m.TypeA, true, nil)
			resp, err := n.send(ctx, addr, aq, tcp)
			if err != nil {
				return nil, err
			}
			rm, _ := parseMessage(resp)
			return buildMessage(rm.id, rm.flags, qm.qname, typeDS, rm.answer, rm.authority, rm.additional, true, true, nil), nil
		}
		return n.send(ctx, addr, q, tcp)
	}
	// a trace reads nothing from the cache, so it asks for the DS itself
	// rather than using the one that came with the referral
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr := r.Trace(ctx, dotted("www.ed.com"), m.TypeA)
	if misled != 1 {
		t.Fatalf("the misleading server was asked %d times", misled)
	}
	if tr.Rcode != "NOERROR" || tr.DNSSEC != "secure" || len(tr.Answers) == 0 {
		t.Fatalf("trace %s %s %v %s", tr.Rcode, tr.DNSSEC, tr.Answers, tr.Error)
	}
}

// When no server of a zone answers, the error says which zone, which
// servers, and what each did; it is still ErrUnreachable.
func TestUnreachableSaysWhy(t *testing.T) {
	n := world()
	r := newTest(t, n, false)
	r.send = func(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
		if a := addr.Addr(); a == exA || a == ex2A {
			qm, _ := parseMessage(q)
			return buildMessage(qm.id, m.FlagQR|m.RcodeRefused, qm.qname, qm.qtype, nil, nil, nil, true, false, nil), nil
		}
		return n.send(ctx, addr, q, tcp)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := buildQuery(5, dotted("www.example.com"), m.TypeA, true, nil)
	q[2] |= 1
	_, err := r.Exchange(ctx, q)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err %v", err)
	}
	for _, want := range []string{"www.example.com. A", "no server of example.com.", exA.String() + " REFUSED", ex2A.String() + " REFUSED"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not say %q", err, want)
		}
	}
}

// A server of the zone that answers without AA (a load balancer the zone
// is delegated to) is taken at its word, not called lame.
func TestAnswerWithoutAA(t *testing.T) {
	n := world()
	r := newTest(t, n, false)
	r.send = func(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
		resp, err := n.send(ctx, addr, q, tcp)
		if a := addr.Addr(); err == nil && (a == exA || a == ex2A) {
			resp = bytes.Clone(resp)
			resp[2] &^= byte(m.FlagAA >> 8)
		}
		return resp, err
	}
	if got := addrs(ask(t, r, "www.example.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("answers %v", got)
	}
}

// When the addresses found for a zone's glueless name servers all fail,
// its other name servers are looked up and asked.
func TestMoreNameServersAfterFailures(t *testing.T) {
	good := netip.MustParseAddr("192.0.2.46")
	for run := range 10 { // which servers are looked up first is random
		n := &fakeNet{servers: map[netip.Addr]*fakeServer{
			rootA: {zones: []*fakeZone{zone(".", ". NS a.root.", "a.root. A 192.0.2.1",
				"com. NS ns.com.", "ns.com. A 192.0.2.2", "org. NS ns.org.", "ns.org. A 192.0.2.3")}},
			comA: {zones: []*fakeZone{zone("com.",
				"many.com. NS ns1.host.org.", "many.com. NS ns2.host.org.", "many.com. NS ns3.host.org.",
				"many.com. NS ns4.host.org.", "many.com. NS ns5.host.org.", "many.com. NS ns6.host.org.")}},
			orgA: {zones: []*fakeZone{zone("org.", "host.org. NS ns.host.org.", "ns.host.org. A 192.0.2.20")}},
			hostA: {zones: []*fakeZone{zone("host.org.", "ns.host.org. A 192.0.2.20",
				// five name servers that do not answer (no server at those addresses)
				"ns1.host.org. A 192.0.2.41", "ns2.host.org. A 192.0.2.42", "ns3.host.org. A 192.0.2.43",
				"ns4.host.org. A 192.0.2.44", "ns5.host.org. A 192.0.2.45", "ns6.host.org. A 192.0.2.46")}},
			good: {zones: []*fakeZone{zone("many.com.", "www.many.com. A 198.51.100.7")}},
		}}
		r := newTest(t, n, false)
		if got := addrs(ask(t, r, "www.many.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.7" {
			t.Fatalf("run %d: answers %v", run, got)
		}
	}
}

// A shortened (minimised) name that no server of a zone answers usably is
// asked again in full, rather than ending the lookup.
func TestMinimisedNameFallsBack(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	full := dotted("a.b.c.example.com")
	r.send = func(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
		if a := addr.Addr(); a == exA || a == ex2A {
			qm, _ := parseMessage(q)
			if qm.qname != full { // only the full name gets a proper answer
				return buildMessage(qm.id, m.FlagQR, qm.qname, qm.qtype, nil, nil, nil, true, false, nil), nil
			}
		}
		return n.send(ctx, addr, q, tcp)
	}
	if got := addrs(ask(t, r, "a.b.c.example.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.9" {
		t.Fatalf("answers %v", got)
	}
}

// A name server whose only known addresses are IPv6, and failing: its
// IPv4 addresses are looked up and asked.
func TestIPv4WhenIPv6Fails(t *testing.T) {
	n := world()
	n.servers[comA].zones[0] = zone("com.",
		"example.com. NS ns1.example.com.", "ns1.example.com. A 192.0.2.10",
		"v6only.com. NS dns6.host.org.")
	n.servers[hostA].zones = append(n.servers[hostA].zones, zone("host.org.",
		"ns.host.org. A 192.0.2.20", "dns6.host.org. A 192.0.2.47", "dns6.host.org. AAAA 2001:db8::99"))
	n.servers[hostA].zones = n.servers[hostA].zones[1:] // the new host.org replaces the first
	n.servers[netip.MustParseAddr("192.0.2.47")] = &fakeServer{zones: []*fakeZone{zone("v6only.com.", "www.v6only.com. A 198.51.100.8")}}
	r := dualStackRecursor(n, n.send) // 2001:db8::99 has no server: it times out
	r.hostV6 = func() bool { return true }
	r.v6ok.Store(time.Now().UnixNano())
	// learn only the IPv6 address of the name server
	if msg := ask(t, r, "dns6.host.org", m.TypeAAAA); len(msg.answer) != 1 {
		t.Fatalf("AAAA: %d answers", len(msg.answer))
	}
	if got := addrs(ask(t, r, "www.v6only.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.8" {
		t.Fatalf("answers %v", got)
	}
}
