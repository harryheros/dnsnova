package recursor

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// A lab for networks that tamper with DNS: the fake servers of a test net
// listen on real loopback sockets, and a censor sits on the path between
// them and the resolver, which uses its real UDP socket pool and TCP.
//
// The censor behaves as measured for the Great Firewall (Hoang et al.,
// "How Great is the Great Firewall?", USENIX Security 2021): for a
// question about a censored name it sends forged answers at once, from
// the server's address, and lets the genuine answer through after them;
// over TCP it resets the connection. Or, as on networks that hijack port
// 53 (RIPE Labs, "Detecting DNS root manipulation", 2022), it answers
// every question itself and nothing reaches the servers.
type censor struct {
	names     []string      // wire names: these and every name below are censored
	aa        bool          // forged answers carry AA (one of the GFW's injectors does)
	copies    int           // forged answers per question (the GFW sends up to three)
	delay     time.Duration // the genuine answer arrives this much later
	intercept bool          // answer everything itself, over UDP and TCP
	// servers whose genuine answers have neither EDNS nor AA (some load
	// balancers): nothing is censored for them, they are only unusual
	plain    map[netip.Addr]bool
	soa      bool // with intercept: NXDOMAIN with the root's SOA, as a resolver would
	tcpBlock bool // with intercept: TCP connections are reset instead
}

func (c *censor) censored(name string) bool {
	return slices.ContainsFunc(c.names, func(n string) bool { return isSub(name, n) })
}

// forged builds what the censor sends: an A record for the name whatever
// the question's type, an address in 2001::/32 for AAAA, no EDNS.
func (c *censor) forged(q *message, i int) []byte {
	flags := uint16(m.FlagQR | m.FlagRA)
	if c.aa {
		flags |= m.FlagAA
	}
	rec := rr{name: q.qname, typ: m.TypeA, class: m.ClassIN, ttl: 60, data: []byte{31, 13, 95, byte(48 + i)}}
	if q.qtype == m.TypeAAAA {
		rec.typ, rec.data = m.TypeAAAA, netip.MustParseAddr("2001::1f0d:5f30").AsSlice()
	}
	return buildMessage(q.id, flags, q.qname, q.qtype, []rr{rec}, nil, nil, false, false, nil)
}

// hijacked is the answer of a resolver that takes over port 53.
func (c *censor) hijacked(q *message) []byte {
	var ns []rr
	if c.soa {
		soa := append(append([]byte(dotted("a.root-servers.net.")), 0), append([]byte(dotted("nstld.verisign-grs.com.")), 0)...)
		soa = append(soa, 0, 0, 0, 1, 0, 0, 7, 8, 0, 0, 3, 132, 0, 9, 58, 128, 0, 1, 81, 128)
		ns = []rr{{name: "", typ: m.TypeSOA, class: m.ClassIN, ttl: 86400, data: soa}}
	}
	return buildMessage(q.id, m.FlagQR|m.FlagRA|m.RcodeNXDomain, q.qname, q.qtype, nil, ns, nil, false, false, nil)
}

type pathLab struct {
	c      *censor
	base   func(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error)
	mu     sync.Mutex
	udp    map[netip.Addr]netip.AddrPort
	tcp    map[netip.Addr]netip.AddrPort
	closer []io.Closer
	forged atomic.Int64 // forged answers sent
	resets atomic.Int64 // TCP connections reset
}

// newPathLab serves base's servers at addrs through the censor c.
func newPathLab(t *testing.T, c *censor, addrs []netip.Addr, base func(context.Context, netip.AddrPort, []byte, bool) ([]byte, error)) *pathLab {
	t.Helper()
	l := &pathLab{c: c, base: base, udp: map[netip.Addr]netip.AddrPort{}, tcp: map[netip.Addr]netip.AddrPort{}}
	t.Cleanup(func() {
		for _, x := range l.closer {
			x.Close()
		}
	})
	for _, a := range addrs {
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		l.closer = append(l.closer, pc, ln)
		l.udp[a] = pc.LocalAddr().(*net.UDPAddr).AddrPort()
		l.tcp[a] = ln.Addr().(*net.TCPAddr).AddrPort()
		go l.serveUDP(pc, netip.AddrPortFrom(a, 53))
		go l.serveTCP(ln, netip.AddrPortFrom(a, 53))
	}
	return l
}

// withEDNS adds an OPT record to an answer to a question that had one, as
// every server that answers EDNS does.
func withEDNS(q, resp []byte) []byte {
	qm, err1 := parseMessage(q)
	rm, err2 := parseMessage(resp)
	if err1 != nil || err2 != nil || !qm.edns || rm.edns {
		return resp
	}
	return buildMessage(rm.id, rm.flags, rm.qname, rm.qtype, rm.answer, rm.authority, rm.additional, true, true, nil)
}

// finish gives a genuine answer the form its server sends.
func (l *pathLab) finish(a netip.Addr, q, resp []byte) []byte {
	if !l.c.plain[a] {
		return withEDNS(q, resp)
	}
	rm, err := parseMessage(resp)
	if err != nil {
		return resp
	}
	return buildMessage(rm.id, rm.flags&^m.FlagAA, rm.qname, rm.qtype, rm.answer, rm.authority, rm.additional, false, false, nil)
}

func (l *pathLab) serveUDP(pc *net.UDPConn, as netip.AddrPort) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			qm, err := parseMessage(q)
			if err != nil {
				return
			}
			if l.c.intercept {
				pc.WriteToUDPAddrPort(l.c.hijacked(qm), from)
				return
			}
			if l.c.censored(qm.qname) {
				for i := range max(l.c.copies, 1) {
					l.forged.Add(1)
					pc.WriteToUDPAddrPort(l.c.forged(qm, i), from)
				}
				time.Sleep(l.c.delay)
			}
			resp, err := l.base(context.Background(), as, q, false)
			if err == nil {
				pc.WriteToUDPAddrPort(l.finish(as.Addr(), q, resp), from)
			}
		}()
	}
}

func (l *pathLab) serveTCP(ln *net.TCPListener, as netip.AddrPort) {
	for {
		c, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			var lb [2]byte
			if _, err := io.ReadFull(c, lb[:]); err != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(lb[:]))
			if _, err := io.ReadFull(c, q); err != nil {
				return
			}
			qm, err := parseMessage(q)
			if err != nil {
				return
			}
			var resp []byte
			switch {
			case l.c.intercept && l.c.tcpBlock:
				l.resets.Add(1)
				c.SetLinger(0)
				return
			case l.c.intercept:
				resp = l.c.hijacked(qm)
			case l.c.censored(qm.qname):
				l.resets.Add(1)
				c.SetLinger(0) // closing now sends RST, as the censor does
				return
			default:
				if resp, err = l.base(context.Background(), as, q, true); err != nil {
					return
				}
				resp = l.finish(as.Addr(), q, resp)
			}
			c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
		}()
	}
}

// route makes r reach the lab's servers over the network: its real UDP
// socket pool and TCP connections.
func (l *pathLab) route(r *Recursor) {
	r.send = func(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
		to, ok := l.udp[addr.Addr()]
		if tcp {
			to = l.tcp[addr.Addr()]
		}
		if !ok {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return r.exchange(ctx, to, q, tcp)
	}
}

func worldAddrs(n *fakeNet) []netip.Addr {
	var out []netip.Addr
	for a := range n.servers {
		out = append(out, a)
	}
	return out
}

func signedAddrs(n *signedNet) []netip.Addr {
	var out []netip.Addr
	for a := range n.byAddr {
		out = append(out, a)
	}
	return out
}

func askCtx(r *Recursor, name string, qtype uint16, do bool) (*message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	q := buildQuery(4242, dotted(name), qtype, true, nil)
	q[2] |= 1 // RD
	if !do {
		q = buildQuery(4242, dotted(name), qtype, false, nil)
		q[2] |= 1
	}
	resp, err := r.Exchange(ctx, q)
	if err != nil {
		return nil, err
	}
	return parseMessage(resp)
}

// TestCensoredNamesResolveSigned: with every zone signed (the root and
// com are, as in the real world) and a censor forging answers for
// example.com and everything below it, the genuine, validated answer is
// still found: the forged ones are told apart and the genuine one, which
// arrives after them, is waited for. Over TCP the censor only resets.
func TestCensoredNamesResolveSigned(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    censor
	}{
		{"injector without AA", censor{copies: 1, delay: 30 * time.Millisecond}},
		{"injector with AA", censor{aa: true, copies: 1, delay: 30 * time.Millisecond}},
		{"three injectors", censor{copies: 3, delay: 60 * time.Millisecond}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, n := newSignedTest(t)
			r.now = func() time.Time { return n.f.now } // the fixture's signatures are valid then
			tc.c.names = []string{dotted("example.com.")}
			lab := newPathLab(t, &tc.c, signedAddrs(n), n.send)
			lab.route(r)
			msg, err := askCtx(r, "www.example.com.", m.TypeA, true)
			if err != nil {
				t.Fatalf("err %v (forged sent %d, TCP resets %d)", err, lab.forged.Load(), lab.resets.Load())
			}
			got := addrs(msg)
			if msg.rcode != m.RcodeNoError || msg.flags&m.FlagAD == 0 || len(got) == 0 || slices.ContainsFunc(got, func(s string) bool { return s[:3] == "31." }) {
				t.Fatalf("rcode %d AD %v answer %v (forged sent %d)", msg.rcode, msg.flags&m.FlagAD != 0, got, lab.forged.Load())
			}
			if lab.forged.Load() == 0 {
				t.Fatal("the censor never fired: the lab tests nothing")
			}
		})
	}
}

// TestCensoredNamesResolveUnsigned: the same where nothing is signed and
// DNSSEC is off, so no signature can give a forged answer away: the
// genuine answers are still the ones used, for A, for AAAA (where the
// censor answers with a 2001::/32 address) and for other types (where it
// answers with an A record).
func TestCensoredNamesResolveUnsigned(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	lab := newPathLab(t, &censor{names: []string{dotted("example.com.")}, copies: 2, delay: 40 * time.Millisecond}, worldAddrs(n), n.send)
	lab.route(r)
	msg, err := askCtx(r, "www.example.com.", m.TypeA, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := addrs(msg); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("A: %v", got)
	}
	for _, qt := range []uint16{m.TypeAAAA, typeTXT, typeMX} {
		msg, err := askCtx(r, "www.example.com.", qt, false)
		if err != nil {
			t.Fatalf("type %d: %v", qt, err)
		}
		if msg.rcode != m.RcodeNoError || len(msg.answer) != 0 {
			t.Fatalf("type %d: rcode %d answer %v, want no records", qt, msg.rcode, msg.answer)
		}
	}
	// a name outside the censored zone needs no waiting
	start := time.Now()
	if got := addrs(ask(t, r, "www.bank.com.", m.TypeA)); len(got) != 1 || got[0] != "203.0.113.1" {
		t.Fatalf("bank: %v", got)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("an uncensored name took %v", d)
	}
}

// TestPort53Hijacked: when every question is answered by someone in
// between, nothing of it is believed or cached: the lookup fails as
// unreachable (so that a configured upstream can take over), recursion
// reports itself unhealthy, and the rewriting is counted.
func TestPort53Hijacked(t *testing.T) {
	for i, c := range []censor{{intercept: true}, {intercept: true, soa: true}, {intercept: true, tcpBlock: true}} {
		soa := i // which case, in messages
		n := world()
		r := newTest(t, n, true)
		start := time.Now()
		lab := newPathLab(t, &c, worldAddrs(n), n.send)
		lab.route(r)
		for range 25 {
			msg, err := askCtx(r, "www.example.com.", m.TypeA, false)
			if err == nil {
				t.Fatalf("case %v: got rcode %d, want an error", soa, msg.rcode)
			}
			if !errors.Is(err, ErrUnreachable) {
				t.Fatalf("case %v: err %v, want ErrUnreachable", soa, err)
			}
		}
		if r.Healthy() {
			t.Fatalf("case %v: healthy while every answer is rewritten", soa)
		}
		if r.Stats.Rewritten.Load() == 0 || !r.Intercepted() {
			t.Fatalf("case %v: rewritten %d, intercepted %v", soa, r.Stats.Rewritten.Load(), r.Intercepted())
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("case %d: 25 lookups took %v; once known, interception should fail at once", soa, d)
		}
	}
}

// TestPlainServerLearnt: a server whose genuine answers look like forged
// ones would (no EDNS, no AA) still answers: the first time over TCP after
// a short wait, then, once its TCP answer has shown that is how it
// answers, over UDP without delay.
func TestPlainServerLearnt(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	lab := newPathLab(t, &censor{plain: map[netip.Addr]bool{exA: true, ex2A: true}}, worldAddrs(n), n.send)
	lab.route(r)
	if got := addrs(ask(t, r, "www.example.com.", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("first: %v", got)
	}
	if r.Stats.TCP.Load() == 0 {
		t.Fatal("the doubted answers were not checked over TCP")
	}
	// each of the zone's two servers is learnt the first time it is asked
	for i := 0; !r.infra.plain(exA, r.now()) || !r.infra.plain(ex2A, r.now()); i++ {
		if i == 20 {
			t.Fatalf("not learnt: %v %v", r.infra.plain(exA, r.now()), r.infra.plain(ex2A, r.now()))
		}
		r.sets.clear()
		r.negs.clear()
		ask(t, r, "www.example.com.", m.TypeA)
	}
	tcp := r.Stats.TCP.Load()
	start := time.Now()
	for _, name := range []string{"alias.example.com.", "a.b.c.example.com."} {
		if got := addrs(ask(t, r, name, m.TypeA)); len(got) == 0 {
			t.Fatalf("%s: no answer", name)
		}
	}
	if d := time.Since(start); d > 200*time.Millisecond || r.Stats.TCP.Load() != tcp {
		t.Fatalf("after learning: %v, TCP %d -> %d", d, tcp, r.Stats.TCP.Load())
	}
}

// TestPickWaitsForGenuine: on a real socket, forged answers that arrive
// first are dropped and the genuine one that follows is returned; with
// only forged ones, the wait ends with ErrForged after forgedGrace, well
// before the query's own timeout.
func TestPickWaitsForGenuine(t *testing.T) {
	for _, genuine := range []bool{true, false} {
		srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Close()
		go func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := srv.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				for i := range 3 {
					f := append([]byte(nil), buf[:n]...)
					f[2] |= 0x80
					f[3] = byte(i + 1) // marks a forged one
					srv.WriteToUDPAddrPort(f, from)
				}
				if genuine {
					time.Sleep(50 * time.Millisecond)
					g := append([]byte(nil), buf[:n]...)
					g[2] |= 0x80
					srv.WriteToUDPAddrPort(g, from)
				}
			}
		}()
		var p sockPool
		q := buildQuery(0x2222, m.WireName("blocked", "test"), 1, false, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ctx = withJudge(ctx, func(resp []byte) verdict {
			if resp[3] != 0 {
				return vForged
			}
			return vAccept
		})
		start := time.Now()
		resp, err := p.exchangeUDP(ctx, srv.LocalAddr().(*net.UDPAddr).AddrPort(), q)
		cancel()
		switch {
		case genuine && (err != nil || resp[3] != 0):
			t.Fatalf("genuine: %v %v", err, resp)
		case !genuine && !errors.Is(err, ErrForged):
			t.Fatalf("forged only: err %v", err)
		case !genuine && time.Since(start) > forgedGrace+time.Second:
			t.Fatalf("forged only: gave up after %v", time.Since(start))
		}
	}
}

func TestImpossibleAnswers(t *testing.T) {
	a := func(name string, typ uint16) rr {
		return rr{name: dotted(name), typ: typ, class: 1, ttl: 60, data: []byte{1, 2, 3, 4}}
	}
	for _, tc := range []struct {
		zone, name string
		qtype      uint16
		msg        *message
		bad        bool
	}{
		{".", "www.google.com.", m.TypeA, &message{flags: m.FlagQR | m.FlagAA, answer: []rr{a("www.google.com.", m.TypeA)}}, true},
		{".", "com.", m.TypeA, &message{flags: m.FlagQR | m.FlagRA, rcode: m.RcodeNXDomain}, true},
		{".", ".", m.TypeNS, &message{flags: m.FlagQR | m.FlagRA}, true},
		{".", "a.root-servers.net.", m.TypeA, &message{flags: m.FlagQR | m.FlagAA, answer: []rr{a("a.root-servers.net.", m.TypeA)}}, false},
		{".", "1.in-addr.arpa.", m.TypeNS, &message{flags: m.FlagQR | m.FlagAA}, false},
		{".", "nosuchtld.", m.TypeA, &message{flags: m.FlagQR | m.FlagAA, rcode: m.RcodeNXDomain}, false},
		{".", "com.", m.TypeA, &message{flags: m.FlagQR, authority: []rr{{name: dotted("com."), typ: m.TypeNS, class: 1, data: append([]byte(dotted("a.gtld.net.")), 0)}}}, false},
		{"example.com.", "www.example.com.", typeMX, &message{flags: m.FlagQR | m.FlagAA, answer: []rr{a("www.example.com.", m.TypeA)}}, true},
		{"example.com.", "www.example.com.", m.TypeA, &message{flags: m.FlagQR, answer: []rr{a("www.example.com.", m.TypeA)}}, false},
		{".", "com.", m.TypeA, &message{flags: m.FlagQR | m.FlagRA, rcode: m.RcodeRefused}, false},
	} {
		if got := impossible(tc.msg, dotted(tc.zone), dotted(tc.name), tc.qtype) != ""; got != tc.bad {
			t.Errorf("%s from %s: impossible %v, want %v", tc.name, tc.zone, got, tc.bad)
		}
	}
}
