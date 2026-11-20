package recursor

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Load balancers in front of some large sites (seen with the name servers
// of some large CDNs) answer over UDP without EDNS or AA, accept
// TCP connections but never answer on them, and give an empty reply
// without authority for names that only exist as part of longer ones.

// TestDoubtfulAnswerKeptWithoutTCP: a server whose UDP answers are only
// doubtful (no EDNS, no AA) and whose TCP never answers still resolves:
// the doubtful answer, the only one that came, is used once TCP has had a
// short chance; and once the server is known not to answer over TCP, its
// answers are used at once.
func TestDoubtfulAnswerKeptWithoutTCP(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	both := map[netip.Addr]bool{exA: true, ex2A: true}
	lab := newPathLab(t, &injector{plain: both, noTCP: both}, worldAddrs(n), n.send)
	lab.route(r)
	start := time.Now()
	msg, err := askCtx(r, "www.example.com.", m.TypeA, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := addrs(msg); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("rcode %d answer %v", msg.rcode, got)
	}
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("took %v: clients give up after a few seconds", d)
	}
	now := r.now()
	if !r.infra.noTCP(exA, now) && !r.infra.noTCP(ex2A, now) {
		t.Fatal("not learnt that the server does not answer over TCP")
	}
	// the server stays usable: not marked failed or lame
	for _, a := range []netip.Addr{exA, ex2A} {
		if r.infra.noTCP(a, now) && r.infra.score(a, dotted("example.com."), now) > 5*time.Second {
			t.Fatalf("%v penalised: score %v", a, r.infra.score(a, dotted("example.com."), now))
		}
	}
	// the server learnt keeps its real round trip, so it is asked first
	tcp := r.Stats.TCP.Load()
	r.sets.clear()
	r.negs.clear()
	start = time.Now()
	if got := addrs(ask(t, r, "alias.example.com.", m.TypeA)); len(got) != 1 {
		t.Fatalf("alias: %v", got)
	}
	if d := time.Since(start); d > 200*time.Millisecond || r.Stats.TCP.Load() != tcp {
		t.Fatalf("after learning: %v, TCP %d -> %d", d, tcp, r.Stats.TCP.Load())
	}
}

// TestDoubtfulAnswerNotKeptUnderInjection: where an injector answers first
// and resets TCP, a doubtful answer is never used in place of TCP: two
// different answers came, so either could be the forged one. The lookup
// fails rather than return the forged address.
func TestDoubtfulAnswerNotKeptUnderInjection(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	both := map[netip.Addr]bool{exA: true, ex2A: true}
	lab := newPathLab(t, &injector{names: []string{dotted("example.com.")}, copies: 1, delay: 30 * time.Millisecond, plain: both}, worldAddrs(n), n.send)
	lab.route(r)
	msg, err := askCtx(r, "www.example.com.", m.TypeA, false)
	if err == nil {
		if got := addrs(msg); slices.ContainsFunc(got, func(s string) bool { return s[:3] == "31." }) {
			t.Fatalf("the forged answer was used: %v", got)
		}
	}
	if lab.forged.Load() == 0 || lab.resets.Load() == 0 {
		t.Fatalf("the injector never fired (forged %d, resets %d): the lab tests nothing", lab.forged.Load(), lab.resets.Load())
	}
	if r.infra.noTCP(exA, r.now()) || r.infra.noTCP(ex2A, r.now()) {
		t.Fatal("a reset TCP connection was taken for a server without TCP")
	}
}

// TestDoubtfulAnswerTCPRefusedOrReset: a server with nothing listening
// on TCP (the connection is refused) is a server without TCP, and its
// doubtful answer is used; a connection reset after the question was sent
// is what injectors do, and the doubtful answer is not used.
func TestDoubtfulAnswerTCPRefusedOrReset(t *testing.T) {
	for _, refused := range []bool{true, false} {
		n := world()
		r := newTest(t, n, true)
		both := map[netip.Addr]bool{exA: true, ex2A: true}
		c := &injector{plain: both, resetTCP: both}
		if refused {
			c = &injector{plain: both, refuseTCP: both}
		}
		lab := newPathLab(t, c, worldAddrs(n), n.send)
		lab.route(r)
		msg, err := askCtx(r, "www.example.com.", m.TypeA, false)
		learnt := r.infra.noTCP(exA, r.now()) || r.infra.noTCP(ex2A, r.now())
		switch {
		case refused && (err != nil || len(addrs(msg)) != 1 || !learnt):
			t.Fatalf("refused: err %v, learnt %v", err, learnt)
		case !refused && learnt:
			t.Fatal("reset: taken for a server without TCP")
		case !refused && err == nil && msg.rcode == m.RcodeNoError:
			t.Fatalf("reset: the doubtful answer was used: %v", addrs(msg))
		case !refused && lab.resets.Load() == 0:
			t.Fatal("reset: nothing was reset: the lab tests nothing")
		}
	}
}

// TestMinimisedLameNotMarked: servers that reply without authority to a
// shortened name (QNAME minimisation, RFC 9156) are not marked lame for
// their whole zone; when none of the zone's servers answers it, the full
// name is asked.
func TestMinimisedLameNotMarked(t *testing.T) {
	n := world()
	n.servers[exA].entLame = true
	n.servers[ex2A].entLame = true
	r := newTest(t, n, true)
	if got := addrs(ask(t, r, "a.b.c.example.com.", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.9" {
		t.Fatalf("answer %v", got)
	}
	now := r.now()
	for _, a := range []netip.Addr{exA, ex2A} {
		if s := r.infra.score(a, dotted("example.com."), now); s >= time.Minute {
			t.Fatalf("%v marked lame for example.com (score %v)", a, s)
		}
	}
	if q := n.servers[exA].queries.Load() + n.servers[ex2A].queries.Load(); q > 3 {
		t.Fatalf("%d queries to example.com's servers, want 3: the shortened name to each, then the full one", q)
	}
}

// TestMinimisedOneServerLame: when only one of a zone's servers mishandles
// shortened names, the others are asked them, and minimisation goes on:
// one server must not send the full name to every later server.
func TestMinimisedOneServerLame(t *testing.T) {
	n := world()
	n.servers[exA].entLame = true
	r := newTest(t, n, true)
	now := r.now()
	r.infra.ok(exA, time.Millisecond, now) // the bad one is asked first
	r.infra.ok(ex2A, 50*time.Millisecond, now)
	if got := addrs(ask(t, r, "a.b.c.example.com.", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.9" {
		t.Fatalf("answer %v", got)
	}
	if _, ok := n.servers[ex2A].seen.Load("c.example.com."); !ok {
		t.Fatal("the shortened name was not asked of the zone's other server: minimisation given up because of one")
	}
	if s := r.infra.score(exA, dotted("example.com."), r.now()); s >= time.Minute {
		t.Fatalf("marked lame for example.com (score %v)", s)
	}
}

// TestNoTCPServerUnderInjection: a server known not to answer over TCP,
// whose genuine answers are unusual, is still not taken for an injector
// that answers in its place first: an unusual answer that comes sooner than
// the server answers waits, and the genuine one, later, is used.
func TestNoTCPServerUnderInjection(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	both := map[netip.Addr]bool{exA: true, ex2A: true}
	lab := newPathLab(t, &injector{names: []string{dotted("example.com.")}, copies: 1, delay: 30 * time.Millisecond,
		plain: both, noTCP: both}, worldAddrs(n), n.send)
	lab.route(r)
	now := r.now()
	for _, a := range []netip.Addr{exA, ex2A} {
		r.infra.setNoTCP(a, now)
		r.infra.ok(a, 30*time.Millisecond, now) // what its answers take
	}
	msg, err := askCtx(r, "www.example.com.", m.TypeA, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := addrs(msg); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("answer %v (forged ones start with 31.)", got)
	}
	if lab.forged.Load() == 0 {
		t.Fatal("the injector never fired: the lab tests nothing")
	}
}
