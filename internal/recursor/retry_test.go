package recursor

import (
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// A zone with one name server whose answer is lost once (a dropped packet)
// still resolves: a server that timed out is asked once more when no
// other server answered, as BIND and Unbound do. One try only gave
// SERVFAIL where public resolvers, retrying, answered.
func TestTimedOutServerIsAskedAgain(t *testing.T) {
	n := world()
	n.servers[bankA].drop.Store(1)
	r := newTest(t, n, true)
	if got := addrs(ask(t, r, "www.bank.com.", m.TypeA)); len(got) != 1 || got[0] != "203.0.113.1" {
		t.Fatalf("answer %v", got)
	}
	if q := n.servers[bankA].queries.Load(); q != 2 {
		t.Fatalf("%d queries to the zone's server, want 2: the lost one and the retry", q)
	}
	if r.Stats.Retries.Load() != 1 || r.Stats.RetriesAnswered.Load() != 1 {
		t.Fatalf("retries %d, answered %d", r.Stats.Retries.Load(), r.Stats.RetriesAnswered.Load())
	}
}

// The retry waits for three times the server's usual round trip (at least
// 400 ms), not for the 2 s its failure has just raised the estimate to: a
// lost packet is not a slow server. A server that answers in 20 ms and
// is down costs 150 ms + 400 ms, not 150 ms + 2 s.
func TestRetryWaitsForTheUsualRoundTrip(t *testing.T) {
	n := world()
	n.servers[bankA].silent = true
	r := newTest(t, n, true)
	ask(t, r, "www.example.com.", m.TypeA) // the rest of the path known
	r.infra.ok(bankA, 20*time.Millisecond, r.now())
	start := time.Now()
	askCtx(r, "www.bank.com.", m.TypeA, false)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v: the retry waited as for a slow server", d)
	}
	if q := n.servers[bankA].queries.Load(); q != 2 {
		t.Fatalf("%d queries, want 2", q)
	}
}

// A server that keeps timing out is asked twice in one lookup at most: a
// dead server is not waited for again and again.
func TestDeadServerIsNotRetriedEndlessly(t *testing.T) {
	n := world()
	n.servers[bankA].silent = true
	r := newTest(t, n, true)
	start := time.Now()
	if _, err := askCtx(r, "www.bank.com.", m.TypeA, false); err == nil {
		t.Fatal("a silent server answered")
	}
	if q := n.servers[bankA].queries.Load(); q != 2 {
		t.Fatalf("%d queries to a dead server, want 2", q)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("took %v", d)
	}
	// once it has failed three times in a row it is in backoff: no retry
	n.servers[bankA].queries.Store(0)
	r.sets.clear()
	r.negs.clear()
	askCtx(r, "www2.bank.com.", m.TypeA, false)
	if q := n.servers[bankA].queries.Load(); q != 1 {
		t.Fatalf("%d queries to a server in backoff, want 1", q)
	}
}

// Servers that refused or are lame are not asked again: only a timeout
// may be a lost packet.
func TestRefusingServerIsNotAskedAgain(t *testing.T) {
	n := world()
	n.servers[bankA].refuse = true
	r := newTest(t, n, true)
	askCtx(r, "www.bank.com.", m.TypeA, false)
	if q := n.servers[bankA].queries.Load(); q != 1 {
		t.Fatalf("%d queries to a refusing server, want 1", q)
	}
}

// With several servers that time out, only the best is asked again: when
// all are down, the error must still come before the upstreams' turn.
func TestOnlyOneTimedOutServerIsAskedAgain(t *testing.T) {
	n := world()
	n.servers[exA].silent, n.servers[ex2A].silent = true, true
	r := newTest(t, n, true)
	askCtx(r, "www.example.com.", m.TypeA, false)
	if q := n.servers[exA].queries.Load() + n.servers[ex2A].queries.Load(); q != 3 {
		t.Fatalf("%d queries to two dead servers, want 3: each, then the best again", q)
	}
}

// Lookups that asked name servers are timed; answers from the cache are
// not counted (and cost no clock reading).
func TestLookupTimesAreRecorded(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	ask(t, r, "www.example.com.", m.TypeA)
	if r.Stats.Lookups.Count() != 1 || r.Stats.RTT.Count() == 0 {
		t.Fatalf("lookups %d, server replies %d", r.Stats.Lookups.Count(), r.Stats.RTT.Count())
	}
	ask(t, r, "www.example.com.", m.TypeA) // from the cache
	if r.Stats.Lookups.Count() != 1 {
		t.Fatalf("a cached answer was counted as a lookup: %d", r.Stats.Lookups.Count())
	}
}
