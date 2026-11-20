package recursor

import (
	"net/netip"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// hedgeSetup: the path to example.com known, both of its servers known to
// answer in 10 and 20 ms, so that exA is asked first.
func hedgeSetup(t *testing.T) (*fakeNet, *Recursor) {
	n := world()
	r := newTest(t, n, true)
	ask(t, r, "www.example.com.", m.TypeA)
	for a, rtt := range map[netip.Addr]time.Duration{exA: 10 * time.Millisecond, ex2A: 20 * time.Millisecond} {
		r.infra.mu.Lock()
		st := r.infra.get(a)
		st.srtt, st.fails, st.until = rtt, 0, time.Time{}
		r.infra.mu.Unlock()
	}
	r.sets.clear()
	r.negs.clear()
	r.Stats.Hedges.Store(0)
	r.Stats.HedgesWon.Store(0)
	return n, r
}

// When the best server takes clearly longer than it usually does, the
// next is asked too and its answer used: the lookup takes about two of
// the first server's round trips, not its timeout. The server that did
// not answer in time is not counted as failed (it may only be slow this
// once), only no longer preferred.
func TestSlowServerIsHedged(t *testing.T) {
	n, r := hedgeSetup(t)
	n.servers[exA].silent = true
	start := time.Now()
	if got := addrs(ask(t, r, "a.b.c.example.com.", m.TypeA)); len(got) == 0 {
		t.Fatal("no answer")
	}
	if d := time.Since(start); d > 140*time.Millisecond {
		t.Fatalf("took %v: the next server was not asked in time", d)
	}
	if r.Stats.Hedges.Load() != 1 || r.Stats.HedgesWon.Load() != 1 {
		t.Fatalf("hedges %d, won %d", r.Stats.Hedges.Load(), r.Stats.HedgesWon.Load())
	}
	if n.servers[ex2A].queries.Load() == 0 {
		t.Fatal("the next server was not asked")
	}
	now := r.now()
	r.infra.mu.Lock()
	st := *r.infra.get(exA)
	r.infra.mu.Unlock()
	if st.fails != 0 || r.infra.backoff(exA, now) {
		t.Fatalf("the slow server counted as failed: %d fails", st.fails)
	}
	if st.srtt <= 10*time.Millisecond {
		t.Fatalf("the slow server still scores %v", st.srtt)
	}
	if a, b := r.infra.score(exA, dotted("example.com."), now), r.infra.score(ex2A, dotted("example.com."), now); a <= b {
		t.Fatalf("slow server %v, the one that answered %v: still preferred", a, b)
	}
}

// Servers that answer as fast as they usually do are asked one at a time:
// no question is sent twice.
func TestNoHedgeWhenServersAnswer(t *testing.T) {
	_, r := hedgeSetup(t)
	for _, name := range []string{"www.example.com.", "alias.example.com.", "a.b.c.example.com.", "nx.example.com."} {
		askCtx(r, name, m.TypeA, false)
	}
	if h := r.Stats.Hedges.Load(); h != 0 {
		t.Fatalf("%d hedges for servers that answer at once", h)
	}
}

// A zone with one server has nothing to hedge with: it is waited for as
// before (and asked again after a timeout).
func TestNoHedgeWithOneServer(t *testing.T) {
	n := world()
	n.servers[bankA].drop.Store(1)
	r := newTest(t, n, true)
	if got := addrs(ask(t, r, "www.bank.com.", m.TypeA)); len(got) != 1 {
		t.Fatalf("answer %v", got)
	}
	if r.Stats.Hedges.Load() != 0 {
		t.Fatalf("%d hedges", r.Stats.Hedges.Load())
	}
}
