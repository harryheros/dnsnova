package recursor

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/locality"
)

// A content network whose name servers answer by where the question comes
// from: from the server itself, through exit-a or through exit-b each get
// the addresses of different servers. Two kinds: edge.cdn.net is answered
// by cdn.net's own servers (one tier); e.x.two.net is delegated by two.net
// to name servers near whoever asks, which answer for themselves (two
// tiers, as some large content networks do).

var (
	netA   = netip.MustParseAddr("192.0.2.4")
	cdnA   = netip.MustParseAddr("192.0.2.40")
	twoA   = netip.MustParseAddr("192.0.2.50")
	lowSrv = netip.MustParseAddr("198.51.100.53") // near the server
	lowA   = netip.MustParseAddr("203.0.113.53")  // near exit-a
	lowB   = netip.MustParseAddr("198.18.0.53")   // near exit-b
)

// the answer each view gets
var geoAnswer = map[string]string{"server": "198.51.100.10", "exit-a": "203.0.113.10", "exit-b": "198.18.0.10"}

type geoWorld struct {
	*fakeNet
	same   atomic.Bool // the content network answers the same everywhere
	mu     sync.Mutex
	cdn    map[string]int // questions to the content network's servers, by where they came from
	other  []string       // anything else asked through an exit
	silent map[string]bool
	asked  map[string]int // "via name type" for the content network
}

// addRecs adds records to a zone, before its SOA (which answer takes from
// the end).
func addRecs(z *fakeZone, lines ...string) {
	more := zone(z.apex, lines...).recs
	soa := z.recs[len(z.recs)-1]
	z.recs = append(append(z.recs[:len(z.recs)-1:len(z.recs)-1], more[:len(more)-1]...), soa)
}

func locNet() *geoWorld {
	n := world()
	addRecs(n.servers[rootA].zones[0], "net. NS ns.net.", "ns.net. A 192.0.2.4")
	n.servers[netA] = &fakeServer{zones: []*fakeZone{zone("net.",
		"cdn.net. NS ns.cdn.net.", "ns.cdn.net. A 192.0.2.40",
		"two.net. NS ns.two.net.", "ns.two.net. A 192.0.2.50",
	)}}
	n.servers[cdnA] = &fakeServer{zones: []*fakeZone{zone("cdn.net.", "edge.cdn.net. A 198.51.100.10", "other.cdn.net. A 198.51.100.20")}}
	n.servers[twoA] = &fakeServer{zones: []*fakeZone{zone("two.net.")}} // referrals made in send
	for _, a := range []netip.Addr{lowSrv, lowA, lowB} {
		n.servers[a] = &fakeServer{zones: []*fakeZone{zone("x.two.net.", "e.x.two.net. A 0.0.0.0")}}
	}
	for _, a := range []netip.Addr{exA, ex2A} {
		addRecs(n.servers[a].zones[0], "site.example.com. CNAME edge.cdn.net.", "two.example.com. CNAME e.x.two.net.")
	}
	return &geoWorld{fakeNet: n, cdn: map[string]int{}, silent: map[string]bool{}, asked: map[string]int{}}
}

func (g *geoWorld) send(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
	via := locality.ServerName
	if e := exitOf(ctx); e != nil {
		via = e.name
	}
	g.mu.Lock()
	silent := g.silent[via]
	g.mu.Unlock()
	if silent {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	a := addr.Addr()
	cdn := a == cdnA || a == twoA || a == lowSrv || a == lowA || a == lowB
	msg, _ := parseMessage(q)
	g.mu.Lock()
	if cdn {
		g.cdn[via]++
		g.asked[via+" "+m.NameString(msg.qname)+" "+m.TypeString(msg.qtype)]++
	} else if via != locality.ServerName {
		g.other = append(g.other, via+" "+a.String()+" "+m.NameString(msg.qname)+" "+m.TypeString(msg.qtype))
	}
	g.mu.Unlock()
	if a == twoA && msg != nil && isSub(msg.qname, dotted("x.two.net")) {
		// a referral to the name servers near whoever asks
		low := map[string]netip.Addr{"server": lowSrv, "exit-a": lowA, "exit-b": lowB}[via]
		if g.same.Load() {
			low = lowSrv
		}
		ns := rr{name: dotted("x.two.net"), typ: m.TypeNS, class: 1, ttl: 4000, data: append([]byte(dotted("ns-"+via+".x.two.net")), 0)}
		glue := rr{name: dotted("ns-" + via + ".x.two.net"), typ: m.TypeA, class: 1, ttl: 4000, data: low.AsSlice()}
		return buildMessage(msg.id, m.FlagQR, msg.qname, msg.qtype, nil, []rr{ns}, []rr{glue}, false, false, nil), nil
	}
	resp, err := g.fakeNet.send(ctx, addr, q, tcp)
	if err != nil || !cdn {
		return resp, err
	}
	out, err := parseMessage(resp)
	if err != nil {
		return resp, nil
	}
	ans := map[netip.Addr]string{lowSrv: "198.51.100.10", lowA: "203.0.113.10", lowB: "198.18.0.10"}[a]
	if a == cdnA {
		ans = geoAnswer[via]
		if g.same.Load() {
			ans = geoAnswer["server"]
		}
	}
	for i := range out.answer {
		if out.answer[i].typ == m.TypeA && (out.answer[i].name == dotted("edge.cdn.net") || out.answer[i].name == dotted("e.x.two.net")) {
			out.answer[i].data = netip.MustParseAddr(ans).AsSlice()
			out.answer[i].ttl = 20
		}
	}
	return buildMessage(out.id, out.flags, out.qname, out.qtype, out.answer, out.authority, out.additional, false, false, nil), nil
}

func (g *geoWorld) counts() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return maps(g.cdn)
}

func maps(in map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (g *geoWorld) reset() {
	g.mu.Lock()
	g.cdn, g.other, g.asked = map[string]int{}, nil, map[string]int{}
	g.mu.Unlock()
}

var testExits = []string{"exit-a 10.66.1.2 XA", "exit-b 10.66.2.2 XC"}

func newGeo(t *testing.T, g *geoWorld, cfg func(*LocalityConfig)) *Recursor {
	t.Helper()
	exits, err := locality.ParseExits(testExits)
	if err != nil {
		t.Fatal(err)
	}
	lcfg := &LocalityConfig{Exits: exits, ExitTimeout: 300 * time.Millisecond, FanoutQPS: 1000, Relearn: 24 * time.Hour}
	if cfg != nil {
		cfg(lcfg)
	}
	r := New(Config{QNameMinimisation: true, RootHints: []netip.Addr{rootA}, Locality: lcfg},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.send = g.send
	return r
}

// mark marks zone as varying, as three differing probes would.
func mark(r *Recursor, zone string) {
	lc := r.loc.Load()
	for range zoneDiffer {
		lc.zones.result(dotted(zone), true, r.now(), time.Hour)
	}
}

func askView(t *testing.T, r *Recursor, view int, name string, x *locality.Variants) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = locality.WithView(ctx, view)
	if x != nil {
		ctx = locality.WithVariants(ctx, x)
	}
	q := buildQuery(77, dotted(name), m.TypeA, true, nil)
	q[2] |= 1
	resp, err := r.Exchange(ctx, q)
	if err != nil {
		t.Fatalf("%s (view %d): %v", name, view, err)
	}
	msg, err := parseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	return addrs(msg)
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	waitUpTo(t, 2*time.Second, what, cond)
}

func waitUpTo(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < int(d/(10*time.Millisecond)); i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestLocalityLearnsAndAnswersPerView: probes find that cdn.net answers by
// where it is asked from; then each client gets its own view's answer, and
// nothing from cdn.net goes into the shared cache.
func TestLocalityLearnsAndAnswersPerView(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	clock := time.Now()
	var mu sync.Mutex
	r.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	lc := r.loc.Load()
	for i := 0; i < zoneDiffer; i++ {
		probes := lc.Probes.Load()
		if got := askView(t, r, 0, "site.example.com", nil); !slices.Equal(got, []string{"198.51.100.10"}) {
			t.Fatalf("before learning: %v", got)
		}
		waitFor(t, "a probe", func() bool { return lc.Probes.Load() > probes })
		waitFor(t, "its result", func() bool {
			lc.zones.mu.RLock()
			defer lc.zones.mu.RUnlock()
			st := lc.zones.m[dotted("cdn.net")]
			return st != nil && st.run == i+1
		})
		advance(probeEvery + time.Second) // the answer (TTL 20) expires too
	}
	if !lc.zones.marked(dotted("edge.cdn.net")) || lc.zones.marked(dotted("example.com")) {
		t.Fatal("cdn.net not marked after three differing probes, or another zone marked")
	}
	if got := r.VaryingZones(); !slices.Equal(got, []string{"cdn.net."}) {
		t.Fatalf("varying zones %v", got)
	}
	for view, want := range []string{"198.51.100.10", "203.0.113.10", "198.18.0.10"} {
		if got := askView(t, r, view, "site.example.com", nil); !slices.Equal(got, []string{want}) {
			t.Errorf("view %d: %v, want %s", view, got, want)
		}
	}
	if _, exp, ok := r.sets.get(tkey(dotted("edge.cdn.net"), m.TypeA)); ok && exp.After(r.now()) {
		t.Fatal("an answer from a zone that varies went into the shared cache")
	}
	// what is shared stays shared: the alias above it
	if _, _, ok := r.sets.get(tkey(dotted("site.example.com"), m.TypeCNAME)); !ok {
		t.Fatal("the shared part of the chain is not cached")
	}
}

// TestLocalityQueriesDoNotDependOnWhoAsked is rule 2 made a test: the same
// name, needed by a client of one view or of another, sends exactly the
// same questions, to the same servers, through the same exits.
func TestLocalityQueriesDoNotDependOnWhoAsked(t *testing.T) {
	var seen []string
	for view := 0; view < 3; view++ {
		g := locNet()
		r := newGeo(t, g, nil)
		mark(r, "cdn.net")
		askView(t, r, view, "site.example.com", nil)
		// the fork goes on after the client's answer: wait for it to end
		lc := r.loc.Load()
		waitFor(t, "the fork", func() bool { lc.mu.Lock(); defer lc.mu.Unlock(); return len(lc.runs) == 0 })
		g.mu.Lock()
		var keys []string
		for k, v := range g.asked {
			keys = append(keys, k+" x"+string(rune('0'+v)))
		}
		other := slices.Clone(g.other)
		g.mu.Unlock()
		slices.Sort(keys)
		got := strings.Join(keys, "; ")
		if view == 0 {
			seen = append(seen, got)
		} else if got != seen[0] {
			t.Fatalf("a client of view %d made other questions:\n%s\nview 0:\n%s", view, got, seen[0])
		}
		for _, via := range []string{"server", "exit-a", "exit-b"} {
			if !strings.Contains(got, via+" ") {
				t.Fatalf("view %d: nothing asked from %s: %s", view, via, got)
			}
		}
		// root, top-level domains and the shared part never go through an exit
		if len(other) > 0 {
			t.Fatalf("asked through an exit outside the zone that varies: %v", other)
		}
	}
}

// TestLocalityTwoTierDelegation: the content network's top delegates to
// name servers near whoever asks; each exit keeps its own delegation, and
// so gets the answer for where it is.
func TestLocalityTwoTierDelegation(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	clock := time.Now()
	var mu sync.Mutex
	r.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	lc := r.loc.Load()
	// learned from the referrals themselves (the glue differs)
	for i := 0; i < zoneDiffer; i++ {
		r.delegs.clear()
		r.sets.clear()
		probes := lc.Probes.Load()
		askView(t, r, 0, "two.example.com", nil)
		waitFor(t, "a probe", func() bool { return lc.Probes.Load() > probes })
		waitFor(t, "its result", func() bool {
			lc.zones.mu.RLock()
			defer lc.zones.mu.RUnlock()
			st := lc.zones.m[dotted("two.net")]
			return st != nil && st.run == i+1
		})
		mu.Lock()
		clock = clock.Add(probeEvery + time.Second)
		mu.Unlock()
	}
	if !lc.zones.marked(dotted("x.two.net")) {
		t.Fatal("two.net not marked from its referrals")
	}
	r.delegs.clear() // the server's own delegation to x.two.net is gone
	for view, want := range []string{"198.51.100.10", "203.0.113.10", "198.18.0.10"} {
		if got := askView(t, r, view, "two.example.com", nil); !slices.Equal(got, []string{want}) {
			t.Errorf("view %d: %v, want %s", view, got, want)
		}
	}
	for view, low := range []netip.Addr{lowSrv, lowA, lowB} {
		d, _, ok := r.vdelegs.get(vkey(dotted("x.two.net"), view))
		if !ok || len(d.ns) != 1 || !slices.Equal(d.ns[0].addrs, []netip.Addr{low}) {
			t.Errorf("view %d: delegation %+v", view, d)
		}
	}
	if _, _, ok := r.delegs.get(dotted("x.two.net")); ok {
		t.Fatal("a delegation that depends on where it was asked went into the shared ones")
	}
}

// TestLocalityVariantsAndOneExpiry: a lookup returns every view's answer
// for the front cache, and a fork's answers expire together.
func TestLocalityVariantsAndOneExpiry(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	mark(r, "cdn.net")
	askView(t, r, 1, "site.example.com", nil)
	lc := r.loc.Load()
	waitFor(t, "the fork", func() bool { lc.mu.Lock(); defer lc.mu.Unlock(); return len(lc.runs) == 0 })
	x := &locality.Variants{}
	askView(t, r, 2, "site.example.com", x)
	resps := x.Get()
	if len(resps) != 3 {
		t.Fatalf("%d variants", len(resps))
	}
	for v, want := range []string{"198.51.100.10", "203.0.113.10", "198.18.0.10"} {
		msg, err := parseMessage(resps[v])
		if err != nil {
			t.Fatal(err)
		}
		if got := addrs(msg); !slices.Equal(got, []string{want}) {
			t.Errorf("variant %d: %v", v, got)
		}
		if msg.answer[0].typ != m.TypeCNAME {
			t.Errorf("variant %d lacks the shared alias", v)
		}
	}
	le, exp, ok := r.lsets.get(tkey(dotted("edge.cdn.net"), m.TypeA))
	if !ok {
		t.Fatal("fork not kept")
	}
	for v, f := range le.frags {
		for _, u := range f.until {
			if u.After(exp) {
				t.Fatalf("view %d expires after the fork: %v > %v", v, u, exp)
			}
		}
	}
	// a name that does not vary: no variants
	x2 := &locality.Variants{}
	askView(t, r, 1, "www.example.com", x2)
	if x2.Get() != nil {
		t.Fatal("variants for a name that does not vary")
	}
}

// TestLocalityExitLateOrDown: a client whose exit does not answer in time
// gets the server's answer; after enough timeouts the exit is left out,
// and the server's own health is not affected.
func TestLocalityExitLateOrDown(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, func(c *LocalityConfig) { c.ExitTimeout = 100 * time.Millisecond })
	mark(r, "cdn.net")
	g.mu.Lock()
	g.silent["exit-b"] = true
	g.mu.Unlock()
	start := time.Now()
	if got := askView(t, r, 2, "site.example.com", nil); !slices.Equal(got, []string{"198.51.100.10"}) {
		t.Fatalf("late exit: %v, want the server's answer", got)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the client waited %v", d)
	}
	lc := r.loc.Load()
	if lc.exits[1].fallbacks.Load() != 1 {
		t.Fatalf("fallbacks %d", lc.exits[1].fallbacks.Load())
	}
	if got := askView(t, r, 1, "site.example.com", nil); !slices.Equal(got, []string{"203.0.113.10"}) {
		t.Fatalf("the other exit: %v", got)
	}
	// timeouts take the exit out; the server stays healthy
	for i := range 4 {
		askView(t, r, 0, "n"+string(rune('0'+i))+".cdn.net", nil)
	}
	waitUpTo(t, 10*time.Second, "exit-b taken out", func() bool { return !lc.exits[1].usable(r.now()) })
	if !r.Healthy() {
		t.Fatal("an exit's timeouts made the server unhealthy")
	}
	st := r.Locality()
	if st.Exits[1].Up || !st.Exits[0].Up || st.Exits[1].Timeouts == 0 {
		t.Fatalf("status %+v", st.Exits)
	}
	// left out of later forks: nothing more is sent through it
	g.reset()
	r.lsets.clear()
	waitUpTo(t, 10*time.Second, "the forks", func() bool { lc.mu.Lock(); defer lc.mu.Unlock(); return len(lc.runs) == 0 })
	g.reset()
	askView(t, r, 0, "other.cdn.net", nil)
	waitFor(t, "the fork", func() bool { lc.mu.Lock(); defer lc.mu.Unlock(); return len(lc.runs) == 0 })
	if c := g.counts(); c["exit-b"] != 0 || c["exit-a"] == 0 {
		t.Fatalf("questions by path %v", c)
	}
}

// TestLocalityFanoutLimit: over fanout_qps, names are asked from the
// server alone, whoever asks; never from the client's exit only.
func TestLocalityFanoutLimit(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, func(c *LocalityConfig) { c.FanoutQPS = 1 })
	mark(r, "cdn.net")
	askView(t, r, 1, "edge.cdn.net", nil) // takes the one fork allowed
	lc := r.loc.Load()
	waitFor(t, "the fork", func() bool { lc.mu.Lock(); defer lc.mu.Unlock(); return len(lc.runs) == 0 })
	g.reset()
	if got := askView(t, r, 1, "other.cdn.net", nil); !slices.Equal(got, []string{"198.51.100.20"}) {
		t.Fatalf("over the limit: %v", got)
	}
	waitFor(t, "the fork", func() bool { lc.mu.Lock(); defer lc.mu.Unlock(); return len(lc.runs) == 0 })
	if c := g.counts(); c["exit-a"] != 0 || c["exit-b"] != 0 || c["server"] == 0 {
		t.Fatalf("over the limit, questions by path %v", c)
	}
	if lc.ForksLimited.Load() != 1 {
		t.Fatalf("limited %d", lc.ForksLimited.Load())
	}
}

// TestLocalityRelearnsFromForks: when the zone stops varying, forks see it
// and clear the mark.
func TestLocalityRelearnsFromForks(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	mark(r, "cdn.net")
	g.same.Store(true)
	lc := r.loc.Load()
	for i := 0; i < zoneAgree; i++ {
		r.lsets.clear()
		askView(t, r, 0, "site.example.com", nil)
		waitFor(t, "the fork", func() bool { lc.mu.Lock(); defer lc.mu.Unlock(); return len(lc.runs) == 0 })
	}
	if lc.zones.marked(dotted("cdn.net")) {
		t.Fatal("still marked after three forks with the same answers")
	}
}

// TestExchangeExit: a measurement through one exit asks every zone below
// the top-level domains there, and keeps nothing in the shared cache.
func TestExchangeExit(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := buildQuery(7, dotted("site.example.com"), m.TypeA, true, nil)
	q[2] |= 1
	resp, err := r.ExchangeExit(ctx, q, "exit-a")
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := parseMessage(resp)
	if got := addrs(msg); !slices.Equal(got, []string{"203.0.113.10"}) {
		t.Fatalf("through exit-a: %v", got)
	}
	g.mu.Lock()
	other := slices.Clone(g.other)
	g.mu.Unlock()
	if !slices.ContainsFunc(other, func(s string) bool {
		return strings.HasPrefix(s, "exit-a 192.0.2.1") && strings.Contains(s, "example.com")
	}) ||
		slices.ContainsFunc(other, func(s string) bool { return strings.Contains(s, " 192.0.2.1 ") || strings.Contains(s, " 192.0.2.2 ") }) {
		t.Fatalf("questions through the exit: %v", other)
	}
	if _, exp, ok := r.sets.get(tkey(dotted("edge.cdn.net"), m.TypeA)); ok && exp.After(r.now()) {
		t.Fatal("a measurement went into the shared cache")
	}
	if _, err := r.ExchangeExit(ctx, q, "nope"); err != ErrNoExit {
		t.Fatalf("unknown exit: %v", err)
	}
}

// TestLocalityTrace: a trace shows every view's answer, and its steps say
// where they were asked from; a trace through one exit asks there.
func TestLocalityTrace(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	mark(r, "cdn.net")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr := r.Trace(ctx, dotted("site.example.com"), m.TypeA)
	if tr.Error != "" || len(tr.Views) != 3 {
		t.Fatalf("%+v", tr)
	}
	for i, want := range []string{"198.51.100.10", "203.0.113.10", "198.18.0.10"} {
		v := tr.Views[i]
		if v.Via != []string{"server", "exit-a", "exit-b"}[i] || !strings.Contains(strings.Join(v.Answers, " "), want) {
			t.Errorf("view %d: %+v", i, v)
		}
	}
	if !slices.ContainsFunc(tr.Steps, func(s TraceStep) bool { return s.Via == "exit-a" && s.Zone == "cdn.net." }) {
		t.Fatal("no step through exit-a")
	}
	tr = r.Trace(WithTraceExit(ctx, "exit-b"), dotted("site.example.com"), m.TypeA)
	if tr.Exit != "exit-b" || !strings.Contains(strings.Join(tr.Answers, " "), "198.18.0.10") {
		t.Fatalf("through exit-b: %+v", tr)
	}
	if tr = r.Trace(WithTraceExit(ctx, "nope"), dotted("site.example.com"), m.TypeA); tr.Error == "" {
		t.Fatal("trace through an unknown exit")
	}
}

// TestLocalityOffChangesNothing: without exits nothing goes through one,
// and turning it off forgets every view's answers.
func TestLocalityOffChangesNothing(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	mark(r, "cdn.net")
	askView(t, r, 1, "site.example.com", nil)
	lc := r.loc.Load()
	waitFor(t, "the fork", func() bool { lc.mu.Lock(); defer lc.mu.Unlock(); return len(lc.runs) == 0 })
	cfg := *r.cfg.Load()
	cfg.Locality = nil
	r.SetConfig(cfg)
	if r.loc.Load() != nil || r.lsets.len() != 0 || r.vdelegs.len() != 0 || r.Locality() != nil {
		t.Fatal("not off")
	}
	g.reset()
	if got := askView(t, r, 1, "site.example.com", nil); !slices.Equal(got, []string{"198.51.100.10"}) {
		t.Fatalf("off: %v", got)
	}
	if c := g.counts(); c["exit-a"]+c["exit-b"] != 0 {
		t.Fatalf("off, yet asked through exits: %v", c)
	}
}

// TestLocalityKeepsZonesAcrossChanges: changing the clients an exit serves
// (which the resolver, not the recursion, uses) keeps the exits' state;
// new exits keep the zones learned.
func TestLocalityKeepsZonesAcrossChanges(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	mark(r, "cdn.net")
	lc := r.loc.Load()
	cfg := *r.cfg.Load()
	exits, _ := locality.ParseExits([]string{"exit-a 10.66.1.2 XB", "exit-b 10.66.2.2 XC"})
	cfg.Locality = &LocalityConfig{Exits: exits, ExitTimeout: time.Second, FanoutQPS: 10, Relearn: time.Hour}
	r.SetConfig(cfg)
	if r.loc.Load() != lc {
		t.Fatal("same exits, other clients: the exits' state was replaced")
	}
	exits, _ = locality.ParseExits([]string{"exit-c 10.66.9.2 XB"})
	cfg.Locality = &LocalityConfig{Exits: exits, ExitTimeout: time.Second, FanoutQPS: 10, Relearn: time.Hour}
	r.SetConfig(cfg)
	if nl := r.loc.Load(); nl == lc || len(nl.exits) != 1 || !nl.zones.marked(dotted("cdn.net")) {
		t.Fatal("new exits: zones lost")
	}
}

func TestSaveLoadZones(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	mark(r, "cdn.net")
	mark(r, "two.net")
	r.loc.Load().zones.result(dotted("plain.example"), false, r.now(), time.Hour)
	var buf bytes.Buffer
	if n, err := r.SaveZones(&buf); err != nil || n != 2 {
		t.Fatalf("saved %d: %v", n, err)
	}
	if bytes.Contains(buf.Bytes(), []byte("plain")) {
		t.Fatal("a zone that does not vary was saved")
	}
	r2 := newGeo(t, locNet(), nil)
	if n, err := r2.LoadZones(bytes.NewReader(buf.Bytes())); err != nil || n != 2 || !r2.loc.Load().zones.marked(dotted("x.two.net")) {
		t.Fatalf("loaded %d: %v", n, err)
	}
	bad := buf.Bytes()
	bad[len(bad)-1] ^= 1
	if _, err := r2.LoadZones(bytes.NewReader(bad)); err != ErrZonesFile {
		t.Fatalf("damaged file: %v", err)
	}
}

// TestNoProbeBeyondTheRules: the root, top-level domains, reverse zones
// and DS/DNSKEY questions are never probed.
func TestNoProbeBeyondTheRules(t *testing.T) {
	g := locNet()
	r := newGeo(t, g, nil)
	askView(t, r, 0, "www.example.com", nil)
	lc := r.loc.Load()
	time.Sleep(50 * time.Millisecond)
	lc.zones.mu.RLock()
	defer lc.zones.mu.RUnlock()
	for z := range lc.zones.m {
		if labelCount(z) <= 1 {
			t.Fatalf("probed %q", m.NameString(z))
		}
	}
}

// FuzzLoadZones: a zones file of any content is refused or loaded, never
// a panic, and only valid names are marked.
func FuzzLoadZones(f *testing.F) {
	g := locNet()
	exits, _ := locality.ParseExits(testExits)
	r := New(Config{Locality: &LocalityConfig{Exits: exits, ExitTimeout: time.Second, FanoutQPS: 1, Relearn: time.Hour}},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.send = g.send
	for range zoneDiffer {
		r.loc.Load().zones.result(dotted("cdn.net"), true, time.Now(), time.Hour)
	}
	var buf bytes.Buffer
	r.SaveZones(&buf)
	f.Add(buf.Bytes())
	f.Add([]byte("DNSNLOC\x01"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r2 := New(Config{Locality: &LocalityConfig{Exits: exits, ExitTimeout: time.Second, FanoutQPS: 1, Relearn: time.Hour}},
			slog.New(slog.NewTextHandler(io.Discard, nil)))
		r2.LoadZones(bytes.NewReader(data))
		for _, z := range r2.VaryingZones() {
			if z == "" {
				t.Fatal("an empty zone marked")
			}
		}
	})
}

// TestExitSocketsUseTheSourceAddress: questions through an exit leave from
// its source address (which the system routes into its tunnel), over UDP
// and TCP; a family it has no address for is refused. 127.0.0.2 stands
// for the tunnel's address.
func TestExitSocketsUseTheSourceAddress(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	from := make(chan string, 2)
	go func() {
		buf := make([]byte, 512)
		n, a, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		from <- a.(*net.UDPAddr).IP.String()
		resp := append([]byte(nil), buf[:n]...)
		resp[2] |= 0x80
		pc.WriteTo(resp, a)
	}()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		from <- c.RemoteAddr().(*net.TCPAddr).IP.String()
		var lb [2]byte
		io.ReadFull(c, lb[:])
		q := make([]byte, int(lb[0])<<8|int(lb[1]))
		io.ReadFull(c, q)
		q[2] |= 0x80
		c.Write(append(lb[:], q...))
	}()
	ex := &exitPath{view: 1, name: "exit-a", ex: locality.Exit{Name: "exit-a", Local: []netip.Addr{netip.MustParseAddr("127.0.0.2")}},
		socks: &sockPool{exit: true, local: [2]netip.Addr{netip.MustParseAddr("127.0.0.2")}}, infra: newInfra()}
	defer ex.socks.closeAll()
	r := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(withExit(context.Background(), ex), 3*time.Second)
	defer cancel()
	q := buildQuery(42, dotted("example.com"), m.TypeA, false, nil)
	udp := netip.MustParseAddrPort(pc.LocalAddr().String())
	if _, err := r.exchange(ctx, udp, q, false); err != nil {
		t.Fatal(err)
	}
	if got := <-from; got != "127.0.0.2" {
		t.Fatalf("UDP left from %s", got)
	}
	tcp := netip.MustParseAddrPort(ln.Addr().String())
	if _, err := r.exchange(ctx, tcp, q, true); err != nil {
		t.Fatal(err)
	}
	if got := <-from; got != "127.0.0.2" {
		t.Fatalf("TCP left from %s", got)
	}
	v6 := netip.MustParseAddrPort("[2001:db8::53]:53")
	for _, tcp := range []bool{false, true} {
		if _, err := r.exchange(ctx, v6, q, tcp); err != errNoFamily {
			t.Fatalf("IPv6 through an IPv4-only exit (tcp %v): %v", tcp, err)
		}
	}
}
