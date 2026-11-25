package resolver

import (
	"bytes"
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/locality"
	"github.com/harryheros/dnsnova/internal/stats"
)

// geoUp stands for the recursion with private locality: vary.test is
// answered for each view (1.0.0.<view>), and every view's answer comes
// back with it; anything else is the same for everyone.
type geoUp struct {
	mu       sync.Mutex
	calls    map[int]int // by view, for vary.test
	sawVars  bool        // a lookup carried somewhere to put every view's answer
	missing  int         // this view's answer is not known yet (-1: none missing)
	ttlByVar []uint32
}

func (g *geoUp) answer(req []byte, view int) []byte {
	q, _, _ := m.ParseQuery(req)
	return m.Answer(req, q, g.ttlByVar[view], []byte{1, 0, 0, byte(view)})
}

func (g *geoUp) Exchange(ctx context.Context, req []byte) ([]byte, error) {
	q, _, err := m.ParseQuery(req)
	if err != nil {
		return nil, err
	}
	x := locality.VariantsFrom(ctx)
	view := locality.ViewFrom(ctx)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sawVars = g.sawVars || x != nil
	if m.NameString(q.Name) != "vary.test." {
		return m.Answer(req, q, 300, []byte{9, 9, 9, 9}), nil
	}
	g.calls[view]++
	if x != nil {
		resps := make([][]byte, 3)
		for v := range resps {
			if v != g.missing || v == view {
				resps[v] = g.answer(req, v)
			}
		}
		x.Set(resps)
	}
	return g.answer(req, view), nil
}

func localityTest(t *testing.T, on bool) (*Resolver, *geoUp, *clock) {
	t.Helper()
	g := &geoUp{calls: map[int]int{}, missing: -1, ttlByVar: []uint32{300, 60, 300}}
	s := settings()
	if on {
		exits, err := locality.ParseExits([]string{"a 10.66.1.2 10.1.0.0/16", "b 10.66.2.2 10.2.0.0/16"})
		if err != nil {
			t.Fatal(err)
		}
		s.Locality = locality.NewMapper(exits)
	}
	r := New(s, g, stats.New())
	c := &clock{t: time.Now()}
	r.now = c.now
	return r, g, c
}

var (
	clientServer = netip.MustParseAddr("10.9.0.1")
	clientA      = netip.MustParseAddr("10.1.0.5")
	clientB      = netip.MustParseAddr("10.2.0.5")
)

func lastA(t *testing.T, resp []byte) (string, uint32) {
	t.Helper()
	p := dnstest.Parse(t, resp)
	if p.AN == 0 {
		t.Fatalf("no answer: %+v", p)
	}
	i := bytes.LastIndex(resp, []byte{0, 4, 1, 0, 0})
	if i < 0 {
		t.Fatalf("no 1.0.0.x address in %x", resp)
	}
	return netip.AddrFrom4([4]byte(resp[i+2 : i+6])).String(), p.TTLs[0]
}

func TestLocalityVariantPerClient(t *testing.T) {
	r, g, c := localityTest(t, true)
	q := dnstest.Query(1, "vary.test", m.TypeA, false, false)
	res := r.ResolveOpts(q, Opts{Client: clientA})
	if a, _ := lastA(t, res.Resp); a != "1.0.0.1" || res.Status != "miss" {
		t.Fatalf("view a: %s %s", a, res.Status)
	}
	for client, want := range map[netip.Addr]string{clientB: "1.0.0.2", clientServer: "1.0.0.0", clientA: "1.0.0.1"} {
		res := r.ResolveOpts(q, Opts{Client: client})
		a, ttl := lastA(t, res.Resp)
		if a != want || res.Status != "hit" {
			t.Errorf("%s: %s %s, want %s from the cache", client, a, res.Status, want)
		}
		if ttl > 60 {
			t.Errorf("%s: TTL %d: every view expires with the first (60)", client, ttl)
		}
	}
	if g.calls[1] != 1 || len(g.calls) != 1 {
		t.Fatalf("asked %v: once is enough for every view", g.calls)
	}
	c.add(61 * time.Second) // all expired together: asked again, for this client's view
	r.set.Load().ServeStale = 0
	if res := r.ResolveOpts(q, Opts{Client: clientB}); res.Status != "miss" {
		t.Fatalf("after expiry: %s", res.Status)
	}
	if g.calls[2] != 1 {
		t.Fatalf("asked %v", g.calls)
	}
	// a name the same for everyone: no variants, one answer
	res = r.ResolveOpts(dnstest.Query(2, "same.test", m.TypeA, false, false), Opts{Client: clientA})
	if res.Status != "miss" || !g.sawVars {
		t.Fatalf("same.test: %s", res.Status)
	}
	sq, _, _ := m.ParseQuery(dnstest.Query(2, "same.test", m.TypeA, false, false))
	if e := r.cache.get(sq.CacheKey()); e == nil || e.views != nil {
		t.Fatal("variants kept for a name the same for everyone")
	}
}

// TestLocalityVariantNotKnownYet: a client whose view's answer is not
// known yet asks for it (the recursion joins the lookups in progress).
func TestLocalityVariantNotKnownYet(t *testing.T) {
	r, g, _ := localityTest(t, true)
	g.missing = 2
	q := dnstest.Query(1, "vary.test", m.TypeA, false, false)
	r.ResolveOpts(q, Opts{Client: clientA})
	res := r.ResolveOpts(q, Opts{Client: clientB})
	if a, _ := lastA(t, res.Resp); a != "1.0.0.2" || res.Status != "miss" {
		t.Fatalf("view b: %s %s", a, res.Status)
	}
	if g.calls[2] != 1 {
		t.Fatalf("asked %v", g.calls)
	}
	if res := r.ResolveOpts(q, Opts{Client: clientB}); res.Status != "hit" {
		t.Fatalf("then: %s", res.Status)
	}
}

func TestLocalityOffAsksForNoVariants(t *testing.T) {
	r, g, _ := localityTest(t, false)
	q := dnstest.Query(1, "vary.test", m.TypeA, false, false)
	if a, _ := lastA(t, r.ResolveOpts(q, Opts{Client: clientA}).Resp); a != "1.0.0.0" || g.sawVars {
		t.Fatalf("off: %s, variants asked for: %v", a, g.sawVars)
	}
	if res := r.ResolveOpts(dnstest.Query(1, "locality.server", typeTXT, false, false), Opts{Client: clientA}); res.Status == "local" {
		t.Fatal("the locality name answered while off")
	}
}

func TestLocalityVariantsNotSaved(t *testing.T) {
	r, _, _ := localityTest(t, true)
	r.ResolveOpts(dnstest.Query(1, "vary.test", m.TypeA, false, false), Opts{Client: clientA})
	r.ResolveOpts(dnstest.Query(2, "same.test", m.TypeA, false, false), Opts{Client: clientA})
	var buf bytes.Buffer
	if n, err := r.SaveCache(&buf); err != nil || n != 1 {
		t.Fatalf("saved %d: %v", n, err)
	}
	if bytes.Contains(buf.Bytes(), dnstest.Wire("vary.test")) {
		t.Fatal("an answer that depends on where it was asked was saved")
	}
}

func TestLocalityName(t *testing.T) {
	r, _, _ := localityTest(t, true)
	q := dnstest.Query(1, "locality.server", typeTXT, false, false)
	q[len(q)-1] = 3 // class CH
	for client, want := range map[netip.Addr][]string{
		clientA:      {"view=a", "by=10.1.0.0/16"},
		clientServer: {"view=server", "by=none"},
	} {
		res := r.ResolveOpts(q, Opts{Client: client})
		if res.Status != "local" {
			t.Fatalf("%s: %s", client, res.Status)
		}
		for _, w := range want {
			if !bytes.Contains(res.Resp, []byte(w)) {
				t.Errorf("%s: %q missing", client, w)
			}
		}
	}
}

func TestLocalityReportCountsOnly(t *testing.T) {
	r, _, _ := localityTest(t, true)
	r.ResolveOpts(dnstest.Query(1, "vary.test", m.TypeA, false, false), Opts{Client: clientA})
	r.ResolveOpts(dnstest.Query(2, "vary.test", m.TypeA, false, false), Opts{Client: clientB})
	r.ResolveOpts(dnstest.Query(3, "same.test", m.TypeA, false, false), Opts{Client: clientB})
	rows := r.set.Load().Locality.Report.Rows()
	if len(rows) != 1 || rows[0] != (locality.ReportRow{Country: "--", Queries: 3, Varying: 2}) {
		t.Fatalf("%+v", rows)
	}
}

// Other exits, or locality turned off: answers kept per view are dropped,
// the others kept.
func TestLocalityVariantsDroppedWhenExitsChange(t *testing.T) {
	r, _, _ := localityTest(t, true)
	r.ResolveOpts(dnstest.Query(1, "vary.test", m.TypeA, false, false), Opts{Client: clientA})
	r.ResolveOpts(dnstest.Query(2, "same.test", m.TypeA, false, false), Opts{Client: clientA})
	s := *r.set.Load()
	exits, _ := locality.ParseExits([]string{"a 10.66.1.2 10.1.0.0/16", "b 10.66.2.2 10.3.0.0/16"})
	s.Locality = locality.NewMapper(exits) // same exits, other clients: kept
	r.SetSettings(s)
	if pos, _ := r.CacheCounts(); pos != 2 {
		t.Fatalf("same exits: %d entries", pos)
	}
	s.Locality = nil
	r.SetSettings(s)
	if pos, _ := r.CacheCounts(); pos != 1 {
		t.Fatalf("off: %d entries, want only the one the same for everyone", pos)
	}
}
