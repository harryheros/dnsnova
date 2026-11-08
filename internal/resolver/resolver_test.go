package resolver

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/stats"
)

func settings() Settings {
	return Settings{
		CacheSize: 10000, MaxTTL: 86400, MaxNegTTL: 3600, ServeStale: 24 * time.Hour,
		Prefetch: true, BlockANY: true, UDPMaxSize: 1232, Timeout: 2 * time.Second,
		UpstreamConcurrency: 100, ZoneConcurrency: 10,
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newTest(t *testing.T) (*Resolver, *dnstest.Auth, *clock) {
	auth := dnstest.NewAuth()
	r := New(settings(), dnstest.Exchanger{Auth: auth}, stats.New())
	c := &clock{t: time.Now()}
	r.now = c.now
	return r, auth, c
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCacheAgingAndClientIdentity(t *testing.T) {
	r, auth, c := newTest(t)
	res := r.Resolve(dnstest.Query(1, "a.test", 1, false, false), true)
	p := dnstest.Parse(t, res.Resp)
	if res.Status != "miss" || p.AN != 1 || p.TTLs[0] != 300 || p.ID != 1 || p.HasOPT {
		t.Fatalf("first: %s %+v", res.Status, p)
	}
	c.add(100 * time.Second)
	res = r.Resolve(dnstest.Query(2, "A.TeSt", 1, false, false), true)
	p = dnstest.Parse(t, res.Resp)
	if res.Status != "hit" || p.ID != 2 || p.TTLs[0] != 200 {
		t.Fatalf("second: %s %+v", res.Status, p)
	}
	if !bytes.Equal(p.QName, dnstest.Wire("A.TeSt")) {
		t.Fatalf("question case not preserved: %q", p.QName)
	}
	if auth.Count("a.test.") != 1 {
		t.Fatalf("upstream queried %d times", auth.Count("a.test."))
	}
}

func TestServeStaleThenRefresh(t *testing.T) {
	r, auth, c := newTest(t)
	auth.SetTTL(60)
	r.Resolve(dnstest.Query(1, "s.test", 1, false, false), true)
	c.add(2 * time.Minute)
	auth.SetTTL(120)
	res := r.Resolve(dnstest.Query(2, "s.test", 1, false, false), true)
	if p := dnstest.Parse(t, res.Resp); res.Status != "stale" || p.TTLs[0] != StaleTTL {
		t.Fatalf("want stale: %s %v", res.Status, p.TTLs)
	}
	waitFor(t, func() bool { return auth.Count("s.test.") == 2 })
	waitFor(t, func() bool { return r.Resolve(dnstest.Query(3, "s.test", 1, false, false), true).Status == "hit" })
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(4, "s.test", 1, false, false), true).Resp); p.TTLs[0] != 120 {
		t.Fatalf("refreshed TTL %v", p.TTLs)
	}
}

func TestPrefetch(t *testing.T) {
	r, auth, c := newTest(t)
	auth.SetTTL(100)
	r.Resolve(dnstest.Query(1, "p.test", 1, false, false), true)
	c.add(95 * time.Second)
	if res := r.Resolve(dnstest.Query(2, "p.test", 1, false, false), true); res.Status != "hit" {
		t.Fatal(res.Status)
	}
	waitFor(t, func() bool { return auth.Count("p.test.") == 2 })
}

func TestNegativeCaching(t *testing.T) {
	r, auth, _ := newTest(t)
	for i := 0; i < 3; i++ {
		if p := dnstest.Parse(t, r.Resolve(dnstest.Query(uint16(i), "nx.test", 1, false, false), true).Resp); p.Rcode != m.RcodeNXDomain {
			t.Fatal(p.Rcode)
		}
	}
	if auth.Count("nx.test.") != 1 {
		t.Fatal("NXDOMAIN not cached")
	}
	q, _, _ := m.ParseQuery(dnstest.Query(0, "nx.test", 1, false, false))
	if e := r.cache.get(q.CacheKey()); e == nil || e.ttl != 300 || !e.negative {
		t.Fatalf("negative TTL should be min(SOA TTL 900, minimum 300): %+v", e)
	}
	if pos, neg := r.CacheCounts(); pos != 0 || neg != 1 {
		t.Fatalf("counts %d/%d", pos, neg)
	}
	r.ClearCache()
	if pos, neg := r.CacheCounts(); pos+neg != 0 {
		t.Fatal("clear")
	}
}

func TestTruncationAndEDNS(t *testing.T) {
	r, _, _ := newTest(t)
	p := dnstest.Parse(t, r.Resolve(dnstest.Query(1, "big.test", 16, false, false), true).Resp)
	if !p.TC() || p.AN != 0 || p.HasOPT {
		t.Fatalf("no EDNS over UDP must be truncated: %+v", p)
	}
	p = dnstest.Parse(t, r.Resolve(dnstest.Query(2, "big.test", 16, true, false), true).Resp)
	if p.TC() || p.AN != 15 || !p.HasOPT {
		t.Fatalf("EDNS 1232 fits: %+v", p)
	}
	p = dnstest.Parse(t, r.Resolve(dnstest.Query(3, "big.test", 16, false, false), false).Resp)
	if p.AN != 15 || p.TC() {
		t.Fatalf("TCP is never truncated: %+v", p)
	}
}

func TestADOnlyForClientsThatAsk(t *testing.T) {
	r, _, _ := newTest(t)
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(1, "signed.test", 1, true, true), true).Resp); !p.AD() || !p.OPTDO {
		t.Fatalf("DO client should see AD and DO: %+v", p)
	}
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(2, "signed.test", 1, false, false), true).Resp); p.AD() {
		t.Fatal("a client that did not ask must not get AD")
	}
	// locally answered names never carry AD
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(3, "1.0.0.10.in-addr.arpa", m.TypePTR, true, true), true).Resp); p.AD() {
		t.Fatal("local answer with AD")
	}
}

func TestLocalAnswers(t *testing.T) {
	r, auth, _ := newTest(t)
	cases := []struct {
		name  string
		qtype uint16
		rcode int
		an    int
	}{
		{"4.3.2.10.in-addr.arpa", m.TypePTR, m.RcodeNXDomain, 0},
		{"1.0.20.172.in-addr.arpa", m.TypePTR, m.RcodeNXDomain, 0},
		{"5.5.100.100.in-addr.arpa", m.TypePTR, m.RcodeNXDomain, 0},
		{"168.192.in-addr.arpa", m.TypeSOA, m.RcodeNoError, 0},
		{"localhost", m.TypeA, m.RcodeNoError, 1},
		{"app.localhost", m.TypeAAAA, m.RcodeNoError, 1},
		{"x.invalid", m.TypeA, m.RcodeNXDomain, 0},
	}
	for _, c := range cases {
		res := r.Resolve(dnstest.Query(1, c.name, c.qtype, false, false), true)
		p := dnstest.Parse(t, res.Resp)
		if res.Status != "local" || p.Rcode != c.rcode || p.AN != c.an {
			t.Errorf("%s: %s rcode=%d an=%d", c.name, res.Status, p.Rcode, p.AN)
		}
	}
	// public reverse zones go upstream
	if res := r.Resolve(dnstest.Query(1, "8.8.8.8.in-addr.arpa", m.TypePTR, false, false), true); res.Status != "miss" {
		t.Fatalf("public reverse lookup answered locally: %s", res.Status)
	}
	if auth.Count("4.3.2.10.in-addr.arpa.") != 0 {
		t.Fatal("a private reverse lookup reached the upstream")
	}
}

func TestRefusals(t *testing.T) {
	r, _, _ := newTest(t)
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(1, "a.test", m.TypeANY, false, false), true).Resp); p.Rcode != m.RcodeNotImp {
		t.Fatal("ANY")
	}
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(1, "a.test", m.TypeAXFR, false, false), true).Resp); p.Rcode != m.RcodeRefused {
		t.Fatal("AXFR")
	}
	ch := dnstest.Query(1, "version.bind", 16, false, false)
	ch[len(ch)-1] = 3 // class CHAOS
	if p := dnstest.Parse(t, r.Resolve(ch, true).Resp); p.Rcode != m.RcodeRefused {
		t.Fatal("CHAOS")
	}
	if res := r.Resolve([]byte{1, 2, 3}, true); res.Resp != nil {
		t.Fatal("garbage must be dropped")
	}
}

func TestSingleflight(t *testing.T) {
	r, auth, _ := newTest(t)
	auth.SetDelay(150 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := r.Resolve(dnstest.Query(uint16(i), "slow.test", 1, false, false), true)
			if dnstest.Parse(t, res.Resp).ID != uint16(i) {
				t.Error("wrong ID")
			}
		}(i)
	}
	wg.Wait()
	if n := auth.Count("slow.test."); n != 1 {
		t.Fatalf("50 concurrent queries made %d upstream queries", n)
	}
}

func TestZoneAndUpstreamConcurrencyCaps(t *testing.T) {
	r, auth, _ := newTest(t)
	s := settings()
	s.ZoneConcurrency = 3
	r.SetSettings(s)
	auth.SetDelay(200 * time.Millisecond)
	var wg sync.WaitGroup
	var mu sync.Mutex
	fails := 0
	for i := 0; i < 10; i++ { // random subdomains of one domain
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := r.Resolve(dnstest.Query(1, string(rune('a'+i))+".flood.test", 1, false, false), true)
			if dnstest.Parse(t, res.Resp).Rcode == m.RcodeServFail {
				mu.Lock()
				fails++
				mu.Unlock()
			}
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	if res := r.Resolve(dnstest.Query(1, "other.test", 1, false, false), true); res.Status != "miss" {
		t.Fatalf("another domain must not be affected: %s", res.Status)
	}
	wg.Wait()
	if fails != 7 {
		t.Fatalf("%d of 10 failed, want 7 (3 allowed per domain)", fails)
	}
	if r.stats.Rejected[stats.RejectZoneBusy].Load() != 7 {
		t.Fatal("zone_busy not counted")
	}

	s.ZoneConcurrency, s.UpstreamConcurrency = 0, 1
	r.SetSettings(s)
	go r.Resolve(dnstest.Query(1, "one.test", 1, false, false), true)
	time.Sleep(50 * time.Millisecond)
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(1, "two.test", 1, false, false), true).Resp); p.Rcode != m.RcodeServFail {
		t.Fatal("upstream concurrency cap not applied")
	}
}

func TestZoneOf(t *testing.T) {
	cases := map[string]string{
		"a.b.example.com":         "example.com",
		"example.com":             "example.com",
		"x.y.example.co.uk":       "example.co.uk",
		"com":                     "com",
		"1.2.3.4.in-addr.arpa":    "3.4.in-addr.arpa",
		"deep.sub.domain.example": "domain.example",
	}
	for in, want := range cases {
		q, _, _ := m.ParseQuery(dnstest.Query(0, in, 1, false, false))
		if got := m.NameString(zoneOf(q.Name)); got != want+"." {
			t.Errorf("zoneOf(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestUpstreamFailureIsServfail(t *testing.T) {
	r, auth, _ := newTest(t)
	auth.ServFail.Store(true)
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(1, "a.test", 1, false, false), true).Resp); p.Rcode != m.RcodeServFail {
		t.Fatal("SERVFAIL expected")
	}
	if pos, neg := r.CacheCounts(); pos+neg != 0 {
		t.Fatal("SERVFAIL must not be cached")
	}
	r.SetUpstreams(failing{})
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(1, "b.test", 1, false, false), true).Resp); p.Rcode != m.RcodeServFail {
		t.Fatal("SERVFAIL expected on upstream error")
	}
}

type failing struct{}

func (failing) Exchange(context.Context, []byte) ([]byte, error) {
	return nil, context.DeadlineExceeded
}

// FuzzAnalyze: arbitrary upstream responses must never crash the cache path.
func FuzzAnalyze(f *testing.F) {
	auth := dnstest.NewAuth()
	for _, n := range []string{"a.test", "nx.test", "big.test"} {
		f.Add(auth.Answer(dnstest.Query(1, n, 1, true, true), false))
	}
	q, _, _ := m.ParseQuery(dnstest.Query(1, "a.test", 1, true, true))
	r := New(settings(), failing{}, stats.New())
	req := dnstest.Query(1, "a.test", 1, true, true)
	f.Fuzz(func(t *testing.T, resp []byte) {
		e, err := analyze(resp, q)
		if err != nil {
			return
		}
		e.stored = time.Now()
		e.ttl = 60
		e.expire = e.stored.Add(time.Minute)
		s := settings()
		out := r.build(e, req, q, time.Now(), false, true, &s)
		if len(out) < m.HeaderLen || m.U16(out, 0) != 1 {
			t.Fatal("bad response")
		}
	})
}
