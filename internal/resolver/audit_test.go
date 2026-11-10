package resolver

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/filter"
	"github.com/harryheros/dnsnova/internal/stats"
)

// TestCacheSizeIsHonoured: a small cache.size is not rounded up to 16
// entries per shard (4,096 in all).
func TestCacheSizeIsHonoured(t *testing.T) {
	c := newCache(100)
	for i := range 5000 {
		c.set(fmt.Sprintf("k%d", i), &entry{expire: time.Now().Add(time.Hour)})
	}
	if p, n := c.counts(); p+n > 100+255 {
		t.Fatalf("size 100 holds %d entries", p+n)
	}
}

// signedUpstream answers with an A record and its RRSIG, both TTL 60.
type signedUpstream struct{}

func (signedUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	q, _, _ := m.ParseQuery(msg)
	b := []byte{msg[0], msg[1], 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0}
	b = append(b, msg[m.HeaderLen:q.QEnd]...)
	b = append(b, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
	sig := make([]byte, 18) // type covered, algorithm, labels, original TTL, times, key tag
	sig = append(sig, 0)    // signer: the root
	sig = append(sig, make([]byte, 64)...)
	b = append(b, 0xC0, 12, 0, 46, 0, 1, 0, 0, 0, 60, byte(len(sig)>>8), byte(len(sig)))
	return append(b, sig...), nil
}

// TestMinTTLLeavesSignedAnswers: min_ttl does not stretch an answer that
// carries DNSSEC signatures; unsigned answers still get it.
func TestMinTTLLeavesSignedAnswers(t *testing.T) {
	s := settings()
	s.MinTTL = 600
	r := New(s, signedUpstream{}, stats.New())
	res := r.ResolveOpts(dnstest.Query(1, "signed.test", 1, true, false), Opts{UDP: true})
	for _, ttl := range dnstest.Parse(t, res.Resp).TTLs {
		if ttl > 60 {
			t.Fatalf("signed answer stretched to TTL %d by min_ttl", ttl)
		}
	}
	r2 := New(s, cnameUpstream{"cdn.example.net"}, stats.New())
	res = r2.ResolveOpts(dnstest.Query(2, "plain.test", 1, false, false), Opts{UDP: true})
	for _, ttl := range dnstest.Parse(t, res.Resp).TTLs {
		if ttl < 600 {
			t.Fatalf("unsigned answer TTL %d, min_ttl 600 not applied", ttl)
		}
	}
}

// longChainUpstream answers with a chain of n CNAMEs.
type longChainUpstream struct{ n int }

func (u longChainUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	q, _, _ := m.ParseQuery(msg)
	b := []byte{msg[0], msg[1], 0x81, 0x80, 0, 1, byte(u.n >> 8), byte(u.n), 0, 0, 0, 0}
	b = append(b, msg[m.HeaderLen:q.QEnd]...)
	owner := []byte{0xC0, 12}
	for i := range u.n {
		t := dnstest.Wire(fmt.Sprintf("hop%d.chain.example", i))
		b = append(b, owner...)
		b = append(b, 0, 5, 0, 1, 0, 0, 1, 44, 0, byte(len(t)))
		off := len(b)
		b = append(b, t...)
		owner = []byte{0xC0 | byte(off>>8), byte(off)}
	}
	return b, nil
}

// TestLongCNAMEChainFailsClosed: a chain too long to check every name is
// blocked on the filtered service, answered on the usual one.
func TestLongCNAMEChainFailsClosed(t *testing.T) {
	r := New(settings(), longChainUpstream{40}, stats.New())
	b := filter.NewBuilder()
	filter.Parse(strings.NewReader("||tracker.example^\n"), b)
	r.SetFilter(b.Set())
	if res := r.ResolveOpts(dnstest.Query(1, "a.site.example", 1, false, false), Opts{UDP: true}); res.Status == "blocked" {
		t.Fatal("unfiltered service blocked a long chain")
	}
	if res := r.ResolveOpts(dnstest.Query(2, "b.site.example", 1, false, false), Opts{UDP: true, Filter: true}); res.Status != "blocked" {
		t.Fatalf("filtered service let an unchecked chain through: %s", res.Status)
	}
	r.SetUpstreams(longChainUpstream{5})
	if res := r.ResolveOpts(dnstest.Query(3, "c.site.example", 1, false, false), Opts{UDP: true, Filter: true}); res.Status == "blocked" {
		t.Fatal("a short clean chain was blocked")
	}
}

// TestNoRecursionRefused: a query without RD is refused, whether or not
// the answer is in the cache, and no upstream is asked for it.
func TestNoRecursionRefused(t *testing.T) {
	r, auth, _ := newTest(t)
	norec := func(id uint16, name string) []byte {
		q := dnstest.Query(id, name, 1, true, false)
		q[2] &^= 0x01
		return q
	}
	res := r.Resolve(norec(1, "norec.test"), true)
	if p := dnstest.Parse(t, res.Resp); p.Rcode != m.RcodeRefused || p.AN != 0 {
		t.Fatalf("RD=0, not cached: %+v", p)
	}
	if code, ok := edeCode(res.Resp); !ok || code != m.EDENotAuth {
		t.Errorf("EDE %d %v", code, ok)
	}
	if n := auth.Count("norec.test."); n != 0 {
		t.Fatalf("upstream asked %d times for a query without RD", n)
	}
	r.Resolve(dnstest.Query(2, "cached.test", 1, false, false), true)
	if p := dnstest.Parse(t, r.Resolve(norec(3, "cached.test"), true).Resp); p.Rcode != m.RcodeRefused || p.AN != 0 {
		t.Fatalf("RD=0 read the cache: %+v", p)
	}
	// names this server answers itself do not need recursion
	if p := dnstest.Parse(t, r.Resolve(norec(4, "localhost"), true).Resp); p.Rcode != 0 || p.AN != 1 {
		t.Fatalf("localhost without RD: %+v", p)
	}
}

// TestADNotWithCDNorStale: AD is not passed on to a client that set CD,
// and not on a stale answer.
func TestADNotWithCDNorStale(t *testing.T) {
	r, auth, c := newTest(t)
	auth.SetTTL(60)
	cd := dnstest.Query(1, "signed.test", 1, true, true)
	cd[3] |= 0x10
	if p := dnstest.Parse(t, r.Resolve(cd, true).Resp); p.AD() || p.AN != 1 {
		t.Fatalf("CD client: %+v", p)
	}
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(2, "signed.test", 1, true, true), true).Resp); !p.AD() {
		t.Fatal("fresh answer without AD")
	}
	c.add(2 * time.Minute)
	res := r.Resolve(dnstest.Query(3, "signed.test", 1, true, true), true)
	if p := dnstest.Parse(t, res.Resp); res.Status != "stale" || p.AD() {
		t.Fatalf("stale answer: %s AD=%v", res.Status, p.AD())
	}
}

// TestMinTTLLeavesValidatedAnswers: an answer marked as validated (AD) is
// not stretched by min_ttl, also for a client that gets no signatures.
func TestMinTTLLeavesValidatedAnswers(t *testing.T) {
	s := settings()
	s.MinTTL = 600
	auth := dnstest.NewAuth()
	auth.SetTTL(60)
	r := New(s, dnstest.Exchanger{Auth: auth}, stats.New())
	for i, name := range []string{"signed.test", "signed.test"} { // miss, then hit
		res := r.ResolveOpts(dnstest.Query(uint16(i), name, 1, false, false), Opts{UDP: true})
		for _, ttl := range dnstest.Parse(t, res.Resp).TTLs {
			if ttl > 60 {
				t.Fatalf("%s: validated answer stretched to TTL %d", res.Status, ttl)
			}
		}
	}
}

// badversUpstream answers RCODE 16 (BADVERS): 0 in the header, 1 in OPT.
type badversUpstream struct{}

func (badversUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	q, _, _ := m.ParseQuery(msg)
	b := []byte{msg[0], msg[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 1}
	b = append(b, msg[m.HeaderLen:q.QEnd]...)
	return append(b, 0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0), nil
}

// TestExtendedRcodeIsFailure: such an answer is a failure, not "no data".
func TestExtendedRcodeIsFailure(t *testing.T) {
	r := New(settings(), badversUpstream{}, stats.New())
	res := r.ResolveOpts(dnstest.Query(1, "ext.test", 1, true, false), Opts{UDP: true})
	if p := dnstest.Parse(t, res.Resp); p.Rcode != m.RcodeServFail {
		t.Fatalf("BADVERS from upstream answered as RCODE %d (%s)", p.Rcode, res.Status)
	}
}

// ecsUpstream records the EDNS options of the queries it gets.
type ecsUpstream struct {
	auth *dnstest.Auth
	mu   sync.Mutex
	opts [][]byte
}

func (u *ecsUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	q, _, _ := m.ParseQuery(msg)
	u.mu.Lock()
	u.opts = append(u.opts, append([]byte(nil), msg[q.QEnd+11:]...))
	u.mu.Unlock()
	return u.auth.Answer(msg, false), nil
}

// TestClientSubnetToUpstream: ecs.address goes out with every upstream
// query, a client's own option does not, and changing the network clears
// the cache, which holds answers for the old one.
func TestClientSubnetToUpstream(t *testing.T) {
	up := &ecsUpstream{auth: dnstest.NewAuth()}
	s := settings()
	r := New(s, up, stats.New())
	ask := func(id uint16) string {
		return r.ResolveOpts(dnstest.Query(id, "geo.test", 1, true, false), Opts{UDP: true}).Status
	}
	if ask(1); len(up.opts) != 1 || len(up.opts[0]) != 0 {
		t.Fatalf("off: options %x", up.opts)
	}
	s.ECS = m.ClientSubnet(netip.MustParsePrefix("101.226.4.0/24"))
	r.SetSettings(s)
	if st := ask(2); st != "miss" || len(up.opts) != 2 || !bytes.Equal(up.opts[1], s.ECS) {
		t.Fatalf("on: %s, options %x", st, up.opts)
	}
	if st := ask(3); st != "hit" {
		t.Fatalf("second ask: %s", st)
	}
	r.SetSettings(s) // unchanged: the cache stays
	if st := ask(4); st != "hit" {
		t.Fatalf("after an unrelated reload: %s", st)
	}
	s.ECS = nil
	r.SetSettings(s)
	if st := ask(5); st != "miss" || len(up.opts[len(up.opts)-1]) != 0 {
		t.Fatalf("off again: %s, options %x", st, up.opts)
	}
}

// slowUpstream answers only when released, so a lookup can still be
// asking when the client subnet changes.
type slowUpstream struct {
	auth    *dnstest.Auth
	asked   chan struct{}
	release chan struct{}
}

func (u *slowUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	u.asked <- struct{}{}
	<-u.release
	return u.auth.Answer(msg, false), nil
}

// TestClientSubnetChangeDuringLookup: a lookup asked for the old network
// and answered after the change does not put its answer in the cache, and
// the next query asks again for the new network.
func TestClientSubnetChangeDuringLookup(t *testing.T) {
	up := &slowUpstream{auth: dnstest.NewAuth(), asked: make(chan struct{}, 4), release: make(chan struct{})}
	s := settings()
	s.ECS = m.ClientSubnet(netip.MustParsePrefix("101.226.4.0/24"))
	r := New(s, up, stats.New())
	done := make(chan string, 1)
	go func() {
		done <- r.ResolveOpts(dnstest.Query(1, "late.test", 1, true, false), Opts{UDP: true}).Status
	}()
	<-up.asked // the old lookup is with the upstream
	s.ECS = m.ClientSubnet(netip.MustParsePrefix("198.51.100.0/24"))
	changed := make(chan struct{})
	go func() { r.SetSettings(s); close(changed) }()
	time.Sleep(50 * time.Millisecond)
	close(up.release) // the old answer arrives after the change was asked for
	<-done
	<-changed
	if st := r.ResolveOpts(dnstest.Query(2, "late.test", 1, true, false), Opts{UDP: true}).Status; st == "hit" {
		t.Fatal("an answer for the old network was served from the cache after the change")
	}
}
