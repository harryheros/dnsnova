package resolver

import (
	"context"
	"fmt"
	"strings"
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
