package resolver

import (
	"github.com/harryheros/dnsnova/internal/locality"

	"net/netip"

	"testing"

	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/stats"
)

// BenchmarkCacheHit measures the hot path of a busy public resolver: an
// answer served from the cache to a plain UDP client.
func BenchmarkCacheHit(b *testing.B) {
	r := New(settings(), dnstest.Exchanger{Auth: dnstest.NewAuth()}, stats.New())
	q := dnstest.Query(1, "www.example.test", 1, true, false)
	r.Resolve(q, true)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.ResolveOpts(q, Opts{UDP: true})
		}
	})
}

// BenchmarkCacheHitLocality is BenchmarkCacheHit with private locality on:
// the client's view is picked (by network, then by country) and the query
// counted for the siting report; for a name whose answers vary, the
// client's variant is served.
func BenchmarkCacheHitLocality(b *testing.B) {
	for _, name := range []string{"www.example.test", "vary.test"} {
		b.Run(name, func(b *testing.B) {
			g := &geoUp{calls: map[int]int{}, missing: -1, ttlByVar: []uint32{300, 300, 300}}
			s := settings()
			exits, _ := locality.ParseExits([]string{"a 10.66.1.2 10.1.0.0/16 XA", "b 10.66.2.2 10.2.0.0/16 XC"})
			s.Locality = locality.NewMapper(exits)
			r := New(s, g, stats.New())
			q := dnstest.Query(1, name, 1, true, false)
			o := Opts{UDP: true, Client: netip.MustParseAddr("10.1.0.5")}
			r.ResolveOpts(q, o)
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r.ResolveOpts(q, o)
				}
			})
		})
	}
}
