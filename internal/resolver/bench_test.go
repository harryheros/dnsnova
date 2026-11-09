package resolver

import (
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
