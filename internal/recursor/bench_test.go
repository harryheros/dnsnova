package recursor

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// BenchmarkResolveNew resolves a name never asked before under a zone whose
// servers are already known: the work done for most cache misses.
func BenchmarkResolveNew(b *testing.B) {
	for _, v := range []struct{ min, cookies bool }{{false, false}, {true, false}, {false, true}} {
		b.Run(fmt.Sprintf("minimise=%v/cookies=%v", v.min, v.cookies), func(b *testing.B) {
			n := world()
			r := newTest(&testing.T{}, n, v.min)
			c := *r.cfg.Load()
			c.Cookies = v.cookies
			r.SetConfig(c)
			ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
			defer cancel()
			warm := buildQuery(1, dotted("www.example.com"), 1, true, nil)
			warm[2] |= 1
			if _, err := r.Exchange(ctx, warm); err != nil {
				b.Fatal(err)
			}
			before := n.servers[exA].queries.Load() + n.servers[ex2A].queries.Load()
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				q := buildQuery(uint16(i), dotted(fmt.Sprintf("u%d.example.com", i)), 1, true, nil)
				q[2] |= 1
				if _, err := r.Exchange(ctx, q); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if sent := n.servers[exA].queries.Load() + n.servers[ex2A].queries.Load() - before; sent < int64(b.N) {
				b.Fatalf("%d queries to the zone's servers for %d names", sent, b.N)
			}
		})
	}
}
