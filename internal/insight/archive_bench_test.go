package insight

import (
	"context"
	"testing"
	"time"
)

// BenchmarkArchiveAdd is the cost on the query path: one queued record.
func BenchmarkArchiveAdd(b *testing.B) {
	a := NewArchive()
	a.Configure(ArchiveSettings{Dir: b.TempDir(), Days: 1, FullIP: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)
	rec := q(time.Now(), "www.example.com", "NOERROR", "cache")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			a.Add(rec, alice)
		}
	})
}

// BenchmarkArchiveWrite is how fast the writer turns records into lines.
func BenchmarkArchiveWrite(b *testing.B) {
	a := NewArchive()
	a.Configure(ArchiveSettings{Dir: b.TempDir(), Days: 1, FullIP: true})
	rec := q(time.Now(), "www.example.com", "NOERROR", "cache")
	rec.Client = "192.168.1.23"
	b.ReportAllocs()
	a.mu.Lock()
	for i := 0; i < b.N; i++ {
		a.writeLocked(rec)
	}
	a.flushLocked()
	a.mu.Unlock()
}
