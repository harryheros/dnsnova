package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRec struct {
	healthy, intercepted atomic.Bool
	calls                atomic.Int64
	delay                time.Duration
}

func (f *fakeRec) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	f.calls.Add(1)
	select {
	case <-time.After(f.delay):
		return nil, errors.New("unreachable")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (f *fakeRec) Healthy() bool     { return f.healthy.Load() }
func (f *fakeRec) Intercepted() bool { return f.intercepted.Load() }

type fakeUp struct{ calls atomic.Int64 }

func (u *fakeUp) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	u.calls.Add(1)
	return []byte("up"), nil
}

// TestRecursionDownAsksUpstreamsAtOnce: while recursion cannot work (name
// servers unreachable, or port 53 intercepted), queries go straight to the
// upstreams instead of each waiting for its lookup to fail; one lookup at a
// time still tries the name servers in the background.
func TestRecursionDownAsksUpstreamsAtOnce(t *testing.T) {
	for _, intercepted := range []bool{false, true} {
		rec := &fakeRec{delay: 2 * time.Second}
		rec.healthy.Store(intercepted) // intercepted: answers arrive, but rewritten
		rec.intercepted.Store(intercepted)
		up := &fakeUp{}
		x := &recursive{s: &Server{}, rec: rec, up: up}
		start := time.Now()
		for range 10 {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			resp, err := x.Exchange(ctx, []byte{0})
			cancel()
			if err != nil || string(resp) != "up" {
				t.Fatalf("resp %q err %v", resp, err)
			}
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("intercepted %v: 10 queries took %v", intercepted, d)
		}
		for i := 0; rec.calls.Load() == 0 && i < 100; i++ {
			time.Sleep(5 * time.Millisecond) // the background lookup starts
		}
		if n := rec.calls.Load(); n != 1 {
			t.Fatalf("intercepted %v: %d background lookups, want 1 at a time", intercepted, n)
		}
	}
	// healthy: recursion first, as before
	rec := &fakeRec{delay: 10 * time.Millisecond}
	rec.healthy.Store(true)
	up := &fakeUp{}
	x := &recursive{s: &Server{}, rec: rec, up: up}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	x.Exchange(ctx, []byte{0})
	if rec.calls.Load() != 1 || up.calls.Load() != 1 {
		t.Fatalf("healthy: rec %d up %d", rec.calls.Load(), up.calls.Load())
	}
}
