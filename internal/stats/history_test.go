package stats

import (
	"testing"
	"time"
)

func TestHistory(t *testing.T) {
	if len(DefaultBounds)+1 != len(sample{}.cache) {
		t.Fatal("sample arrays must match the histogram buckets")
	}
	s := New()
	t0 := s.Started
	h := NewHistory(s)
	// 30 minutes of traffic: 10 UDP queries a minute, cache answers in ~1 ms
	for m := 1; m <= 30; m++ {
		for i := 0; i < 10; i++ {
			s.Queries[UDP].Add(1)
			s.Sources[SourceCache].Add(1)
			s.LatencyCache.Observe(800 * time.Microsecond)
		}
		if m == 30 {
			s.Queries[DoQ].Add(5)
			s.Sources[SourceUpstream].Add(5)
			for i := 0; i < 5; i++ {
				s.LatencyUpstream.Observe(40 * time.Millisecond)
			}
			s.Rejected[RejectClientLimit].Add(2)
		}
		h.Tick(t0.Add(time.Duration(m) * time.Minute))
	}
	now := t0.Add(30*time.Minute + 10*time.Second)

	r := h.Report(10*time.Minute, now)
	if r.Queries["udp"] != 100 || r.Queries["doq"] != 5 || r.Rejected["client_limit"] != 2 {
		t.Fatalf("last 10 minutes: %v %v", r.Queries, r.Rejected)
	}
	if len(r.Series) != 11 { // 10 minute points and the live one
		t.Fatalf("%d points", len(r.Series))
	}
	if r.CacheRatio < 0.95 || r.CacheRatio > 0.96 {
		t.Fatalf("cache ratio %v", r.CacheRatio)
	}
	if p := r.Latency.Cache.P50; p < 0.5 || p > 1 {
		t.Fatalf("cache median %v ms", p)
	}
	if p := r.Latency.Upstream.P50; p < 25 || p > 50 {
		t.Fatalf("upstream median %v ms", p)
	}

	// a day: the range starts at the server start
	r = h.Report(24*time.Hour, now)
	if r.Queries["udp"] != 300 || !r.From.Equal(t0) {
		t.Fatalf("whole day: %d from %v", r.Queries["udp"], r.From)
	}
	if len(r.Series) != 7 { // samples every 5 minutes, then the live one
		t.Fatalf("day points: %d", len(r.Series))
	}
	var sum uint64
	for _, p := range r.Series {
		sum += p.Queries
	}
	if sum != 305 {
		t.Fatalf("series sums to %d", sum)
	}
	if r = h.Report(7*24*time.Hour, now); r.Queries["udp"] != 300 {
		t.Fatalf("week: %d", r.Queries["udp"])
	}
}

func TestHistoryRetentionAndReset(t *testing.T) {
	s := New()
	t0 := s.Started
	h := NewHistory(s)
	h.SetHours(30*24 + 1)
	for hr := 1; hr <= 40*24; hr++ { // 40 days of one query an hour
		s.Queries[UDP].Add(1)
		h.Tick(t0.Add(time.Duration(hr) * time.Hour))
	}
	now := t0.Add(40*24*time.Hour + time.Minute)
	if r := h.Report(30*24*time.Hour, now); r.Queries["udp"] != 30*24 {
		t.Fatalf("30 days: %d", r.Queries["udp"])
	}
	h.SetHours(7*24 + 1) // shrinking keeps the latest week
	if r := h.Report(7*24*time.Hour, now); r.Queries["udp"] != 7*24 {
		t.Fatalf("7 days after shrinking: %d", r.Queries["udp"])
	}
	h.Reset(now)
	s.Queries[UDP].Add(3)
	if r := h.Report(7*24*time.Hour, now.Add(time.Minute)); r.Queries["udp"] != 3 {
		t.Fatalf("after reset: %d", r.Queries["udp"])
	}
}
