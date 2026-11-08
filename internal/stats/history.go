package stats

import (
	"sync"
	"time"
)

// History keeps snapshots of the counters so the admin interface can show
// totals and charts for the last hour, day or week. It holds three rings:
// one sample a minute for an hour, one every five minutes for a day and one
// an hour for a week, about 600 samples in all. Nothing is written to disk.
type History struct {
	s *Stats

	mu     sync.Mutex
	minute ring
	five   ring
	hour   ring
}

type sample struct {
	t        time.Time
	queries  [numProto]uint64
	rejected [numReject]uint64
	sources  [numSource]uint64
	cache    [16]uint64 // histogram bucket counts (len(DefaultBounds)+1)
	upstream [16]uint64
}

type ring struct {
	buf  []sample
	head int // next write
	n    int
	step time.Duration
	last time.Time
}

func newRing(size int, step time.Duration) ring { return ring{buf: make([]sample, size), step: step} }

func (r *ring) add(s sample) {
	r.buf[r.head] = s
	r.head = (r.head + 1) % len(r.buf)
	if r.n < len(r.buf) {
		r.n++
	}
	r.last = s.t
}

// each calls f for every sample, oldest first.
func (r *ring) each(f func(*sample)) {
	start := (r.head - r.n + len(r.buf)) % len(r.buf)
	for i := 0; i < r.n; i++ {
		f(&r.buf[(start+i)%len(r.buf)])
	}
}

// SetHours keeps n hourly samples (the longest range shown is n-1 hours),
// keeping the most recent ones when the ring shrinks.
func (h *History) SetHours(n int) {
	if n < 2 {
		n = 2
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.hour.buf) == n {
		return
	}
	nr := newRing(n, time.Hour)
	var keep []sample
	h.hour.each(func(s *sample) { keep = append(keep, *s) })
	if len(keep) > n {
		keep = keep[len(keep)-n:]
	}
	for _, s := range keep {
		nr.add(s)
	}
	h.hour = nr
}

// Reset forgets every sample; totals and charts start again from now. The
// counters themselves (and the Prometheus metrics) are not touched.
func (h *History) Reset(now time.Time) {
	smp := h.s.sample(now)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.minute = newRing(len(h.minute.buf), time.Minute)
	h.five = newRing(len(h.five.buf), 5*time.Minute)
	h.hour = newRing(len(h.hour.buf), time.Hour)
	h.minute.add(smp)
	h.five.add(smp)
	h.hour.add(smp)
}

// NewHistory starts a history with a zero sample at the server's start.
func NewHistory(s *Stats) *History {
	h := &History{s: s, minute: newRing(61, time.Minute), five: newRing(289, 5*time.Minute), hour: newRing(169, time.Hour)}
	zero := sample{t: s.Started}
	h.minute.add(zero)
	h.five.add(zero)
	h.hour.add(zero)
	return h
}

func (s *Stats) sample(now time.Time) sample {
	out := sample{t: now}
	for i := range s.Queries {
		out.queries[i] = s.Queries[i].Load()
	}
	for i := range s.Rejected {
		out.rejected[i] = s.Rejected[i].Load()
	}
	for i := range s.Sources {
		out.sources[i] = s.Sources[i].Load()
	}
	for i := range s.LatencyCache.counts {
		out.cache[i] = s.LatencyCache.counts[i].Load()
		out.upstream[i] = s.LatencyUpstream.counts[i].Load()
	}
	return out
}

// Tick records a sample; call it about once a minute. Each ring takes a
// sample once its step has passed since its last one.
func (h *History) Tick(now time.Time) {
	smp := h.s.sample(now)
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range []*ring{&h.minute, &h.five, &h.hour} {
		if now.Sub(r.last) >= r.step-time.Second {
			r.add(smp)
		}
	}
}

// Percentiles are response times in milliseconds.
type Percentiles struct {
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
}

// Point is one step of a chart.
type Point struct {
	T       time.Time   `json:"t"`
	Queries uint64      `json:"queries"`
	Latency Percentiles `json:"latency"`
}

// Report sums a time range.
type Report struct {
	From     time.Time         `json:"from"`
	To       time.Time         `json:"to"`
	Queries  map[string]uint64 `json:"queries"`
	Rejected map[string]uint64 `json:"rejected"`
	Answers  map[string]uint64 `json:"answers"`
	// CacheRatio is the share of answers served from the cache (fresh or
	// stale), 0..1.
	CacheRatio float64 `json:"cache_ratio"`
	Latency    struct {
		All      Percentiles `json:"all"`
		Cache    Percentiles `json:"cache"`
		Upstream Percentiles `json:"upstream"`
	} `json:"latency"`
	Series []Point `json:"series"`
}

// Report sums the last span (at most the hourly ring's length) and returns a chart with one
// point per minute (span up to an hour), five minutes (up to a day) or hour.
// The range starts at the server's start if that is more recent.
func (h *History) Report(span time.Duration, now time.Time) Report {
	live := h.s.sample(now)
	h.mu.Lock()
	r := &h.hour
	switch {
	case span <= time.Hour:
		r = &h.minute
	case span <= 24*time.Hour:
		r = &h.five
	}
	from := now.Add(-span)
	var pts []sample
	var base *sample
	r.each(func(s *sample) {
		if !s.t.After(from) {
			c := *s
			base = &c // latest sample at or before the start of the range
			return
		}
		pts = append(pts, *s)
	})
	h.mu.Unlock()
	if base == nil { // the range reaches back before the oldest sample
		if len(pts) == 0 {
			base = &sample{t: h.s.Started}
		} else {
			base, pts = &pts[0], pts[1:]
		}
	}
	pts = append(pts, live)

	rep := Report{From: base.t, To: now, Queries: map[string]uint64{}, Rejected: map[string]uint64{}, Answers: map[string]uint64{}}
	for i, n := range protoNames {
		rep.Queries[n] = live.queries[i] - base.queries[i]
	}
	for i, n := range rejectNames {
		rep.Rejected[n] = live.rejected[i] - base.rejected[i]
	}
	var answers uint64
	for i, n := range sourceNames {
		d := live.sources[i] - base.sources[i]
		rep.Answers[n] = d
		answers += d
	}
	if answers > 0 {
		rep.CacheRatio = float64(rep.Answers["cache"]+rep.Answers["stale"]) / float64(answers)
	}
	c, u := diff(live.cache, base.cache), diff(live.upstream, base.upstream)
	rep.Latency.Cache = percentiles(c)
	rep.Latency.Upstream = percentiles(u)
	rep.Latency.All = percentiles(sum(c, u))

	prev := *base
	for _, p := range pts {
		var q uint64
		for i := range p.queries {
			q += p.queries[i] - prev.queries[i]
		}
		rep.Series = append(rep.Series, Point{T: p.t, Queries: q,
			Latency: percentiles(sum(diff(p.cache, prev.cache), diff(p.upstream, prev.upstream)))})
		prev = p
	}
	return rep
}

func diff(a, b [16]uint64) (out [16]uint64) {
	for i := range a {
		out[i] = a[i] - b[i]
	}
	return
}

func sum(a, b [16]uint64) (out [16]uint64) {
	for i := range a {
		out[i] = a[i] + b[i]
	}
	return
}

func percentiles(c [16]uint64) Percentiles {
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	return Percentiles{P50: ms(quantile(c[:], 0.5)), P95: ms(quantile(c[:], 0.95))}
}

// quantile estimates quantile q from bucket counts by linear interpolation
// within the bucket that holds it.
func quantile(counts []uint64, q float64) time.Duration {
	var total uint64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	rank := q * float64(total)
	var cum float64
	lower := 0.0
	for i, n := range counts {
		c := float64(n)
		upper := lower * 2
		if i < len(DefaultBounds) {
			upper = DefaultBounds[i]
		}
		if cum+c >= rank && c > 0 {
			frac := (rank - cum) / c
			return time.Duration((lower + frac*(upper-lower)) * float64(time.Second))
		}
		cum += c
		lower = upper
	}
	return time.Duration(lower * float64(time.Second))
}
