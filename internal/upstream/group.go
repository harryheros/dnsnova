package upstream

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"slices"
	"sync/atomic"
	"time"

	"github.com/harryheros/dnsnova/internal/dnsmsg"
)

// ErrBadRcode reports an upstream answer of SERVFAIL or REFUSED.
var ErrBadRcode = errors.New("upstream answered SERVFAIL or REFUSED")

// Member is one upstream in a group, with its health.
type Member struct {
	U        Upstream
	Fallback bool

	ewma    atomic.Int64 // smoothed latency in microseconds; 0 = unknown
	queries atomic.Uint64
	errors  atomic.Uint64
	lastOK  atomic.Int64 // unix nanos
	lastErr atomic.Int64
}

// Latency is the smoothed response time.
func (m *Member) Latency() time.Duration { return time.Duration(m.ewma.Load()) * time.Microsecond }

// Queries and Errors are lifetime counters.
func (m *Member) Queries() uint64 { return m.queries.Load() }
func (m *Member) Errors() uint64  { return m.errors.Load() }

// LastOK and LastError are when the last success and failure happened (zero
// if never).
func (m *Member) LastOK() time.Time    { return unixTime(m.lastOK.Load()) }
func (m *Member) LastError() time.Time { return unixTime(m.lastErr.Load()) }

func unixTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// Healthy reports whether the most recent outcome was a success, or no query
// has been sent yet.
func (m *Member) Healthy() bool { return m.lastErr.Load() <= m.lastOK.Load() }

func (m *Member) observe(d time.Duration, err error, timeout time.Duration) {
	if err != nil && errors.Is(err, context.Canceled) {
		return // lost the race to a faster upstream: not a failure
	}
	now := time.Now().UnixNano()
	old := m.ewma.Load()
	var nv int64
	if err != nil {
		m.errors.Add(1)
		m.lastErr.Store(now)
		nv = max(old*2, int64(timeout/time.Microsecond))
		nv = min(nv, int64(10*time.Second/time.Microsecond))
	} else {
		m.lastOK.Store(now)
		s := int64(d / time.Microsecond)
		if old == 0 {
			nv = s
		} else {
			nv = (old*4 + s) / 5
		}
	}
	m.ewma.Store(nv)
}

// Group sends each query to the fastest primary upstreams in parallel and
// uses the fallback upstreams only when the primaries have all failed or have
// not answered within FallbackDelay. The first good answer wins.
type Group struct {
	primary  []*Member
	fallback []*Member
	parallel int
	timeout  time.Duration
	delay    time.Duration
	n        atomic.Uint64
}

// Options configures a Group.
type Options struct {
	Primary       []string
	Fallback      []string
	Bootstrap     []string
	Parallel      int // how many primaries to query at once; 0 = all
	Timeout       time.Duration
	FallbackDelay time.Duration
	TLS           *tls.Config // tests only
}

// NewGroup builds the upstreams.
func NewGroup(o Options) (*Group, error) {
	var boot *Bootstrap
	if len(o.Bootstrap) > 0 {
		b, err := NewBootstrap(o.Bootstrap)
		if err != nil {
			return nil, err
		}
		boot = b
	}
	d := NewDialer(boot)
	g := &Group{parallel: o.Parallel, timeout: o.Timeout, delay: o.FallbackDelay}
	build := func(list []string, fallback bool) ([]*Member, error) {
		var out []*Member
		for _, raw := range list {
			s, err := ParseSpec(raw)
			if err != nil {
				return nil, err
			}
			u, err := New(s, d, o.TLS)
			if err != nil {
				return nil, err
			}
			out = append(out, &Member{U: u, Fallback: fallback})
		}
		return out, nil
	}
	var err error
	if g.primary, err = build(o.Primary, false); err != nil {
		return nil, err
	}
	if g.fallback, err = build(o.Fallback, true); err != nil {
		return nil, err
	}
	if len(g.primary) == 0 {
		return nil, errors.New("no primary upstreams")
	}
	return g, nil
}

// Members returns primaries followed by fallbacks.
func (g *Group) Members() []*Member { return append(slices.Clone(g.primary), g.fallback...) }

// Close releases idle connections.
func (g *Group) Close() {
	for _, m := range g.Members() {
		m.U.Close()
	}
}

// pick returns the fastest `parallel` members of list; every 16th call also
// adds one slower member so a recovered upstream can win its place back.
func (g *Group) pick(list []*Member) []*Member {
	if g.parallel <= 0 || g.parallel >= len(list) {
		return list
	}
	s := slices.Clone(list)
	slices.SortStableFunc(s, func(a, b *Member) int { return cmp.Compare(a.ewma.Load(), b.ewma.Load()) })
	sel := s[:g.parallel:g.parallel]
	if g.n.Add(1)%16 == 0 {
		sel = append(sel, s[g.parallel+rand.IntN(len(s)-g.parallel)])
	}
	return sel
}

type result struct {
	resp []byte
	err  error
}

// Exchange resolves msg. ctx should carry the overall deadline.
func (g *Group) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan result, len(g.primary)+len(g.fallback)+1)
	pending := 0
	launch := func(list []*Member) {
		for _, m := range g.pick(list) {
			pending++
			go func(m *Member) {
				start := time.Now()
				m.queries.Add(1)
				resp, err := m.U.Exchange(ctx, msg)
				if err == nil {
					if rc := dnsmsg.Rcode(resp); rc == dnsmsg.RcodeServFail || rc == dnsmsg.RcodeRefused {
						err = ErrBadRcode
					}
				}
				m.observe(time.Since(start), err, g.timeout)
				ch <- result{resp, err}
			}(m)
		}
	}
	launch(g.primary)

	var timer <-chan time.Time
	fallbackStarted := len(g.fallback) == 0
	if !fallbackStarted {
		t := time.NewTimer(g.delay)
		defer t.Stop()
		timer = t.C
	}
	var fallbackResp []byte
	var lastErr error
	for {
		select {
		case r := <-ch:
			pending--
			if r.err == nil {
				return r.resp, nil
			}
			if r.resp != nil {
				fallbackResp = r.resp
			}
			lastErr = r.err
			if pending == 0 {
				if !fallbackStarted {
					fallbackStarted = true
					timer = nil
					launch(g.fallback)
					continue
				}
				if fallbackResp != nil {
					return fallbackResp, nil // everyone said SERVFAIL: pass it on
				}
				return nil, lastErr
			}
		case <-timer:
			timer = nil
			if !fallbackStarted {
				fallbackStarted = true
				launch(g.fallback)
			}
		case <-ctx.Done():
			if fallbackResp != nil {
				return fallbackResp, nil
			}
			return nil, ctx.Err()
		}
	}
}
