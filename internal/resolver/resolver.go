// Package resolver answers queries from local zones, the cache or the
// upstream group, and prepares each answer for the client that asked.
package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/stats"
)

// StaleTTL is the TTL given to clients for answers served past their
// expiry while a fresh one is fetched (RFC 8767).
const StaleTTL = 30

// Exchanger is the upstream group.
type Exchanger interface {
	Exchange(ctx context.Context, msg []byte) ([]byte, error)
}

// Settings can be replaced at run time with SetSettings.
type Settings struct {
	CacheSize           int
	MinTTL              uint32
	MaxTTL              uint32
	MaxNegTTL           uint32
	ServeStale          time.Duration
	Prefetch            bool
	BlockANY            bool
	UDPMaxSize          int
	Timeout             time.Duration
	UpstreamConcurrency int      // 0 = unlimited
	ZoneConcurrency     int      // 0 = unlimited
	DDR                 [][]byte // SVCB record data for _dns.resolver.arpa
	// CheckZone (wire format, lowercase) is the zone of "check it yourself"
	// names, such as check.dns.example.com: a query for <token>.<zone> is
	// answered locally (NXDOMAIN, not cached) with Status "probe", so the
	// server can tell the status page that it was asked. Empty: off.
	CheckZone string
	// Local answers names from local.records (see NewLocalNames).
	Local *LocalNames
}

var (
	errUpstreamBusy = errors.New("too many upstream queries in flight")
	errZoneBusy     = errors.New("too many upstream queries for one domain")
)

// Resolver is safe for concurrent use.
type Resolver struct {
	set   atomic.Pointer[Settings]
	ups   atomic.Pointer[upHolder]
	sem   atomic.Pointer[chan struct{}]
	cache *cache
	sf    flightGroup
	zones zoneLimiter
	stats *stats.Stats
	now   func() time.Time
}

type upHolder struct{ x Exchanger }

// New returns a resolver.
func New(s Settings, ups Exchanger, st *stats.Stats) *Resolver {
	r := &Resolver{cache: newCache(s.CacheSize), stats: st, now: time.Now}
	r.SetSettings(s)
	r.SetUpstreams(ups)
	return r
}

// SetSettings applies new settings; cached answers are kept.
func (r *Resolver) SetSettings(s Settings) {
	old := r.set.Load()
	r.set.Store(&s)
	r.cache.setSize(s.CacheSize)
	if old == nil || old.UpstreamConcurrency != s.UpstreamConcurrency {
		if s.UpstreamConcurrency > 0 {
			ch := make(chan struct{}, s.UpstreamConcurrency)
			r.sem.Store(&ch)
		} else {
			r.sem.Store(nil)
		}
	}
}

// SetUpstreams replaces the upstream group.
func (r *Resolver) SetUpstreams(x Exchanger) { r.ups.Store(&upHolder{x}) }

// ClearCache drops every cached answer.
func (r *Resolver) ClearCache() { r.cache.clear() }

// CacheCounts returns the number of positive and negative cache entries.
func (r *Resolver) CacheCounts() (positive, negative int) { return r.cache.counts() }

// Result is the outcome of Resolve.
type Result struct {
	Resp   []byte   // nil: drop the packet
	Q      *m.Query // nil if the packet could not be parsed
	Source int      // stats.Source*
	Status string   // for logs: hit, stale, miss, local, refused, ...
}

// Resolve answers one raw query. udp applies the client's UDP size limit.
func (r *Resolver) Resolve(req []byte, udp bool) Result {
	start := r.now()
	s := r.set.Load()
	q, rc, err := m.ParseQuery(req)
	if err != nil {
		r.stats.Rejected[stats.RejectMalformed].Add(1)
		return Result{Status: "malformed"}
	}
	if rc != 0 {
		return r.done(Result{Resp: m.ErrorResponse(req, q, rc), Q: q, Source: stats.SourceLocal, Status: m.RcodeString(rc)})
	}
	switch {
	case q.Class != m.ClassIN, q.Type == m.TypeAXFR, q.Type == m.TypeIXFR:
		return r.done(Result{Resp: m.ErrorResponse(req, q, m.RcodeRefused), Q: q, Source: stats.SourceLocal, Status: "refused"})
	case q.Type == m.TypeANY && s.BlockANY:
		return r.done(Result{Resp: m.ErrorResponse(req, q, m.RcodeNotImp), Q: q, Source: stats.SourceLocal, Status: "notimp"})
	}
	if s.CheckZone != "" && isProbe(q.Name, s.CheckZone) {
		return r.done(Result{Resp: r.fit(m.NegativeSOA(req, q, s.CheckZone, 0, m.RcodeNXDomain), req, q, udp, s), Q: q, Source: stats.SourceLocal, Status: "probe"})
	}
	if s.Local != nil {
		if resp := s.Local.answer(req, q); resp != nil {
			return r.done(Result{Resp: r.fit(resp, req, q, udp, s), Q: q, Source: stats.SourceLocal, Status: "local"})
		}
	}
	if resp := localAnswer(req, q, s); resp != nil {
		return r.done(Result{Resp: r.fit(resp, req, q, udp, s), Q: q, Source: stats.SourceLocal, Status: "local"})
	}

	key := q.CacheKey()
	now := r.now()
	e := r.cache.get(key)
	if e != nil && now.Before(e.expire) {
		if s.Prefetch && e.ttl >= 10 && e.expire.Sub(now) < time.Duration(e.ttl)*time.Second/10 {
			r.refreshAsync(key, q, e, now)
		}
		res := Result{Resp: r.build(e, req, q, now, false, udp, s), Q: q, Source: stats.SourceCache, Status: "hit"}
		r.stats.LatencyCache.Observe(r.now().Sub(start))
		return r.done(res)
	}
	stale := e != nil && s.ServeStale > 0 && now.Before(e.expire.Add(s.ServeStale))
	if stale {
		r.refreshAsync(key, q, e, now)
		res := Result{Resp: r.build(e, req, q, now, true, udp, s), Q: q, Source: stats.SourceStale, Status: "stale"}
		r.stats.LatencyCache.Observe(r.now().Sub(start))
		return r.done(res)
	}

	fresh, err := r.sf.do(key, func() (*entry, error) { return r.fetch(q) })
	if err != nil {
		switch {
		case errors.Is(err, errUpstreamBusy):
			r.stats.Rejected[stats.RejectUpstreamBusy].Add(1)
		case errors.Is(err, errZoneBusy):
			r.stats.Rejected[stats.RejectZoneBusy].Add(1)
		}
		return r.done(Result{Resp: m.ErrorResponse(req, q, m.RcodeServFail), Q: q, Source: stats.SourceUpstream, Status: "servfail"})
	}
	res := Result{Resp: r.build(fresh, req, q, r.now(), false, udp, s), Q: q, Source: stats.SourceUpstream, Status: "miss"}
	r.stats.LatencyUpstream.Observe(r.now().Sub(start))
	return r.done(res)
}

func (r *Resolver) done(res Result) Result {
	r.stats.Sources[res.Source].Add(1)
	r.stats.Rcode(m.Rcode(res.Resp))
	return res
}

// refreshAsync fetches a fresh copy in the background, at most once per 5s
// per entry; concurrent refreshes of a key share one upstream query.
func (r *Resolver) refreshAsync(key string, q *m.Query, e *entry, now time.Time) {
	next := e.nextRefresh.Load()
	if now.UnixNano() < next || !e.nextRefresh.CompareAndSwap(next, now.Add(5*time.Second).UnixNano()) {
		return
	}
	r.stats.Refreshes.Add(1)
	go r.sf.do(key, func() (*entry, error) { return r.fetch(q) })
}

func (r *Resolver) fetch(q *m.Query) (*entry, error) {
	s := r.set.Load()
	if semp := r.sem.Load(); semp != nil {
		sem := *semp
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			return nil, errUpstreamBusy
		}
	}
	zone := zoneOf(q.Name)
	if !r.zones.acquire(zone, s.ZoneConcurrency) {
		return nil, errZoneBusy
	}
	defer r.zones.release(zone)

	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	resp, err := r.ups.Load().x.Exchange(ctx, m.BuildUpstreamQuery(q))
	if err != nil {
		return nil, err
	}
	e, err := analyze(resp, q)
	if err != nil {
		return nil, err
	}
	e.stored = r.now()
	if e.cacheable {
		e.ttl = clampTTL(e.ttl, e.negative, s)
		e.cacheable = e.ttl > 0
	}
	e.expire = e.stored.Add(time.Duration(e.ttl) * time.Second)
	if e.cacheable {
		r.cache.set(q.CacheKey(), e)
	}
	return e, nil
}

func clampTTL(t uint32, negative bool, s *Settings) uint32 {
	if negative {
		return min(t, s.MaxNegTTL)
	}
	return min(max(t, s.MinTTL), s.MaxTTL)
}

// build turns a cached entry into the response for one particular query.
func (r *Resolver) build(e *entry, req []byte, q *m.Query, now time.Time, stale, udp bool, s *Settings) []byte {
	out := make([]byte, len(e.msg), len(e.msg)+11)
	copy(out, e.msg)

	// The client's ID and its exact question bytes (keeps 0x20 case mixing).
	binary.BigEndian.PutUint16(out, q.ID)
	if e.qEnd == q.QEnd {
		copy(out[m.HeaderLen:e.qEnd], req[m.HeaderLen:q.QEnd])
	}

	flags := m.U16(out, 2)
	upAD := flags & m.FlagAD
	flags &^= m.FlagAA | m.FlagRD | m.FlagCD | m.FlagAD
	flags |= m.FlagRA | q.Flags&(m.FlagRD|m.FlagCD)
	if q.DO || q.Flags&m.FlagAD != 0 {
		flags |= upAD // RFC 6840 5.8: AD only for clients that asked
	}
	binary.BigEndian.PutUint16(out[2:], flags)

	var age uint32
	if d := now.Sub(e.stored); d > 0 {
		age = uint32(d / time.Second)
	}
	for i, off := range e.ttlOffs {
		var t uint32
		if stale {
			t = StaleTTL
		} else {
			t = e.ttls[i]
			if e.cacheable {
				if !e.negative {
					t = max(t, s.MinTTL)
				}
				t = min(t, e.ttl)
			}
			if t > age {
				t -= age
			} else {
				t = 0
			}
		}
		binary.BigEndian.PutUint32(out[off:], t)
	}

	ar := m.U16(out, 10)
	switch {
	case e.optStart >= 0 && !q.EDNS:
		if e.optLast {
			out = out[:e.optStart]
			ar--
		}
	case e.optStart >= 0 && q.EDNS:
		binary.BigEndian.PutUint16(out[e.optStart+3:], uint16(s.UDPMaxSize))
		if q.DO {
			out[e.optStart+7] |= 0x80
		} else {
			out[e.optStart+7] &^= 0x80
		}
	case e.optStart < 0 && q.EDNS:
		out = m.AppendOPT(out, uint16(s.UDPMaxSize), q.DO)
		ar++
	}
	binary.BigEndian.PutUint16(out[10:], ar)
	return r.fit(out, req, q, udp, s)
}

// fit truncates a UDP response that exceeds the client's limit.
func (r *Resolver) fit(out, req []byte, q *m.Query, udp bool, s *Settings) []byte {
	if !udp {
		return out
	}
	limit := 512
	if q.EDNS {
		limit = min(max(int(q.UDPSize), 512), s.UDPMaxSize)
	}
	if len(out) <= limit {
		return out
	}
	r.stats.Truncated.Add(1)
	return m.Truncated(req, q, m.Rcode(out))
}

// Janitor removes expired entries once a minute until ctx is done.
func (r *Resolver) Janitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.cache.sweep(r.now(), r.set.Load().ServeStale)
		}
	}
}

// ---- per-domain upstream concurrency ----

// zoneLimiter caps concurrent upstream queries per parent domain, so a flood
// of random subdomains of one domain cannot occupy every upstream slot.
type zoneLimiter struct {
	mu sync.Mutex
	n  map[string]int
}

func (z *zoneLimiter) acquire(zone string, limit int) bool {
	if limit <= 0 {
		return true
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.n == nil {
		z.n = map[string]int{}
	}
	if z.n[zone] >= limit {
		return false
	}
	z.n[zone]++
	return true
}

func (z *zoneLimiter) release(zone string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.n[zone] <= 1 {
		delete(z.n, zone)
	} else {
		z.n[zone]--
	}
}

// zoneOf approximates the registered domain of a wire-format name: the last
// two labels, or three when the second-level label looks like a public
// suffix such as co.uk or com.au, or four under arpa. It only groups queries for the limiter, so
// an occasional wrong guess just means a slightly wider or narrower group.
func zoneOf(name string) string {
	var starts []int
	for i := 0; i < len(name); i += 1 + int(name[i]) {
		starts = append(starts, i)
	}
	n := len(starts)
	if n <= 2 {
		return name
	}
	keep := 2
	tld := name[starts[n-1]+1:]
	sld := name[starts[n-2]+1 : starts[n-1]]
	switch {
	case tld == "arpa":
		keep = 4 // reverse lookups: group by /16 (IPv4) or 8 nibbles (IPv6)
	case len(tld) == 2 && len(sld) <= 3:
		keep = 3
	}
	if keep >= n {
		return name
	}
	return name[starts[n-keep]:]
}
