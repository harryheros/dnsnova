// Package resolver answers queries from local zones, the cache or the
// upstream group, and prepares each answer for the client that asked.
package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/filter"
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
	set    atomic.Pointer[Settings]
	filter atomic.Pointer[filter.Set]
	ups    atomic.Pointer[upHolder]
	sem    atomic.Pointer[chan struct{}]
	cache  *cache
	sf     flightGroup
	zones  zoneLimiter
	stats  *stats.Stats
	now    func() time.Time
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

// SetFilter replaces the block rules of the filtered service (nil: none).
func (r *Resolver) SetFilter(f *filter.Set) { r.filter.Store(f) }

// SetUpstreams replaces the upstream group.
func (r *Resolver) SetUpstreams(x Exchanger) { r.ups.Store(&upHolder{x}) }

// ClearCache drops every cached answer.
func (r *Resolver) ClearCache() { r.cache.clear() }

// CacheCounts returns the number of positive and negative cache entries.
func (r *Resolver) CacheCounts() (positive, negative int) { return r.cache.counts() }

// Opts describe how a query arrived.
type Opts struct {
	UDP       bool // apply the client's UDP size limit
	Encrypted bool // DoT, DoH or DoQ: pad responses for clients that pad (RFC 8467)
	Filter    bool // the query came in through the filtered service
}

// BlockedTTL is how long clients may remember that a name is blocked: short,
// so an allow rule takes effect soon.
const BlockedTTL = 60

// Result is the outcome of Resolve.
type Result struct {
	Resp   []byte   // nil: drop the packet
	Q      *m.Query // nil if the packet could not be parsed
	Source int      // stats.Source*
	Status string   // for logs: hit, stale, miss, local, refused, ...
	// Filtered: answered by the filtered service (whether or not blocked).
	Filtered bool
}

// Resolve answers one raw query. udp applies the client's UDP size limit.
func (r *Resolver) Resolve(req []byte, udp bool) Result {
	return r.ResolveOpts(req, Opts{UDP: udp})
}

// ResolveOpts answers one raw query that arrived as o describes.
func (r *Resolver) ResolveOpts(req []byte, o Opts) Result {
	res, _ := r.resolve(req, o, true)
	return res
}

// ResolveCached answers a query only if no upstream needs to be asked:
// from the cache, a local name or an error. It reports false when the query
// needs an upstream; nothing has been counted then, and the caller should
// call ResolveOpts (typically on another goroutine). A busy UDP listener
// answers most queries this way without starting a goroutine for each.
func (r *Resolver) ResolveCached(req []byte, o Opts) (Result, bool) {
	return r.resolve(req, o, false)
}

func (r *Resolver) resolve(req []byte, o Opts, mayFetch bool) (Result, bool) {
	start := r.now()
	s := r.set.Load()
	q, rc, err := m.ParseQuery(req)
	if err != nil {
		r.stats.Rejected[stats.RejectMalformed].Add(1)
		return Result{Status: "malformed"}, true
	}
	f := finisher{r: r, req: req, q: q, o: o, s: s}
	if rc != 0 {
		return f.done(Result{Resp: m.ErrorResponse(req, q, rc), Q: q, Source: stats.SourceLocal, Status: strings.ToLower(m.RcodeString(rc))}, nil), true
	}
	switch {
	case q.Class != m.ClassIN, q.Type == m.TypeAXFR, q.Type == m.TypeIXFR:
		return f.done(Result{Resp: m.ErrorResponse(req, q, m.RcodeRefused), Q: q, Source: stats.SourceLocal, Status: "refused"},
			m.EDE(m.EDENotSupported, "zone transfers and non-IN classes are not served")), true
	case q.Type == m.TypeANY && s.BlockANY:
		return f.done(Result{Resp: m.ErrorResponse(req, q, m.RcodeNotImp), Q: q, Source: stats.SourceLocal, Status: "notimp"},
			m.EDE(m.EDENotSupported, "ANY queries are not answered (RFC 8482)")), true
	}
	if s.CheckZone != "" && isProbe(q.Name, s.CheckZone) {
		return f.done(Result{Resp: m.NegativeSOA(req, q, s.CheckZone, 0, m.RcodeNXDomain), Q: q, Source: stats.SourceLocal, Status: "probe"}, nil), true
	}
	if s.Local != nil {
		if resp := s.Local.answer(req, q); resp != nil {
			return f.done(Result{Resp: resp, Q: q, Source: stats.SourceLocal, Status: "local"}, nil), true
		}
	}
	if resp := localAnswer(req, q, s); resp != nil {
		return f.done(Result{Resp: resp, Q: q, Source: stats.SourceLocal, Status: "local"}, nil), true
	}
	if o.Filter && r.filter.Load().Blocked(q.Name) {
		return f.blocked(), true
	}

	key := q.CacheKey()
	now := r.now()
	e := r.cache.get(key)
	if e != nil && now.Before(e.expire) {
		if s.Prefetch && e.ttl >= 10 && e.expire.Sub(now) < time.Duration(e.ttl)*time.Second/10 {
			r.refreshAsync(key, q, e, now)
		}
		if f.cnameBlocked(e) {
			return f.blocked(), true
		}
		res := Result{Resp: r.build(e, req, q, now, false, s), Q: q, Source: stats.SourceCache, Status: "hit"}
		if e.failure {
			res.Status = "servfail"
		}
		r.stats.LatencyCache.Observe(r.now().Sub(start))
		return f.done(res, e.ede), true
	}
	stale := e != nil && !e.failure && s.ServeStale > 0 && now.Before(e.expire.Add(s.ServeStale))
	if stale {
		r.refreshAsync(key, q, e, now)
		if f.cnameBlocked(e) {
			return f.blocked(), true
		}
		res := Result{Resp: r.build(e, req, q, now, true, s), Q: q, Source: stats.SourceStale, Status: "stale"}
		r.stats.LatencyCache.Observe(r.now().Sub(start))
		return f.done(res, append(slices.Clip(e.ede), m.EDE(m.EDEStaleAnswer, "")...)), true
	}

	if !mayFetch {
		return Result{}, false
	}
	fresh, err := r.sf.do(key, func() (*entry, error) { return r.fetch(q) })
	if err != nil {
		switch {
		case errors.Is(err, errUpstreamBusy):
			r.stats.Rejected[stats.RejectUpstreamBusy].Add(1)
		case errors.Is(err, errZoneBusy):
			r.stats.Rejected[stats.RejectZoneBusy].Add(1)
		}
		return f.done(Result{Resp: m.ErrorResponse(req, q, m.RcodeServFail), Q: q, Source: stats.SourceUpstream, Status: "servfail"},
			m.EDE(m.EDEOther, "server busy")), true
	}
	if f.cnameBlocked(fresh) {
		return f.blocked(), true
	}
	res := Result{Resp: r.build(fresh, req, q, r.now(), false, s), Q: q, Source: stats.SourceUpstream, Status: "miss"}
	if fresh.failure {
		res.Status = "servfail"
	}
	r.stats.LatencyUpstream.Observe(r.now().Sub(start))
	return f.done(res, fresh.ede), true
}

// finisher prepares every response the same way, whatever produced it.
type finisher struct {
	r   *Resolver
	req []byte
	q   *m.Query
	o   Opts
	s   *Settings
}

// blocked answers a name the filtered service blocks: NXDOMAIN with an SOA
// so clients remember it briefly, and an Extended DNS Error so people and
// programs can tell it was blocked.
func (f finisher) blocked() Result {
	return f.done(Result{Resp: m.NegativeSOA(f.req, f.q, f.q.Name, BlockedTTL, m.RcodeNXDomain), Q: f.q, Source: stats.SourceBlocked, Status: "blocked"},
		m.EDE(m.EDEBlocked, "blocked by this server's filter"))
}

// cnameBlocked reports whether the filtered service must block an answer
// because its CNAME chain leads to a blocked name: trackers disguised as a
// site's own subdomain ("CNAME cloaking"). A name the operator allowed
// explicitly is never blocked this way.
func (f finisher) cnameBlocked(e *entry) bool {
	if !f.o.Filter || len(e.cnames) == 0 {
		return false
	}
	set := f.r.filter.Load()
	if set == nil || set.Allowed(f.q.Name) {
		return false
	}
	for _, c := range e.cnames {
		if set.Blocked(c) {
			return true
		}
	}
	return false
}

// done adds Extended DNS Errors (for clients that use EDNS), keeps UDP
// answers within the client's size limit, pads encrypted answers for
// clients that pad, and counts the result.
func (f finisher) done(res Result, ede []byte) Result {
	res.Filtered = f.o.Filter
	if res.Resp != nil && f.q != nil && f.q.EDNS {
		res.Resp = m.AddOptions(res.Resp, ede)
	}
	if res.Resp != nil && f.q != nil {
		res.Resp = f.r.fit(res.Resp, f.req, f.q, f.o.UDP, f.s)
		if f.o.Encrypted && f.q.Padding {
			res.Resp = m.Pad(res.Resp, m.PaddingBlock)
		}
	}
	f.r.stats.Sources[res.Source].Add(1)
	f.r.stats.Rcode(m.Rcode(res.Resp))
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
	var e *entry
	resp, err := r.ups.Load().x.Exchange(ctx, m.BuildUpstreamQuery(q))
	if err == nil {
		e, err = analyze(resp, q)
	}
	if err != nil {
		// Nobody answered usefully: remember the failure briefly (RFC 9520).
		if e = failureEntry(q); e == nil {
			return nil, err
		}
	}
	e.stored = r.now()
	if e.cacheable {
		e.ttl = clampTTL(e.ttl, e.negative, e.failure, s)
		e.cacheable = e.ttl > 0
	}
	e.expire = e.stored.Add(time.Duration(e.ttl) * time.Second)
	key := q.CacheKey()
	if e.failure && s.ServeStale > 0 {
		// An answer that can still be served stale is better than SERVFAIL.
		if old := r.cache.get(key); old != nil && !old.failure && e.stored.Before(old.expire.Add(s.ServeStale)) {
			e.cacheable = false
		}
	}
	if e.cacheable {
		r.cache.set(key, e)
	}
	return e, nil
}

func clampTTL(t uint32, negative, failure bool, s *Settings) uint32 {
	if failure {
		return t // FailTTL: short by design, not subject to min_ttl
	}
	if negative {
		return min(t, s.MaxNegTTL)
	}
	return min(max(t, s.MinTTL), s.MaxTTL)
}

// build turns a cached entry into the response for one particular query.
func (r *Resolver) build(e *entry, req []byte, q *m.Query, now time.Time, stale bool, s *Settings) []byte {
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

	if q.EDNS { // the client's own OPT record; the upstream's was removed
		out = m.AppendOPT(out, uint16(s.UDPMaxSize), q.DO)
		binary.BigEndian.PutUint16(out[10:], m.U16(out, 10)+1)
	}
	return out
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
