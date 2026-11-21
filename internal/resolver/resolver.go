// Package resolver answers queries from local zones, the cache or the
// upstream group, and prepares each answer for the client that asked.
package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harryheros/dnsnova/internal/cookie"
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
	// ECS is an EDNS Client Subnet option (dnsmsg.ClientSubnet) added to
	// every upstream query: one fixed network, the same for all clients,
	// so the cache holds one view. Changing it clears the cache.
	ECS []byte
	// Rebinding refuses public names that point into private networks;
	// nil: off.
	Rebinding *Rebinding
	// Forward sends names under some domains to servers of their own
	// (local.forward), never to the upstreams. Nil: none.
	Forward *Forwards
	// ServerID names this server to clients that ask which one answered:
	// NSID (RFC 5001) and CH TXT id.server, for telling the nodes behind
	// one anycast address apart. Empty: not said.
	ServerID string
	// Groups sorts clients into groups with their own filtering. Nil: none.
	Groups *Groups
}

var (
	errUpstreamBusy = errors.New("too many upstream queries in flight")
	errZoneBusy     = errors.New("too many upstream queries for one domain")
)

// Resolver is safe for concurrent use.
type Resolver struct {
	set     atomic.Pointer[Settings]
	filter  atomic.Pointer[filter.Set]
	cookies atomic.Pointer[cookie.Jar]
	ups     atomic.Pointer[upHolder]
	sem     atomic.Pointer[chan struct{}]
	cache   *cache
	// netMu orders a change of the client subnet against lookups: each
	// lookup holds it for reading from start to cache write, and a change
	// waits for them, so an answer for the old network cannot reach the
	// cache after it has been cleared.
	netMu sync.RWMutex
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
	if old != nil && (!bytes.Equal(old.ECS, s.ECS) || old.Forward.spec() != s.Forward.spec()) {
		r.netMu.Lock() // waits for lookups under the old network
		r.set.Store(&s)
		r.cache.clear() // answers for another network, or from other servers
		r.netMu.Unlock()
	} else {
		r.set.Store(&s)
	}
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

// SetCookies turns DNS Cookies (RFC 7873) on with jar, or off (nil): a
// query's COOKIE option is then ignored, as by a server without them.
func (r *Resolver) SetCookies(jar *cookie.Jar) { r.cookies.Store(jar) }

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
	// Client is the address the query came from, for its DNS Cookie.
	Client netip.Addr
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
	// Cookie is what the query's DNS Cookie showed (cookie.None when
	// cookies are off). Good: the client is not spoofed.
	Cookie cookie.State
	// CookieOpt is the COOKIE option sent with Resp, for a response made
	// again later (a truncated one, BADCOOKIE).
	CookieOpt []byte
	// Group is the client's group (clients.groups), or "".
	Group string
	// BlockedByGroup: blocked by a rule of the client's group, not by the
	// block lists.
	BlockedByGroup bool
	// Rebinding: an answer refused because it pointed into a private
	// network (DNS rebinding protection)
	Rebinding bool
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
	g := s.Groups.find(o.Client)
	f := finisher{r: r, req: req, q: q, o: o, s: s, g: g, filt: g.filtering(o.Filter)}
	if rc != 0 {
		return f.done(Result{Resp: m.ErrorResponse(req, q, rc), Q: q, Source: stats.SourceLocal, Status: strings.ToLower(m.RcodeString(rc))}, nil), true
	}
	if s.ServerID != "" && q.Class == classCH && q.Type == typeTXT && (q.Name == wireIDServer || q.Name == wireHostnameBind) {
		return f.done(Result{Resp: m.Answer(req, q, 0, txt(s.ServerID)), Q: q, Source: stats.SourceLocal, Status: "local"}, nil), true
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
	// A forwarded domain is the administrator's own: its servers answer,
	// also for private reverse zones otherwise answered here.
	forwarded := s.Forward.match(q.Name) != nil
	if resp := localAnswer(req, q, s); resp != nil && !forwarded {
		return f.done(Result{Resp: resp, Q: q, Source: stats.SourceLocal, Status: "local"}, nil), true
	}
	if q.Flags&m.FlagRD == 0 {
		// A resolver's clients ask for recursion. Without it the only
		// thing to learn here is what others have looked up (the cache),
		// so nothing is answered from it and nobody is asked.
		return f.done(Result{Resp: m.ErrorResponse(req, q, m.RcodeRefused), Q: q, Source: stats.SourceLocal, Status: "refused"},
			m.EDE(m.EDENotAuth, "recursion not requested")), true
	}
	if blocked, byGroup := f.nameBlocked(q.Name); blocked {
		return f.blocked(byGroup), true
	}

	key := q.CacheKey()
	now := r.now()
	e := r.cache.get(key)
	if e != nil {
		e.touch()
	}
	if e != nil && now.Before(e.expire) {
		if s.Prefetch && e.ttl >= 10 && e.expire.Sub(now) < time.Duration(e.ttl)*time.Second/10 {
			r.refreshAsync(key, q, e, now)
		}
		if blocked, byGroup := f.cnameBlocked(e); blocked {
			return f.blocked(byGroup), true
		}
		if f.rebound(e) {
			return f.rebinding(), true
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
		if blocked, byGroup := f.cnameBlocked(e); blocked {
			return f.blocked(byGroup), true
		}
		if f.rebound(e) {
			return f.rebinding(), true
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
	if blocked, byGroup := f.cnameBlocked(fresh); blocked {
		return f.blocked(byGroup), true
	}
	if f.rebound(fresh) {
		return f.rebinding(), true
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
	r    *Resolver
	req  []byte
	q    *m.Query
	o    Opts
	s    *Settings
	g    *Group // the client's group, or nil
	filt bool   // the block lists apply
}

// nameBlocked reports whether name is blocked for this client, and whether
// by its group's own rules rather than the block lists (when they apply).
// A group's allow rule wins over both.
func (f finisher) nameBlocked(name string) (blocked, byGroup bool) {
	if gr := f.g.rules(); gr != nil {
		if gr.Allowed(name) {
			return false, false
		}
		if gr.Blocked(name) {
			return true, true
		}
	}
	return f.filt && f.r.filter.Load().Blocked(name), false
}

// blocked answers a name the filtered service blocks: NXDOMAIN with an SOA
// so clients remember it briefly, and an Extended DNS Error so people and
// programs can tell it was blocked.
func (f finisher) blocked(byGroup bool) Result {
	res := Result{Resp: m.NegativeSOA(f.req, f.q, f.q.Name, BlockedTTL, m.RcodeNXDomain), Q: f.q, Source: stats.SourceBlocked, Status: "blocked"}
	why := "blocked by this server's filter"
	if byGroup {
		res.BlockedByGroup = true
		why = "blocked by a rule of this client's group"
	}
	return f.done(res, m.EDE(m.EDEBlocked, why))
}

// cnameBlocked reports whether the filtered service must block an answer
// because its CNAME chain leads to a blocked name: trackers disguised as a
// site's own subdomain ("CNAME cloaking"). A name the operator allowed
// explicitly is never blocked this way.
func (f finisher) cnameBlocked(e *entry) (blocked, byGroup bool) {
	gr := f.g.rules()
	if (!f.filt && gr == nil) || (len(e.cnames) == 0 && !e.cnamesCut) {
		return false, false
	}
	if gr != nil && gr.Allowed(f.q.Name) {
		return false, false
	}
	set := f.r.filter.Load()
	if !f.filt {
		set = nil
	}
	if set != nil && set.Allowed(f.q.Name) {
		set = nil // the lists exempt the name; the group's rules still apply
	}
	if set == nil && gr == nil {
		return false, false
	}
	if e.cnamesCut {
		return true, set == nil // too long to check every name: fail closed
	}
	for _, c := range e.cnames {
		if gr != nil && gr.Blocked(c) {
			return true, true
		}
		if set != nil && set.Blocked(c) {
			return true, false
		}
	}
	return false, false
}

// done adds Extended DNS Errors (for clients that use EDNS), keeps UDP
// answers within the client's size limit, pads encrypted answers for
// clients that pad, and counts the result.
func (f finisher) done(res Result, ede []byte) Result {
	res.Filtered, res.Group = f.filt, f.g.name()
	if f.q != nil && f.q.EDNS && f.q.Cookie != nil {
		if jar := f.r.cookies.Load(); jar != nil {
			res.Cookie = cookie.Check(f.q.Cookie)
			if res.Cookie == cookie.Bad && jar.Verify(f.q.Cookie, f.o.Client) {
				res.Cookie = cookie.Good
			}
			f.r.stats.Cookies[res.Cookie-cookie.ClientOnly].Add(1)
			res.CookieOpt = jar.Answer(f.q.Cookie, f.o.Client)
		}
	}
	if res.Resp != nil && f.q != nil && f.q.EDNS {
		opts := append(slices.Clip(ede), res.CookieOpt...)
		if f.q.NSID && f.s.ServerID != "" {
			opts = append(opts, m.NSID(f.s.ServerID)...)
		}
		res.Resp = m.AddOptions(res.Resp, opts)
	}
	if res.Resp != nil && f.q != nil {
		full := res.Resp
		res.Resp = f.r.fit(res.Resp, f.req, f.q, f.o.UDP, f.s)
		if len(res.Resp) != len(full) { // truncated: the cookie still goes along
			res.Resp = m.AddOptions(res.Resp, res.CookieOpt)
		}
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
	r.netMu.RLock()
	defer r.netMu.RUnlock()
	s := r.set.Load() // one snapshot for the whole lookup
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
	x, ecs := r.ups.Load().x, s.ECS
	fwd := s.Forward.match(q.Name)
	if fwd != nil {
		x, ecs = fwd, nil // a private server: no client subnet
	}
	resp, err := x.Exchange(ctx, m.BuildUpstreamQuery(q, ecs))
	if err == nil && fwd != nil && len(resp) >= m.HeaderLen {
		// Not validated here, and a router's AD bit says nothing: no AD.
		binary.BigEndian.PutUint16(resp[2:], m.U16(resp, 2)&^m.FlagAD)
	}
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
		if e.signed && !e.negative && !e.failure {
			e.ttl = clampSigned(e.ttl, s)
		} else {
			e.ttl = clampTTL(e.ttl, e.negative, e.failure, s)
		}
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

// clampSigned: answers with DNSSEC signatures keep their own TTLs (up to
// max_ttl); min_ttl does not stretch them.
func clampSigned(t uint32, s *Settings) uint32 {
	return min(t, s.MaxTTL)
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
	if (q.DO || q.Flags&m.FlagAD != 0) && q.Flags&m.FlagCD == 0 && !stale {
		// RFC 6840 5.8: AD only for clients that asked. Not with CD (the
		// client checks for itself), and not on a stale answer, whose
		// signatures may have expired since it was validated.
		flags |= upAD
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
				if !e.negative && !e.signed {
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
		out = m.AppendOPT(out, uint16(s.UDPMaxSize), q.DO, nil)
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
