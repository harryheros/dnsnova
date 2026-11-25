package resolver

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// entry is an upstream response prepared for fast re-serving. It is
// immutable once stored, except for nextRefresh.
type entry struct {
	msg     []byte
	qEnd    int
	ttlOffs []int    // offsets of every TTL field except OPT's
	ttls    []uint32 // their original values
	ede     []byte   // Extended DNS Error options to pass on (RFC 8914)
	// cnames are the CNAME targets in the answer (wire format, lowercase):
	// the filtered service blocks an answer that leads to a blocked name.
	cnames []string
	// cnamesCut: the chain was longer than recorded; the filtered service
	// blocks rather than let unchecked names through
	cnamesCut bool
	// private: an A or AAAA record in the answer gives an address of a
	// private network (see rebinding.go)
	private bool
	// signed: the answer carries DNSSEC signatures, whose TTLs min_ttl must
	// not stretch (a validating client would see them outlive their use)
	signed bool
	rcode  int
	tc     bool
	// failure is a cached SERVFAIL (RFC 9520): an upstream's own, or one
	// dnsnova made when no upstream could be reached. It is never served
	// stale and never replaces an answer that can still be served stale.
	failure bool

	negative  bool   // NXDOMAIN or NODATA
	ttl       uint32 // cache lifetime after clamping
	stored    time.Time
	expire    time.Time
	cacheable bool

	nextRefresh atomic.Int64 // unix nanos; throttles background refreshes

	// views: the answer for each view, when it depends on where it is
	// asked from (private locality); nil for a view whose answer is not
	// known yet. Nil: the same answer for everyone. All expire together.
	views []*entry

	// used: a client was answered from it since eviction last looked at
	// it (see cache.set)
	used atomic.Bool
}

// variant returns the answer for a client in view: e itself when it is
// the same for everyone, nil when e is nil or that view's is not known.
func (e *entry) variant(view int) *entry {
	if e == nil || e.views == nil {
		return e
	}
	if view < len(e.views) {
		return e.views[view]
	}
	return e.views[0]
}

// addVariants attaches every view's answer to e (the answer for view):
// each is checked as e was, and all expire with the first of them.
func (e *entry) addVariants(resps [][]byte, q *m.Query, view int, s *Settings) {
	if len(resps) < 2 {
		return
	}
	views := make([]*entry, len(resps))
	expire := e.expire
	for v, resp := range resps {
		if resp == nil {
			continue
		}
		ev, err := analyze(resp, q)
		if err != nil || ev.failure || !ev.cacheable {
			continue
		}
		ev.stored = e.stored
		if ev.signed && !ev.negative {
			ev.ttl = clampSigned(ev.ttl, s)
		} else {
			ev.ttl = clampTTL(ev.ttl, ev.negative, false, s)
		}
		if ev.ttl == 0 {
			continue
		}
		ev.expire = ev.stored.Add(time.Duration(ev.ttl) * time.Second)
		expire = minTime(expire, ev.expire)
		views[v] = ev
	}
	if view < len(views) {
		views[view] = e
	}
	for _, ev := range views {
		if ev != nil && ev != e {
			ev.expire = expire
			ev.ttl = min(ev.ttl, uint32(expire.Sub(e.stored)/time.Second))
		}
	}
	e.expire = expire
	e.ttl = uint32(expire.Sub(e.stored) / time.Second)
	e.cacheable = e.ttl > 0
	e.views = views
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// dropVariants removes the answers kept per view (private locality).
func (c *cache) dropVariants() {
	for i := range c.shards {
		sh := &c.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e.views != nil {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

// touch notes that a client was answered from e. Read first: most hits
// find it set already, and leave the memory shared between cores alone.
func (e *entry) touch() {
	if !e.used.Load() {
		e.used.Store(true)
	}
}

// FailTTL is how long a resolution failure (SERVFAIL) is remembered, so a
// broken domain or an unreachable upstream is not asked again for every
// client (RFC 9520 asks for at least one second).
const FailTTL = 2

// analyze validates an upstream response to q and indexes its TTLs. The
// upstream's OPT record is removed: its options (padding, cookies, ...)
// belong to that hop. Extended DNS Errors are kept for the client, and each
// client gets its own OPT record when the answer is built.
func analyze(resp []byte, q *m.Query) (*entry, error) {
	if len(resp) < m.HeaderLen || m.U16(resp, 2)&m.FlagQR == 0 || m.U16(resp, 4) != 1 {
		return nil, m.ErrMalformed
	}
	resp, ede, err := m.StripOPT(resp)
	if err != nil {
		return nil, err
	}
	name, off, err := m.ReadQName(resp, m.HeaderLen)
	if err != nil || off+4 > len(resp) || name != q.Name ||
		m.U16(resp, off) != q.Type || m.U16(resp, off+2) != q.Class {
		return nil, m.ErrMalformed
	}
	off += 4
	e := &entry{msg: resp, qEnd: off, ede: ede}
	flags := m.U16(resp, 2)
	e.rcode = int(flags & 0xF)
	// Validated by the resolver or the upstream: keeps its own TTLs like an
	// answer with signatures, which a client without DO does not receive.
	e.signed = flags&m.FlagAD != 0
	e.tc = flags&m.FlagTC != 0

	an, ns, ar := int(m.U16(resp, 6)), int(m.U16(resp, 8)), int(m.U16(resp, 10))
	var minAns, negTTL uint32
	hasAns, hasSOA := false, false
	collect := func(rr m.RR) uint32 {
		t := m.U32(resp, rr.TTLOff)
		if t > 1<<31-1 {
			t = 0 // RFC 2181 section 8
		}
		e.ttlOffs = append(e.ttlOffs, rr.TTLOff)
		e.ttls = append(e.ttls, t)
		return t
	}
	if off, err = m.WalkRRs(resp, off, an, func(rr m.RR) error {
		if rr.Type == m.TypeOPT {
			return m.ErrMalformed
		}
		t := collect(rr)
		if rr.Type == m.TypeCNAME {
			if len(e.cnames) >= maxCNAMEs {
				e.cnamesCut = true
			} else if target, _, err := m.ReadName(resp, rr.RDOff); err == nil {
				e.cnames = append(e.cnames, target)
			}
		}
		if rr.Type == typeRRSIG {
			e.signed = true
		}
		if !e.private && privateRR(resp, rr) {
			e.private = true
		}
		if !hasAns || t < minAns {
			minAns, hasAns = t, true
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if off, err = m.WalkRRs(resp, off, ns, func(rr m.RR) error {
		if rr.Type == m.TypeOPT {
			return m.ErrMalformed
		}
		t := collect(rr)
		if rr.Type == m.TypeSOA && !hasSOA && rr.RDLen >= 22 {
			negTTL, hasSOA = min(t, m.U32(resp, rr.RDOff+rr.RDLen-4)), true
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if _, err = m.WalkRRs(resp, off, ar, func(rr m.RR) error {
		collect(rr)
		return nil
	}); err != nil {
		return nil, err
	}

	switch {
	case e.tc:
		// never cache truncated responses
	case e.rcode == m.RcodeNoError && hasAns:
		e.ttl, e.cacheable = minAns, true
	case e.rcode == m.RcodeNoError || e.rcode == m.RcodeNXDomain:
		e.ttl = 30 // RFC 2308: without an SOA, cache only briefly
		if hasSOA {
			e.ttl = negTTL
		}
		e.cacheable, e.negative = true, true
	case e.rcode == m.RcodeServFail:
		e.ttl, e.cacheable, e.negative, e.failure = FailTTL, true, true, true
	}
	return e, nil
}

// failureEntry is a SERVFAIL made by dnsnova when no upstream answered,
// cached like an upstream's SERVFAIL and marked "Network Error" (RFC 8914).
func failureEntry(q *m.Query) *entry {
	up := m.BuildUpstreamQuery(q, nil)
	pq := *q
	pq.QEnd, pq.EDNS = m.HeaderLen+len(q.Name)+1+4, false
	e, err := analyze(m.ErrorResponse(up, &pq, m.RcodeServFail), q)
	if err != nil {
		return nil
	}
	e.ede = m.EDE(m.EDENetworkError, "no upstream answered")
	return e
}

// cache is a sharded map. When a shard is full, a few entries are sampled
// and one no client has used since it was last looked at is evicted (the
// one that expires first); those used get a second chance, and lose the
// mark. So popular answers stay, even with short TTLs (as a CDN's have),
// and answers asked once go first: a sampled form of CLOCK, close to the
// SIEVE policy resolvers have moved to.
type cache struct {
	shards   [256]cacheShard
	perShard atomic.Int64
	pick     func(s *cacheShard) string // the victim; tests replace it
}

type cacheShard struct {
	mu sync.RWMutex
	m  map[string]*entry
}

func newCache(size int) *cache {
	c := &cache{pick: victim}
	c.setSize(size)
	for i := range c.shards {
		c.shards[i].m = make(map[string]*entry)
	}
	return c
}

func (c *cache) setSize(size int) {
	// spread over the shards, rounding up: the cache holds at most size+255
	// entries (before, at least 16 per shard: 4,096 even for size = 100)
	per := int64(0)
	if size > 0 {
		per = int64((size + 255) / 256)
	}
	c.perShard.Store(per)
}

// maxCNAMEs CNAME targets are checked by the filtered service; real chains
// are a few long.
const maxCNAMEs = 32

const typeRRSIG = 46

func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func (c *cache) shard(key string) *cacheShard { return &c.shards[fnv32(key)&255] }

func (c *cache) get(key string) *entry {
	if c.perShard.Load() == 0 {
		return nil
	}
	s := c.shard(key)
	s.mu.RLock()
	e := s.m[key]
	s.mu.RUnlock()
	return e
}

func (c *cache) set(key string, e *entry) {
	per := int(c.perShard.Load())
	if per == 0 {
		return
	}
	s := c.shard(key)
	s.mu.Lock()
	if old, ok := s.m[key]; !ok {
		for len(s.m) >= per {
			delete(s.m, c.pick(s))
		}
	} else if old.used.Load() {
		e.used.Store(true) // a refresh keeps the mark
	}
	s.m[key] = e
	s.mu.Unlock()
}

// evictSample entries are looked at to choose one to evict.
const evictSample = 8

// victim chooses the entry of a full shard to evict (s is locked).
func victim(s *cacheShard) string {
	var unused, any string
	var uexp, aexp time.Time
	n := 0
	for k, v := range s.m {
		if v.used.Load() {
			v.used.Store(false) // a second chance, once
		} else if unused == "" || v.expire.Before(uexp) {
			unused, uexp = k, v.expire
		}
		if any == "" || v.expire.Before(aexp) {
			any, aexp = k, v.expire
		}
		if n++; n >= evictSample {
			break
		}
	}
	if unused != "" {
		return unused
	}
	return any
}

// sweep removes entries past expiry plus the stale window.
func (c *cache) sweep(now time.Time, stale time.Duration) {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, e := range s.m {
			if now.After(e.expire.Add(stale)) {
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}

func (c *cache) clear() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		s.m = make(map[string]*entry)
		s.mu.Unlock()
	}
}

// counts returns the number of positive and negative entries.
func (c *cache) counts() (positive, negative int) {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		for _, e := range s.m {
			if e.negative {
				negative++
			} else {
				positive++
			}
		}
		s.mu.RUnlock()
	}
	return
}

// flightGroup collapses concurrent fetches of one key into one upstream query.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flightCall
}

type flightCall struct {
	wg  sync.WaitGroup
	e   *entry
	err error
}

func (g *flightGroup) do(key string, fn func() (*entry, error)) (*entry, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*flightCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.e, c.err
	}
	c := &flightCall{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	// Release the key and the waiters even if fn panics: otherwise, when
	// the panic is recovered (net/http does it for DoH), every later query
	// for this key would wait forever. Waiters then get errFlightPanic; the
	// panic itself goes on up the leader's stack.
	c.err = errFlightPanic
	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		c.wg.Done()
	}()
	c.e, c.err = fn()
	return c.e, c.err
}

var errFlightPanic = errors.New("resolver: query failed unexpectedly")
