package resolver

import (
	"sync"
	"sync/atomic"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// entry is an upstream response prepared for fast re-serving. It is
// immutable once stored, except for nextRefresh.
type entry struct {
	msg      []byte
	qEnd     int
	ttlOffs  []int    // offsets of every TTL field except OPT's
	ttls     []uint32 // their original values
	optStart int      // offset of the OPT record, -1 if none
	optLast  bool     // OPT is the last record
	rcode    int
	tc       bool

	negative  bool   // NXDOMAIN or NODATA
	ttl       uint32 // cache lifetime after clamping
	stored    time.Time
	expire    time.Time
	cacheable bool

	nextRefresh atomic.Int64 // unix nanos; throttles background refreshes
}

// analyze validates an upstream response to q and indexes its TTLs.
func analyze(resp []byte, q *m.Query) (*entry, error) {
	if len(resp) < m.HeaderLen || m.U16(resp, 2)&m.FlagQR == 0 || m.U16(resp, 4) != 1 {
		return nil, m.ErrMalformed
	}
	name, off, err := m.ReadQName(resp, m.HeaderLen)
	if err != nil || off+4 > len(resp) || name != q.Name ||
		m.U16(resp, off) != q.Type || m.U16(resp, off+2) != q.Class {
		return nil, m.ErrMalformed
	}
	off += 4
	e := &entry{msg: resp, qEnd: off, optStart: -1}
	flags := m.U16(resp, 2)
	e.rcode = int(flags & 0xF)
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
		if rr.Type == m.TypeOPT {
			if e.optStart >= 0 || resp[rr.Start] != 0 {
				return m.ErrMalformed
			}
			e.optStart = rr.Start
			e.optLast = rr.End == len(resp)
			return nil
		}
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
	}
	return e, nil
}

// cache is a sharded map. When a shard is full, a few random entries are
// sampled and the one that expires first is evicted.
type cache struct {
	shards   [256]cacheShard
	perShard atomic.Int64
}

type cacheShard struct {
	mu sync.RWMutex
	m  map[string]*entry
}

func newCache(size int) *cache {
	c := &cache{}
	c.setSize(size)
	for i := range c.shards {
		c.shards[i].m = make(map[string]*entry)
	}
	return c
}

func (c *cache) setSize(size int) {
	per := int64(0)
	if size > 0 {
		per = max(int64(size/256), 16)
	}
	c.perShard.Store(per)
}

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
	if _, ok := s.m[key]; !ok {
		for len(s.m) >= per {
			var victim string
			var vexp time.Time
			n := 0
			for k, v := range s.m {
				if n == 0 || v.expire.Before(vexp) {
					victim, vexp = k, v.expire
				}
				if n++; n >= 8 {
					break
				}
			}
			delete(s.m, victim)
		}
	}
	s.m[key] = e
	s.mu.Unlock()
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

	c.e, c.err = fn()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	c.wg.Done()
	return c.e, c.err
}
