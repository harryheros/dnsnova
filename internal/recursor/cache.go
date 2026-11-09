package recursor

import (
	"context"
	"hash/maphash"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"
)

// ttlMap is a bounded map whose entries expire. When a shard is full a few
// random entries are sampled and the one expiring first is evicted.
type ttlMap[V any] struct {
	seed   maphash.Seed
	shards [64]ttlShard[V]
}

type ttlShard[V any] struct {
	mu  sync.Mutex
	m   map[string]ttlItem[V]
	max int
}

type ttlItem[V any] struct {
	v      V
	expire time.Time
}

func newTTLMap[V any](limit int) *ttlMap[V] {
	t := &ttlMap[V]{seed: maphash.MakeSeed()}
	for i := range t.shards {
		t.shards[i].m = map[string]ttlItem[V]{}
		t.shards[i].max = max(limit/len(t.shards), 16)
	}
	return t
}

func (t *ttlMap[V]) shard(k string) *ttlShard[V] {
	return &t.shards[maphash.String(t.seed, k)%uint64(len(t.shards))]
}

// get returns the value and its expiry, also when expired (callers decide).
func (t *ttlMap[V]) get(k string) (V, time.Time, bool) {
	s := t.shard(k)
	s.mu.Lock()
	it, ok := s.m[k]
	s.mu.Unlock()
	return it.v, it.expire, ok
}

func (t *ttlMap[V]) set(k string, v V, expire time.Time) {
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[k]; !ok && len(s.m) >= s.max {
		var victim string
		var first time.Time
		n := 0
		for key, it := range s.m { // map iteration order is random
			if n == 0 || it.expire.Before(first) {
				victim, first = key, it.expire
			}
			if n++; n >= 8 {
				break
			}
		}
		delete(s.m, victim)
	}
	s.m[k] = ttlItem[V]{v, expire}
}

func (t *ttlMap[V]) del(k string) {
	s := t.shard(k)
	s.mu.Lock()
	delete(s.m, k)
	s.mu.Unlock()
}

func (t *ttlMap[V]) len() int {
	n := 0
	for i := range t.shards {
		t.shards[i].mu.Lock()
		n += len(t.shards[i].m)
		t.shards[i].mu.Unlock()
	}
	return n
}

// sweep removes entries that expired more than grace ago.
func (t *ttlMap[V]) sweep(now time.Time, grace time.Duration) {
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, it := range s.m {
			if now.Sub(it.expire) > grace {
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}

func (t *ttlMap[V]) clear() {
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		s.m = map[string]ttlItem[V]{}
		s.mu.Unlock()
	}
}

func tkey(name string, t uint16) string { return name + string([]byte{0, byte(t >> 8), byte(t)}) }

// ---- what the caches hold ----

type security uint8

const (
	secUnchecked security = iota // not validated yet (or validation off)
	secSecure
	secInsecure
	secBogus
)

func (s security) String() string {
	return [...]string{"unchecked", "secure", "insecure", "bogus"}[s]
}

// cachedSet is an RRset learnt from an authoritative answer.
type cachedSet struct {
	set   *rrset
	zone  string // the zone of the server it came from
	sec   security
	ede   uint16
	why   string
	orig  uint32   // TTL when stored
	proof []*rrset // NSEC/NSEC3 from the same answer (wildcard expansions)
	synth bool     // a CNAME made from a DNAME, never signed
}

// negEntry is a cached NXDOMAIN or NODATA with what proves it.
type negEntry struct {
	rcode int
	soa   *rrset
	proof []*rrset // NSEC, NSEC3 and their signatures
	zone  string
	sec   security
	ede   uint16
	why   string
	orig  uint32
	cut   bool // a proven DS NODATA at a delegation: an unsigned child zone
}

// keyEntry is what is known about a zone's keys.
type keyEntry struct {
	sec  security // secure: keys are validated; insecure: no DS (or unusable); bogus
	keys []*dnskey
	ede  uint16
	why  string
}

// delegation is a zone and its name servers.
type delegation struct {
	zone string
	ns   []nsHost
}

type nsHost struct {
	name  string
	addrs []netip.Addr
}

// ---- servers ----

type server struct {
	srtt     time.Duration // smoothed round-trip time; 0 = unknown
	fails    int           // consecutive timeouts
	until    time.Time     // do not use before this (after failures)
	noEDNS   time.Time     // answers only without EDNS until then
	lame     map[string]time.Time
	lastUsed time.Time
}

type infra struct {
	mu sync.Mutex
	m  map[netip.Addr]*server
}

func newInfra() *infra { return &infra{m: map[netip.Addr]*server{}} }

const unknownRTT = 250 * time.Millisecond

func (in *infra) get(a netip.Addr) *server {
	s := in.m[a]
	if s == nil {
		if len(in.m) > 100000 { // forget idle servers
			for k, v := range in.m {
				if time.Since(v.lastUsed) > time.Hour {
					delete(in.m, k)
				}
			}
		}
		s = &server{}
		in.m[a] = s
	}
	return s
}

// infraForget is how long what was learnt about a server's speed and
// failures counts: a server that timed out once is slow on paper and would
// never be chosen again, so it would never get the chance to show it has
// recovered. After this long it is treated as unknown and tried afresh.
const infraForget = 15 * time.Minute

func (s *server) forgetOld(now time.Time) {
	if !s.lastUsed.IsZero() && now.Sub(s.lastUsed) > infraForget && now.After(s.until) {
		s.srtt, s.fails = 0, 0
	}
}

// score orders candidate servers: lower is better.
func (in *infra) score(a netip.Addr, zone string, now time.Time) time.Duration {
	in.mu.Lock()
	defer in.mu.Unlock()
	s := in.get(a)
	s.forgetOld(now)
	d := s.srtt
	if d == 0 {
		d = unknownRTT + time.Duration(rand.IntN(50))*time.Millisecond
	}
	if now.Before(s.until) {
		d += 10 * time.Second
	}
	if t, ok := s.lame[zone]; ok && now.Before(t) {
		d += time.Minute
	}
	return d
}

func (in *infra) timeout(a netip.Addr) time.Duration {
	in.mu.Lock()
	defer in.mu.Unlock()
	s := in.get(a)
	if s.srtt == 0 {
		return 800 * time.Millisecond
	}
	return min(max(3*s.srtt, 150*time.Millisecond), 2*time.Second)
}

func (in *infra) ok(a netip.Addr, rtt time.Duration, now time.Time) {
	in.mu.Lock()
	defer in.mu.Unlock()
	s := in.get(a)
	if s.srtt == 0 || s.fails > 0 {
		s.srtt = rtt
	} else {
		s.srtt = (7*s.srtt + rtt) / 8
	}
	s.fails, s.until, s.lastUsed = 0, time.Time{}, now
}

func (in *infra) fail(a netip.Addr, now time.Time) {
	in.mu.Lock()
	defer in.mu.Unlock()
	s := in.get(a)
	s.fails++
	s.srtt = min(max(s.srtt*2, time.Second), 5*time.Second)
	if s.fails >= 3 {
		s.until = now.Add(time.Duration(min(s.fails, 10)) * 10 * time.Second)
	}
	s.lastUsed = now
}

func (in *infra) setLame(a netip.Addr, zone string, now time.Time) {
	in.mu.Lock()
	defer in.mu.Unlock()
	s := in.get(a)
	if s.lame == nil {
		s.lame = map[string]time.Time{}
	}
	if len(s.lame) > 64 {
		clear(s.lame)
	}
	s.lame[zone] = now.Add(10 * time.Minute)
}

func (in *infra) setNoEDNS(a netip.Addr, now time.Time) {
	in.mu.Lock()
	in.get(a).noEDNS = now.Add(time.Hour)
	in.mu.Unlock()
}

func (in *infra) useEDNS(a netip.Addr, now time.Time) bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return !now.Before(in.get(a).noEDNS)
}

func (in *infra) size() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return len(in.m)
}

// ---- coalescing ----

// flights shares one lookup between concurrent callers. Waiters give up
// when their context ends, so lookups that wait on each other cannot hang.
type flights struct {
	mu sync.Mutex
	m  map[string]*flight
}

type flight struct {
	done chan struct{}
	v    any
	err  error
}

func (f *flights) do(ctx context.Context, key string, fn func() (any, error)) (any, error) {
	f.mu.Lock()
	if f.m == nil {
		f.m = map[string]*flight{}
	}
	if c, ok := f.m[key]; ok {
		f.mu.Unlock()
		select {
		case <-c.done:
			return c.v, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &flight{done: make(chan struct{})}
	f.m[key] = c
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.m, key)
		f.mu.Unlock()
		close(c.done)
	}()
	c.v, c.err = fn()
	return c.v, c.err
}
