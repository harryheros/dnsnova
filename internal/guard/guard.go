// Package guard decides which queries dnsnova is willing to answer: access
// lists, per-client, per-network and global rate limits, and response rate
// limiting (RRL) against reflection attacks.
package guard

import (
	"net/netip"
	"sync"
	"time"
)

// ACL is a list of allowed networks.
type ACL []netip.Prefix

// Contains reports whether ip is in the list.
func (a ACL) Contains(ip netip.Addr) bool {
	for _, p := range a {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientKey groups addresses the way they are usually allocated: one IPv4
// address, or one IPv6 /56 (a typical customer allocation).
func ClientKey(ip netip.Addr) netip.Addr { return mask(ip, 32, 56) }

// NetworkKey is a wider grouping: an IPv4 /24 or an IPv6 /48.
func NetworkKey(ip netip.Addr) netip.Addr { return mask(ip, 24, 48) }

func mask(ip netip.Addr, v4, v6 int) netip.Addr {
	ip = ip.Unmap()
	bits := v6
	if ip.Is4() {
		bits = v4
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return ip
	}
	return p.Addr()
}

// Bucket is a token bucket keyed by K, with a bounded number of keys so an
// attacker cycling through addresses cannot exhaust memory.
type Bucket[K comparable] struct {
	rate, burst float64
	maxKeys     int
	now         func() int64
	shards      [64]bucketShard[K]
	hash        func(K) uint32
}

type bucketShard[K comparable] struct {
	mu sync.Mutex
	m  map[K]*tokens
}

type tokens struct {
	n    float64
	last int64
}

// NewBucket returns a limiter allowing rate events per second with bursts up
// to burst, for at most maxKeys keys. A rate of 0 disables it (nil is
// returned, and a nil *Bucket allows everything).
func NewBucket[K comparable](rate, burst float64, maxKeys int, hash func(K) uint32) *Bucket[K] {
	if rate <= 0 {
		return nil
	}
	if burst < 1 {
		burst = max(rate, 1)
	}
	b := &Bucket[K]{rate: rate, burst: burst, maxKeys: maxKeys, hash: hash, now: func() int64 { return time.Now().UnixNano() }}
	for i := range b.shards {
		b.shards[i].m = make(map[K]*tokens)
	}
	return b
}

// Allow takes one token for k.
func (b *Bucket[K]) Allow(k K) bool {
	if b == nil {
		return true
	}
	s := &b.shards[b.hash(k)&63]
	now := b.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.m[k]
	if t == nil {
		if len(s.m) >= b.maxKeys/64+1 {
			for victim := range s.m { // map order is random: evict an arbitrary key
				delete(s.m, victim)
				break
			}
		}
		t = &tokens{n: b.burst, last: now}
		s.m[k] = t
	}
	t.n += float64(now-t.last) / 1e9 * b.rate
	if t.n > b.burst {
		t.n = b.burst
	}
	t.last = now
	if t.n < 1 {
		return false
	}
	t.n--
	return true
}

// Sweep drops keys idle long enough to have refilled completely.
func (b *Bucket[K]) Sweep() {
	if b == nil {
		return
	}
	idle := int64(b.burst/b.rate*1e9) + int64(time.Second)
	cutoff := b.now() - idle
	for i := range b.shards {
		s := &b.shards[i]
		s.mu.Lock()
		for k, t := range s.m {
			if t.last < cutoff {
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}

// Len returns the number of tracked keys.
func (b *Bucket[K]) Len() int {
	if b == nil {
		return 0
	}
	n := 0
	for i := range b.shards {
		b.shards[i].mu.Lock()
		n += len(b.shards[i].m)
		b.shards[i].mu.Unlock()
	}
	return n
}

// Global is a single token bucket for the whole server.
type Global struct {
	mu          sync.Mutex
	rate, burst float64
	n           float64
	last        int64
}

// NewGlobal returns a global limiter; rate 0 disables it (nil).
func NewGlobal(rate float64) *Global {
	if rate <= 0 {
		return nil
	}
	return &Global{rate: rate, burst: rate, n: rate, last: time.Now().UnixNano()}
}

// Allow takes one token.
func (g *Global) Allow() bool {
	if g == nil {
		return true
	}
	now := time.Now().UnixNano()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n = min(g.burst, g.n+float64(now-g.last)/1e9*g.rate)
	g.last = now
	if g.n < 1 {
		return false
	}
	g.n--
	return true
}

func hashAddr(a netip.Addr) uint32 {
	b := a.As16()
	h := uint32(2166136261)
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

// Verdict is the outcome of a guard check.
type Verdict int

const (
	Allow Verdict = iota
	DenyACL
	DenyClient
	DenyNetwork
	DenyGlobal
)

func (v Verdict) String() string {
	return [...]string{"allow", "acl", "client_limit", "network_limit", "global_limit"}[v]
}

// Limits configures a Guard.
type Limits struct {
	Private                  bool
	Allow                    ACL
	Deny                     ACL // refused in either mode
	ClientQPS, ClientBurst   float64
	NetworkQPS, NetworkBurst float64
	GlobalQPS                float64
	RRLRate                  float64
	RRLSlip                  int
}

// Guard applies the access list and the three rate limits in order: client,
// network, then global, so one noisy client cannot use up the global budget.
type Guard struct {
	private bool
	allow   ACL
	deny    ACL
	client  *Bucket[netip.Addr]
	network *Bucket[netip.Addr]
	global  *Global
	RRL     *RRL
}

// New builds a Guard.
func New(l Limits) *Guard {
	return &Guard{
		private: l.Private,
		allow:   l.Allow,
		deny:    l.Deny,
		client:  NewBucket[netip.Addr](l.ClientQPS, l.ClientBurst, 1<<18, hashAddr),
		network: NewBucket[netip.Addr](l.NetworkQPS, l.NetworkBurst, 1<<16, hashAddr),
		global:  NewGlobal(l.GlobalQPS),
		RRL:     NewRRL(l.RRLRate, l.RRLSlip),
	}
}

// Admit checks a client before its query is processed.
func (g *Guard) Admit(ip netip.Addr) Verdict {
	ip = ip.Unmap()
	if !g.Permitted(ip) {
		return DenyACL
	}
	if !g.client.Allow(ClientKey(ip)) {
		return DenyClient
	}
	if !g.network.Allow(NetworkKey(ip)) {
		return DenyNetwork
	}
	if !g.global.Allow() {
		return DenyGlobal
	}
	return Allow
}

// Permitted reports whether ip passes the access list (used when a TCP
// connection is accepted, before any query arrives).
func (g *Guard) Permitted(ip netip.Addr) bool {
	ip = ip.Unmap()
	if len(g.deny) > 0 && g.deny.Contains(ip) {
		return false
	}
	// in private mode the machine itself may always ask: programs on it use
	// 127.0.0.1 and are not a network anyone could list
	return !g.private || (LoopbackPermitted && ip.IsLoopback()) || g.allow.Contains(ip)
}

// LoopbackPermitted lets the machine itself query in private mode. Tests
// whose clients all come from 127.0.0.1 turn it off to check the list.
var LoopbackPermitted = true

// Sweep drops idle limiter state; call it about once a minute.
func (g *Guard) Sweep() {
	g.client.Sweep()
	g.network.Sweep()
	g.RRL.Sweep()
}
