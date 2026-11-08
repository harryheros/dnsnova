// Package insight keeps the admin interface's lists of popular domains,
// domains that do not exist and networks that hit the limits, and the
// optional query log. Everything is held in memory only: nothing here is
// ever written to disk, and a restart clears it.
//
// The domain lists hold no client addresses. To keep a name that only one
// person visits off the list, each entry carries a 64-bit sketch of the
// networks (IPv4 /24, IPv6 /48) that asked for it, hashed with a random key
// that is replaced every hour and never stored. A name is shown only when
// at least MinNetworks bits are set, which proves that at least that many
// different networks asked for it within one hour.
package insight

import (
	"hash/maphash"
	"math/bits"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// MinNetworks is how many different networks must ask for a domain within
// one hour before it can appear on a list.
const MinNetworks = 5

const (
	shards    = 16
	shardCap  = 4096 // live entries per shard
	keepPerHr = 200  // entries kept per finished hour
)

// Entry is one line of a list.
type Entry struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type cell struct {
	count  uint64
	sketch uint64
}

type kept struct {
	name   string
	count  uint64
	spread int // networks seen in its busiest hour (at most 64)
}

type shard struct {
	mu sync.Mutex
	m  map[string]*cell
}

// Top counts names in hourly buckets.
type Top struct {
	sketch bool // whether entries need MinNetworks networks to be shown

	live    [shards]shard
	seed    maphash.Seed // per live hour; replaced at every roll
	seedMu  sync.RWMutex
	hourMu  sync.Mutex
	hour    time.Time // start of the live hour
	past    []past    // finished hours, oldest first
	maxPast int
}

type past struct {
	t       time.Time
	entries []kept
}

// NewTop returns an empty list. With sketch set, names are shown only once
// MinNetworks networks asked for them. hours is how much history to keep.
func NewTop(sketch bool, hours int, now time.Time) *Top {
	t := &Top{sketch: sketch, seed: maphash.MakeSeed(), hour: now.Truncate(time.Hour), maxPast: hours}
	for i := range t.live {
		t.live[i].m = map[string]*cell{}
	}
	return t
}

// Add counts key once, asked by ip.
func (t *Top) Add(key string, ip netip.Addr) {
	if key == "" {
		return
	}
	t.seedMu.RLock()
	seed := t.seed
	t.seedMu.RUnlock()
	sh := &t.live[maphash.String(seed, key)%shards]
	var bit uint64
	if t.sketch {
		p := NetworkOf(ip)
		b := p.Addr().As16()
		bit = 1 << (maphash.Bytes(seed, b[:]) % 64)
	}
	sh.mu.Lock()
	c := sh.m[key]
	if c == nil {
		if len(sh.m) >= shardCap {
			prune(sh.m)
		}
		if len(sh.m) >= shardCap {
			sh.mu.Unlock()
			return
		}
		c = &cell{}
		sh.m[key] = c
	}
	c.count++
	c.sketch |= bit
	sh.mu.Unlock()
}

// prune drops the entries seen only once; under a flood of random names
// the live table stays bounded.
func prune(m map[string]*cell) {
	for k, c := range m {
		if c.count <= 1 {
			delete(m, k)
		}
	}
}

// Roll closes the live hour when now is past it. Call it about once a
// minute.
func (t *Top) Roll(now time.Time) {
	t.hourMu.Lock()
	defer t.hourMu.Unlock()
	h := now.Truncate(time.Hour)
	if !h.After(t.hour) {
		return
	}
	t.seedMu.Lock()
	t.seed = maphash.MakeSeed() // the old key is gone with the hour
	t.seedMu.Unlock()
	var all []kept
	for i := range t.live {
		sh := &t.live[i]
		sh.mu.Lock()
		for k, c := range sh.m {
			all = append(all, kept{name: k, count: c.count, spread: bits.OnesCount64(c.sketch)})
		}
		sh.m = map[string]*cell{}
		sh.mu.Unlock()
	}
	sort.Slice(all, func(i, j int) bool { return all[i].count > all[j].count })
	if len(all) > keepPerHr {
		all = all[:keepPerHr]
	}
	t.past = append(t.past, past{t: t.hour, entries: all})
	if len(t.past) > t.maxPast {
		t.past = t.past[len(t.past)-t.maxPast:]
	}
	t.hour = h
}

// SetHours changes how many finished hours are kept.
func (t *Top) SetHours(n int) {
	t.hourMu.Lock()
	defer t.hourMu.Unlock()
	t.maxPast = n
	if len(t.past) > n {
		t.past = t.past[len(t.past)-n:]
	}
}

// Reset forgets everything counted so far.
func (t *Top) Reset(now time.Time) {
	t.hourMu.Lock()
	defer t.hourMu.Unlock()
	for i := range t.live {
		sh := &t.live[i]
		sh.mu.Lock()
		sh.m = map[string]*cell{}
		sh.mu.Unlock()
	}
	t.past = nil
	t.hour = now.Truncate(time.Hour)
}

// List returns up to n entries for the hours that overlap the last span,
// busiest first, including the current hour.
func (t *Top) List(span time.Duration, now time.Time, n int) []Entry {
	type acc struct {
		count  uint64
		spread int
	}
	sum := map[string]*acc{}
	addTo := func(name string, count uint64, spread int) {
		a := sum[name]
		if a == nil {
			a = &acc{}
			sum[name] = a
		}
		a.count += count
		a.spread = max(a.spread, spread)
	}
	from := now.Add(-span)
	t.hourMu.Lock()
	for _, p := range t.past {
		if p.t.Add(time.Hour).After(from) {
			for _, e := range p.entries {
				addTo(e.name, e.count, e.spread)
			}
		}
	}
	t.hourMu.Unlock()
	for i := range t.live {
		sh := &t.live[i]
		sh.mu.Lock()
		for k, c := range sh.m {
			addTo(k, c.count, bits.OnesCount64(c.sketch))
		}
		sh.mu.Unlock()
	}
	out := make([]Entry, 0, n)
	for k, a := range sum {
		if t.sketch && a.spread < MinNetworks {
			continue
		}
		out = append(out, Entry{Name: k, Count: a.count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// NetworkOf is the network an address is counted in: /24 for IPv4, /48
// for IPv6.
func NetworkOf(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	bits := 48
	if ip.Is4() {
		bits = 24
	}
	p, _ := ip.Prefix(bits)
	return p
}

// Domain reduces a query name to the domain it belongs to, so that
// mail.google.com and www.google.com count as google.com. Reverse lookups
// are counted together, so the addresses being looked up are not listed.
func Domain(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	switch {
	case name == "":
		return "."
	case strings.HasSuffix(name, ".in-addr.arpa") || name == "in-addr.arpa":
		return "in-addr.arpa (reverse lookups)"
	case strings.HasSuffix(name, ".ip6.arpa") || name == "ip6.arpa":
		return "ip6.arpa (reverse lookups)"
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return name // a public suffix itself, such as "com"
	}
	return d
}
