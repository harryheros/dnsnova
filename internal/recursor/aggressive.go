package recursor

import (
	"slices"
	"strings"
	"sync"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Aggressive use of DNSSEC-validated NSEC records (RFC 8198): a validated
// NSEC record says that no name exists between its owner and the next
// name, so names in that range are answered NXDOMAIN (or NODATA) from the
// cache without asking. This answers random-subdomain floods aimed at
// signed zones locally. NSEC3 is not used this way (as in Unbound).

const (
	maxNSECZones   = 10000
	maxNSECPerZone = 2000
)

type nsecIndex struct {
	mu    sync.RWMutex
	zones map[string]*nsecZone
}

type nsecZone struct {
	soa    *rrset
	soaExp time.Time
	list   []nsecItem // sorted by canonical order of owner
}

type nsecItem struct {
	key string // canonicalKey(owner)
	n   *nsec
	set *rrset
	exp time.Time
}

// canonicalKey turns a name into a string whose byte order is the
// canonical name order (RFC 4034 6.1): labels from the right, separated
// by a zero byte. ok is false for names with zero bytes in labels.
func canonicalKey(name string) (string, bool) {
	ls := labelsOf(name)
	var b strings.Builder
	for i := len(ls) - 1; i >= 0; i-- {
		l := lowerStr(ls[i])
		if strings.IndexByte(l, 0) >= 0 {
			return "", false
		}
		b.WriteString(l)
		b.WriteByte(0)
	}
	return b.String(), true
}

// add records validated NSEC sets of zone and its SOA.
func (x *nsecIndex) add(zone string, soa *rrset, sets []*rrset, ttl uint32, now time.Time) {
	if ttl == 0 {
		return
	}
	exp := now.Add(time.Duration(ttl) * time.Second)
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.zones == nil {
		x.zones = map[string]*nsecZone{}
	}
	z := x.zones[zone]
	if z == nil {
		if len(x.zones) >= maxNSECZones {
			for k, v := range x.zones { // forget one that expired, or any
				if now.After(v.soaExp) {
					delete(x.zones, k)
					break
				}
			}
			if len(x.zones) >= maxNSECZones {
				for k := range x.zones {
					delete(x.zones, k)
					break
				}
			}
		}
		z = &nsecZone{}
		x.zones[zone] = z
	}
	if soa != nil {
		z.soa, z.soaExp = soa, exp
	}
	for _, s := range sets {
		n, ok := parseNSEC(s)
		if !ok || !isSub(n.owner, zone) || !isSub(n.next, zone) {
			continue
		}
		key, ok := canonicalKey(n.owner)
		if !ok {
			continue
		}
		i, found := slices.BinarySearchFunc(z.list, key, func(it nsecItem, k string) int { return strings.Compare(it.key, k) })
		item := nsecItem{key: key, n: n, set: s, exp: exp}
		if found {
			z.list[i] = item
			continue
		}
		if len(z.list) >= maxNSECPerZone {
			z.list = slices.DeleteFunc(z.list, func(it nsecItem) bool { return now.After(it.exp) })
			if len(z.list) >= maxNSECPerZone {
				continue
			}
			i, _ = slices.BinarySearchFunc(z.list, key, func(it nsecItem, k string) int { return strings.Compare(it.key, k) })
		}
		z.list = slices.Insert(z.list, i, item)
	}
}

// before returns the NSEC with the greatest owner not after name.
func (z *nsecZone) before(name string, now time.Time) *nsecItem {
	key, ok := canonicalKey(name)
	if !ok {
		return nil
	}
	i, found := slices.BinarySearchFunc(z.list, key, func(it nsecItem, k string) int { return strings.Compare(it.key, k) })
	if !found {
		i--
	}
	if i < 0 {
		// before the first one: the last NSEC (next = apex) wraps around
		i = len(z.list) - 1
	}
	if i < 0 || now.After(z.list[i].exp) {
		return nil
	}
	return &z.list[i]
}

// synth answers qname/qtype NXDOMAIN or NODATA from cached NSEC records,
// or returns nil. The result is already validated.
func (x *nsecIndex) synth(qname string, qtype uint16, now time.Time) (*negEntry, time.Time) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	var z *nsecZone
	zone := qname
	for {
		if z = x.zones[zone]; z != nil {
			break
		}
		if zone == "" {
			return nil, time.Time{}
		}
		zone = parent(zone)
	}
	if z.soa == nil || now.After(z.soaExp) || len(z.list) == 0 {
		return nil, time.Time{}
	}
	exp := z.soaExp
	if d := z.soa.data[0]; len(d) >= 22 { // negative TTL: at most the SOA minimum
		exp = earliest(exp, now.Add(time.Duration(m.U32(d, len(d)-4))*time.Second))
	}
	it := z.before(qname, now)
	if it == nil || !nsecUsable(it.n, qname) {
		return nil, time.Time{}
	}
	ns := []*nsec{it.n}
	proof := []*rrset{it.set}
	exp = earliest(exp, it.exp)
	if it.n.owner == qname {
		if ok, cut := proveNoDataNSEC(ns, qname, qtype); ok {
			return &negEntry{rcode: m.RcodeNoError, soa: z.soa, proof: proof, zone: zone, sec: secSecure, cut: cut}, exp
		}
		return nil, time.Time{}
	}
	if !it.n.covers(qname) {
		return nil, time.Time{}
	}
	if isSub(it.n.next, qname) { // an empty non-terminal
		if qtype == typeDS {
			return nil, time.Time{}
		}
		return &negEntry{rcode: m.RcodeNoError, soa: z.soa, proof: proof, zone: zone, sec: secSecure}, exp
	}
	wild := "\x01*" + nsecClosestEncloser(it.n, qname)
	w := z.before(wild, now)
	if w == nil || w.n.owner == wild || !w.n.covers(wild) {
		return nil, time.Time{} // a wildcard may exist: ask
	}
	if w.set != it.set {
		proof = append(proof, w.set)
	}
	exp = earliest(exp, w.exp)
	return &negEntry{rcode: m.RcodeNXDomain, soa: z.soa, proof: proof, zone: zone, sec: secSecure}, exp
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// wildcard returns, for a name that NSEC records prove does not exist
// while a wildcard covers it, the wildcard and the NSEC proving the name
// itself is absent. The wildcard's RRset comes from the cache.
func (x *nsecIndex) wildcard(qname string, qtype uint16, now time.Time) (wild string, proof *rrset) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	var z *nsecZone
	for zone := qname; ; zone = parent(zone) {
		if z = x.zones[zone]; z != nil || zone == "" {
			break
		}
	}
	if z == nil || len(z.list) == 0 {
		return "", nil
	}
	it := z.before(qname, now)
	if it == nil || it.n.owner == qname || !it.n.covers(qname) || !nsecUsable(it.n, qname) || isSub(it.n.next, qname) {
		return "", nil
	}
	wild = "\x01*" + nsecClosestEncloser(it.n, qname)
	w := z.before(wild, now)
	if w == nil || w.n.owner != wild || !(w.n.has(qtype) || w.n.has(5)) {
		return "", nil
	}
	return wild, it.set
}
