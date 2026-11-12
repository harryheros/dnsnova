package recursor

import (
	"context"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

const (
	maxCacheTTL = 86400
	maxNegTTL   = 3600
	bogusTTL    = 60 // how long a validation failure is remembered
)

// resolve answers qname/qtype from the cache or by iterating, following
// CNAME and DNAME records. With validate, every RRset and negative answer
// gets a DNSSEC status; answer.sec is the weakest of them.
func (r *Recursor) resolve(ctx context.Context, t *task, qname string, qtype uint16, validate bool) (*answer, error) {
	if t.depth >= maxDepth {
		return nil, errBudget
	}
	t.depth++
	defer func() { t.depth-- }()

	ans := &answer{rcode: m.RcodeNoError, sec: secSecure}
	if !validate {
		ans.sec = secUnchecked
	}
	name := qname
	seen := map[string]bool{}
	for hop := 0; hop <= maxCNAMEs; hop++ {
		if seen[name] {
			return &answer{rcode: m.RcodeServFail, sec: ans.sec}, nil // CNAME loop
		}
		seen[name] = true
		next, done, err := r.step(ctx, t, ans, name, qtype, validate, hop == 0)
		if err != nil {
			return nil, err
		}
		if done {
			return ans, nil
		}
		if t.trace != nil {
			t.trace.add(t, TraceStep{Kind: "cname", Name: m.NameString(name), Result: "an alias: continue with " + m.NameString(next)})
		}
		name = next
	}
	return &answer{rcode: m.RcodeServFail, sec: ans.sec}, nil // chain too long
}

// fresh reports whether a cached entry may be used. The final answer is
// fetched again in the last tenth of its life, so that the resolver's
// prefetching gets a fresh copy rather than the one about to expire.
func (r *Recursor) fresh(exp time.Time, orig uint32, final bool) bool {
	left := exp.Sub(r.now())
	if left <= 0 {
		return false
	}
	return !final || orig < 20 || left > time.Duration(orig)*time.Second/10
}

// step resolves one link of a chain. It returns the next name to follow,
// or done when the answer is complete.
func (r *Recursor) step(ctx context.Context, t *task, ans *answer, name string, qtype uint16, validate, first bool) (string, bool, error) {
	// the cache (not for a trace, nor for one network's own answer)
	if t.fresh || !t.shared() {
		goto ask
	}
	if cs, exp, ok := r.sets.get(tkey(name, qtype)); ok && r.fresh(exp, cs.orig, true) {
		r.Stats.CacheHits.Add(1)
		return "", true, r.addSet(ctx, t, ans, cs, exp, validate)
	}
	if qtype != m.TypeCNAME {
		if cs, exp, ok := r.sets.get(tkey(name, m.TypeCNAME)); ok && r.fresh(exp, cs.orig, false) {
			r.Stats.CacheHits.Add(1)
			if err := r.addSet(ctx, t, ans, cs, exp, validate); err != nil {
				return "", false, err
			}
			return lower(nameOf(cs.set.data[0])), false, nil
		}
	}
	for _, k := range []string{tkey(name, qtype), tkey(name, 0)} {
		// (a DS proof kept from a referral has no SOA: fine for validating,
		// but a client gets a complete answer)
		if ne, exp, ok := r.negs.get(k); ok && r.fresh(exp, ne.orig, true) && (ne.soa != nil || qtype == typeDS && t.depth > 1) {
			r.Stats.CacheHits.Add(1)
			return "", true, r.addNeg(ctx, t, ans, ne, exp, name, qtype, validate)
		}
	}
	if validate { // RFC 8198: proven from NSEC records already validated
		now := r.now()
		if ne, exp := r.nsecs.synth(name, qtype, now); ne != nil {
			r.Stats.Aggressive.Add(1)
			return "", true, r.addNeg(ctx, t, ans, ne, exp, name, qtype, validate)
		}
		if wild, proof := r.nsecs.wildcard(name, qtype, now); proof != nil {
			for _, typ := range []uint16{qtype, m.TypeCNAME} {
				ws, exp, ok := r.wilds.get(tkey(wild, typ))
				if !ok || !now.Before(exp) || (typ == m.TypeCNAME && qtype == m.TypeCNAME) {
					continue
				}
				set := *ws.set
				set.name = name
				cs := &cachedSet{set: &set, zone: ws.zone, sec: secSecure, orig: ws.orig, proof: []*rrset{proof}}
				r.Stats.Aggressive.Add(1)
				if err := r.addSet(ctx, t, ans, cs, exp, validate); err != nil {
					return "", false, err
				}
				if typ == m.TypeCNAME {
					return lower(nameOf(set.data[0])), false, nil
				}
				return "", true, nil
			}
		}
	}
	r.Stats.CacheMisses.Add(1)
ask:
	resp, err := r.iterate(ctx, t, name, qtype)
	if err != nil {
		return "", false, err
	}
	now := r.now()
	sets := groupRRsets(resp.msg.answer)
	auth := groupRRsets(resp.msg.authority)
	var proof []*rrset
	for _, s := range auth {
		if s.typ == typeNSEC || s.typ == typeNSEC3 {
			proof = append(proof, s)
		}
	}
	find := func(owner string, typ uint16) *rrset {
		for _, s := range sets {
			if s.name == owner && s.typ == typ {
				return s
			}
		}
		return nil
	}
	cur := name
	added := false
	for i := 0; i < maxCNAMEs; i++ {
		if s := find(cur, qtype); s != nil {
			cs := r.storeSet(s, resp.zone, proof, now, t.shared())
			return "", true, r.addSet(ctx, t, ans, cs, now.Add(time.Duration(cs.orig)*time.Second), validate)
		}
		if qtype == m.TypeANY {
			found := false
			for _, s := range sets {
				if s.name == cur {
					cs := r.storeSet(s, resp.zone, proof, now, t.shared())
					if err := r.addSet(ctx, t, ans, cs, now.Add(time.Duration(cs.orig)*time.Second), validate); err != nil {
						return "", false, err
					}
					found = true
				}
			}
			if found {
				return "", true, nil
			}
		}
		if dn := findDNAME(sets, cur); dn != nil && qtype != typeDNAME {
			cs := r.storeSet(dn, resp.zone, nil, now, t.shared())
			if err := r.addSet(ctx, t, ans, cs, now.Add(time.Duration(cs.orig)*time.Second), validate); err != nil {
				return "", false, err
			}
			target := cur[:len(cur)-len(dn.name)] + string(nameOf(dn.data[0]))
			if len(target) > 254 {
				ans.rcode = 6 // YXDOMAIN (RFC 6672 2.2)
				return "", true, nil
			}
			target = lowerStr(target)
			synth := &cachedSet{set: &rrset{name: cur, typ: m.TypeCNAME, class: m.ClassIN, ttl: dn.ttl,
				data: [][]byte{append([]byte(target), 0)}}, zone: resp.zone, synth: true, orig: dn.ttl, sec: ans.lastSec()}
			ans.chain = append(ans.chain, synth)
			ans.until = append(ans.until, now.Add(time.Duration(dn.ttl)*time.Second))
			cur, added = target, true
			continue
		}
		if s := find(cur, m.TypeCNAME); s != nil && qtype != m.TypeCNAME && len(s.data) == 1 {
			cs := r.storeSet(s, resp.zone, proof, now, t.shared())
			if err := r.addSet(ctx, t, ans, cs, now.Add(time.Duration(cs.orig)*time.Second), validate); err != nil {
				return "", false, err
			}
			cur, added = lower(nameOf(s.data[0])), true
			continue
		}
		break
	}
	if added {
		return cur, false, nil
	}
	switch resp.msg.rcode {
	case m.RcodeNXDomain, m.RcodeNoError:
		ne := &negEntry{rcode: resp.msg.rcode, proof: proof, zone: resp.zone}
		ttl := uint32(30)
		for _, s := range auth {
			if s.typ == m.TypeSOA && isSub(name, s.name) && len(s.data) == 1 && len(s.data[0]) >= 22 {
				ne.soa = s
				d := s.data[0]
				ttl = min(s.ttl, m.U32(d, len(d)-4))
				break
			}
		}
		ttl = min(ttl, maxNegTTL)
		ne.orig = ttl
		exp := now.Add(time.Duration(ttl) * time.Second)
		k := tkey(name, qtype)
		if ne.rcode == m.RcodeNXDomain {
			k = tkey(name, 0)
		}
		if ne.soa != nil && t.shared() {
			r.negs.set(k, ne, exp)
		}
		return "", true, r.addNeg(ctx, t, ans, ne, exp, name, qtype, validate)
	}
	return "", false, ErrUnreachable
}

func findDNAME(sets []*rrset, name string) *rrset {
	for _, s := range sets {
		if s.typ == typeDNAME && s.name != name && isSub(name, s.name) && len(s.data) == 1 {
			return s
		}
	}
	return nil
}

func (a *answer) lastSec() security {
	if len(a.chain) == 0 {
		return secUnchecked
	}
	return a.chain[len(a.chain)-1].sec
}

// storeSet makes the cache entry for s, and keeps it when keep is set.
func (r *Recursor) storeSet(s *rrset, zone string, proof []*rrset, now time.Time, keep bool) *cachedSet {
	ttl := min(s.ttl, maxCacheTTL)
	cs := &cachedSet{set: s, zone: zone, orig: ttl}
	if wildcardExpanded(s) {
		cs.proof = proof
	}
	if ttl > 0 && keep {
		r.sets.set(tkey(s.name, s.typ), cs, now.Add(time.Duration(ttl)*time.Second))
	}
	return cs
}

// wildcardExpanded reports whether an RRSIG says the set came from a wildcard.
func wildcardExpanded(s *rrset) bool {
	for _, raw := range s.sigs {
		if sg, ok := parseSig(raw); ok && int(sg.labels) < labelCount(s.name) {
			return true
		}
	}
	return false
}

// addSet validates cs if needed and appends it to the answer.
func (r *Recursor) addSet(ctx context.Context, t *task, ans *answer, cs *cachedSet, exp time.Time, validate bool) error {
	if validate && cs.sec == secUnchecked {
		v, err := r.validateSet(ctx, t, cs)
		if err != nil {
			return err
		}
		ttl := min(v.orig, uint32(max(exp.Sub(r.now())/time.Second, 0)))
		exp = r.now().Add(time.Duration(ttl) * time.Second)
		if v.sec == secBogus {
			exp = r.now().Add(bogusTTL * time.Second)
		}
		if ttl > 0 {
			r.sets.set(tkey(cs.set.name, cs.set.typ), v, exp)
		}
		cs = v
	}
	ans.chain = append(ans.chain, cs)
	ans.until = append(ans.until, exp)
	ans.merge(cs.sec, cs.ede, cs.why, validate)
	return nil
}

func (r *Recursor) addNeg(ctx context.Context, t *task, ans *answer, ne *negEntry, exp time.Time, name string, qtype uint16, validate bool) error {
	if validate && ne.sec == secUnchecked {
		v, err := r.validateNeg(ctx, t, ne, name, qtype)
		if err != nil {
			return err
		}
		// As in addSet: never keep the answer past its signatures (v.orig
		// is capped by the SOA's and the proof's RRSIG expiry).
		ttl := min(v.orig, uint32(max(exp.Sub(r.now())/time.Second, 0)))
		exp = r.now().Add(time.Duration(ttl) * time.Second)
		if v.sec == secBogus {
			exp = r.now().Add(bogusTTL * time.Second)
		}
		k := tkey(name, qtype)
		if ne.rcode == m.RcodeNXDomain {
			k = tkey(name, 0)
		}
		if (ne.soa != nil || qtype == typeDS) && exp.After(r.now()) {
			r.negs.set(k, v, exp)
		}
		ne = v
	}
	ans.rcode = ne.rcode
	ans.neg = ne
	ans.negUntil = exp
	ans.merge(ne.sec, ne.ede, ne.why, validate)
	return nil
}

// merge folds one status into the answer's: bogus beats insecure beats secure.
func (a *answer) merge(s security, ede uint16, why string, validate bool) {
	if !validate {
		return
	}
	switch {
	case s == secBogus:
		if a.sec != secBogus {
			a.sec, a.ede, a.why = secBogus, ede, why
		}
	case a.sec == secBogus:
	case s == secInsecure || s == secUnchecked:
		a.sec = secInsecure
		if a.ede == 0 && ede != 0 {
			a.ede, a.why = ede, why
		}
	}
}
