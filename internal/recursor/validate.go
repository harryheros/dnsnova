package recursor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Extended DNS Error codes (RFC 8914, RFC 9276).
const (
	edeUnsupportedAlg    = 1
	edeUnsupportedDigest = 2
	edeBogus             = 6
	edeSigExpired        = 7
	edeSigNotYet         = 8
	edeDNSKEYMissing     = 9
	edeRRSIGsMissing     = 10
	edeNSECMissing       = 12
	edeNSEC3Iterations   = 27
)

func sigEDE(err error) (uint16, string) {
	switch {
	case errors.Is(err, errSigExpired):
		return edeSigExpired, "signature expired"
	case errors.Is(err, errSigNotYet):
		return edeSigNotYet, "signature not yet valid"
	case errors.Is(err, errNoSig):
		return edeRRSIGsMissing, "signatures missing"
	case errors.Is(err, errNoKey):
		return edeDNSKEYMissing, "no key for the signature"
	}
	return edeBogus, "signature does not verify"
}

// signerOf returns the signer of set's first usable RRSIG: a zone at or
// above the owner, at or below the zone of the server it came from.
func signerOf(set *rrset, zone string) (string, bool) {
	for _, raw := range set.sigs {
		if s, ok := parseSig(raw); ok && s.covered == set.typ && isSub(set.name, s.signer) && isSub(s.signer, zone) {
			return s.signer, true
		}
	}
	return "", false
}

// validateSet returns a copy of cs with its DNSSEC status.
func (r *Recursor) validateSet(ctx context.Context, t *task, cs *cachedSet) (*cachedSet, error) {
	var v *cachedSet
	var err error
	if d, ok := r.underNTA(cs.set.name); ok && !cs.synth {
		c := *cs
		c.sec, c.ede, c.why = secInsecure, 0, ntaWhy(d)
		v = &c
	} else if v, err = r.checkSet(ctx, t, cs); err != nil {
		return nil, err
	}
	if t.trace != nil && !cs.synth {
		t.trace.add(t, TraceStep{Kind: "validate", Zone: zoneName(cs.zone), Name: m.NameString(cs.set.name), Type: m.TypeString(cs.set.typ),
			Result: fmt.Sprintf("%d record%s: %s", len(cs.set.data), plural(len(cs.set.data)), v.sec), Sec: v.sec.String(), Why: v.why})
	}
	return v, nil
}

func (r *Recursor) checkSet(ctx context.Context, t *task, cs *cachedSet) (*cachedSet, error) {
	v := *cs
	if cs.synth {
		return &v, nil
	}
	signer, signed := signerOf(cs.set, cs.zone)
	if !signed {
		sec, ede, why, err := r.unsignedStatus(ctx, t, cs.set.name, cs.zone)
		if err != nil {
			return nil, err
		}
		v.sec, v.ede, v.why = sec, ede, why
		return &v, nil
	}
	ke, err := r.zoneKeys(ctx, t, signer)
	if err != nil {
		return nil, err
	}
	switch ke.sec {
	case secInsecure:
		v.sec, v.ede, v.why = secInsecure, ke.ede, ke.why
		return &v, nil
	case secBogus:
		v.sec, v.ede, v.why = secBogus, ke.ede, ke.why
		return &v, nil
	}
	ttl, labels, err := verifySet(cs.set, signer, ke.keys, r.now(), &t.sigBudget)
	if err != nil {
		v.sec = secBogus
		v.ede, v.why = sigEDE(err)
		v.why = v.why + " for " + m.NameString(cs.set.name) + " " + m.TypeString(cs.set.typ)
		return &v, nil
	}
	v.orig = min(cs.orig, ttl)
	v.sec = secSecure
	if int(labels) < labelCount(cs.set.name) { // a wildcard expansion: the name itself must not exist
		p, pttl := r.checkProof(cs.proof, signer, ke, t)
		v.orig = min(v.orig, pttl) // the proof must not outlive its signatures either
		if ns := nsecs(p); len(ns) > 0 && proveWildcardNSEC(ns, cs.set.name) {
			// remembered for RFC 8198: the wildcard's RRset and the NSEC records
			wild := "\x01*" + ancestorAt(cs.set.name, int(labels))
			ws := *cs.set
			ws.name = wild
			now := r.now()
			if t.shared() {
				r.wilds.set(tkey(wild, cs.set.typ), &cachedSet{set: &ws, zone: cs.zone, sec: secSecure, orig: v.orig},
					now.Add(time.Duration(v.orig)*time.Second))
			}
			r.nsecs.add(signer, nil, p, v.orig, now)
			return &v, nil
		}
		if s, insecure := nsec3sFor(p, cs.set.name); len(s.list) > 0 {
			switch proveWildcardNSEC3(s, cs.set.name, int(labels)) {
			case proofSecure:
				return &v, nil
			case proofInsecure:
				v.sec = secInsecure
				return &v, nil
			}
		} else if insecure {
			v.sec, v.ede, v.why = secInsecure, edeNSEC3Iterations, "NSEC3 iterations above the limit"
			return &v, nil
		}
		v.sec, v.ede, v.why = secBogus, edeNSECMissing, "wildcard answer without proof"
	}
	return &v, nil
}

// checkProof returns the proof RRsets that verify with the zone's keys, and
// the shortest time any of them may still be trusted (TTL capped by the
// signatures' expiry), so a cached proof never outlives its signatures.
func (r *Recursor) checkProof(proof []*rrset, zone string, ke *keyEntry, t *task) ([]*rrset, uint32) {
	var out []*rrset
	least := uint32(math.MaxUint32)
	now := r.now()
	for _, p := range proof {
		if ttl, _, err := verifySet(p, zone, ke.keys, now, &t.sigBudget); err == nil {
			out = append(out, p)
			least = min(least, ttl)
		}
	}
	return out, least
}

// unsignedStatus decides about data without signatures from zone: fine if
// the zone is insecure, or if an insecure delegation lies between the zone
// and owner (one server can serve a parent and its unsigned child).
func (r *Recursor) unsignedStatus(ctx context.Context, t *task, owner, zone string) (security, uint16, string, error) {
	if d, ok := r.underNTA(owner); ok {
		return secInsecure, 0, ntaWhy(d), nil
	}
	ke, err := r.zoneKeys(ctx, t, zone)
	if err != nil {
		return 0, 0, "", err
	}
	if ke.sec != secSecure {
		return ke.sec, ke.ede, ke.why, nil
	}
	for n := labelCount(zone) + 1; n <= labelCount(owner); n++ {
		cut := ancestorAt(owner, n)
		ds, err := r.resolve(ctx, t, cut, typeDS, true)
		if err != nil {
			return 0, 0, "", err
		}
		if ds.sec == secInsecure || (ds.sec == secSecure && ds.neg != nil && ds.neg.cut) {
			return secInsecure, 0, "", nil
		}
		if ds.sec == secBogus {
			return secBogus, ds.ede, ds.why, nil
		}
		if ds.sec == secSecure && ds.neg == nil { // a signed child: its data must be signed
			break
		}
	}
	return secBogus, edeRRSIGsMissing, "signatures missing for " + m.NameString(owner), nil
}

// validateNeg returns a copy of ne with its DNSSEC status.
func (r *Recursor) validateNeg(ctx context.Context, t *task, ne *negEntry, qname string, qtype uint16) (*negEntry, error) {
	var v *negEntry
	var err error
	if d, ok := r.underNTA(qname); ok {
		c := *ne
		c.sec, c.ede, c.why = secInsecure, 0, ntaWhy(d)
		v = &c
	} else if v, err = r.checkNeg(ctx, t, ne, qname, qtype); err != nil {
		return nil, err
	}
	if t.trace != nil {
		what := "no records of this type"
		if ne.rcode == m.RcodeNXDomain {
			what = "the name does not exist"
		}
		t.trace.add(t, TraceStep{Kind: "validate", Zone: zoneName(ne.zone), Name: m.NameString(qname), Type: m.TypeString(qtype),
			Result: what + ": " + v.sec.String(), Sec: v.sec.String(), Why: v.why})
	}
	return v, nil
}

func (r *Recursor) checkNeg(ctx context.Context, t *task, ne *negEntry, qname string, qtype uint16) (*negEntry, error) {
	v := *ne
	signer, signed := "", false
	if ne.soa != nil {
		signer, signed = signerOf(ne.soa, ne.zone)
	}
	if !signed {
		for _, p := range ne.proof {
			if signer, signed = signerOf(p, ne.zone); signed {
				break
			}
		}
	}
	if signed && !isSub(qname, signer) {
		signed = false
	}
	if !signed {
		sec, ede, why, err := r.unsignedStatus(ctx, t, qname, ne.zone)
		if err != nil {
			return nil, err
		}
		v.sec, v.ede, v.why = sec, ede, why
		if sec == secBogus && ede == edeRRSIGsMissing {
			v.ede, v.why = edeNSECMissing, "no proof of non-existence for "+m.NameString(qname)
		}
		return &v, nil
	}
	ke, err := r.zoneKeys(ctx, t, signer)
	if err != nil {
		return nil, err
	}
	if ke.sec != secSecure {
		v.sec, v.ede, v.why = ke.sec, ke.ede, ke.why
		return &v, nil
	}
	now := r.now()
	if ne.soa != nil {
		ttl, _, err := verifySet(ne.soa, signer, ke.keys, now, &t.sigBudget)
		if err != nil {
			v.sec = secBogus
			v.ede, v.why = sigEDE(err)
			return &v, nil
		}
		v.orig = min(v.orig, ttl)
	}
	checked, pttl := r.checkProof(ne.proof, signer, ke, t)
	v.orig = min(v.orig, pttl)
	bogus := func() (*negEntry, error) {
		v.sec, v.ede, v.why = secBogus, edeNSECMissing, "no proof of non-existence for "+m.NameString(qname)
		return &v, nil
	}
	if ns := nsecs(checked); len(ns) > 0 {
		ok, cut := false, false
		if ne.rcode == m.RcodeNXDomain {
			ok = proveNXDomainNSEC(ns, qname)
		} else {
			ok, cut = proveNoDataNSEC(ns, qname, qtype)
		}
		if ok {
			v.sec, v.cut = secSecure, cut
			if ne.soa != nil { // remembered for RFC 8198
				r.nsecs.add(signer, ne.soa, checked, v.orig, now)
			}
			return &v, nil
		}
	}
	s, insecure := nsec3sFor(checked, qname)
	if len(s.list) == 0 {
		if insecure {
			v.sec, v.ede, v.why = secInsecure, edeNSEC3Iterations, "NSEC3 iterations above the limit"
			return &v, nil
		}
		return bogus()
	}
	var p proof
	if ne.rcode == m.RcodeNXDomain {
		p = proveNXDomainNSEC3(s, qname)
	} else {
		p, v.cut = proveNoDataNSEC3(s, qname, qtype)
	}
	switch p {
	case proofSecure:
		v.sec = secSecure
	case proofInsecure:
		v.sec = secInsecure
	default:
		return bogus()
	}
	return &v, nil
}

// zoneKeys returns the validated keys of zone, or that it is insecure or bogus.
func (r *Recursor) zoneKeys(ctx context.Context, t *task, zone string) (*keyEntry, error) {
	if d, ok := r.underNTA(zone); ok {
		return &keyEntry{sec: secInsecure, why: ntaWhy(d)}, nil
	}
	if ke, exp, ok := r.keys.get(zone); ok && r.now().Before(exp) && !t.fresh {
		return ke, nil
	}
	key := "k" + zone
	if t.stack[key] {
		return nil, errLoop
	}
	t.stack[key] = true
	defer delete(t.stack, key)
	var ke *keyEntry
	if t.fresh { // a trace sees its own queries, not another lookup's
		var err error
		if ke, err = r.fetchKeys(ctx, t, zone); err != nil {
			return nil, err
		}
	} else {
		v, err := r.fl.do(ctx, key, func() (any, error) { return r.fetchKeys(ctx, t, zone) })
		if err != nil {
			return nil, err
		}
		ke = v.(*keyEntry)
	}
	if t.trace != nil {
		res := fmt.Sprintf("%d key%s", len(ke.keys), plural(len(ke.keys)))
		switch ke.sec {
		case secInsecure:
			res = "not signed (no DS at the parent): answers from here are not checked"
		case secBogus:
			res = "keys cannot be trusted"
		default:
			res += " that match the parent's DS"
		}
		t.trace.add(t, TraceStep{Kind: "keys", Zone: zoneName(zone), Result: res, Sec: ke.sec.String(), Why: ke.why})
	}
	return ke, nil
}

func (r *Recursor) fetchKeys(ctx context.Context, t *task, zone string) (*keyEntry, error) {
	now := r.now()
	keep := func(ke *keyEntry, ttl uint32) (*keyEntry, error) {
		if ke.sec == secBogus {
			ttl = bogusTTL
		}
		ttl = min(max(ttl, 5), maxCacheTTL)
		r.keys.set(zone, ke, now.Add(time.Duration(ttl)*time.Second))
		return ke, nil
	}
	var ds *rrset
	dsTTL := uint32(maxCacheTTL)
	if zone == "" {
		ds = r.anchors.Load()
		if len(ds.data) == 0 {
			return keep(&keyEntry{sec: secInsecure}, 3600)
		}
	} else {
		ans, err := r.resolve(ctx, t, zone, typeDS, true)
		if err != nil {
			return nil, err
		}
		switch {
		case ans.sec == secBogus:
			return keep(&keyEntry{sec: secBogus, ede: ans.ede, why: ans.why}, bogusTTL)
		case ans.sec != secSecure:
			return keep(&keyEntry{sec: secInsecure, ede: ans.ede, why: ans.why}, negTTL(ans, now))
		case ans.neg != nil && ans.rcode == m.RcodeNoError:
			return keep(&keyEntry{sec: secInsecure}, negTTL(ans, now)) // proven: no DS, an unsigned zone
		case ans.neg != nil:
			return keep(&keyEntry{sec: secBogus, ede: edeBogus, why: "the signing zone " + m.NameString(zone) + " does not exist"}, bogusTTL)
		}
		for i, cs := range ans.chain {
			if cs.set.typ == typeDS && cs.set.name == zone {
				ds = cs.set
				dsTTL = uint32(max(ans.until[i].Sub(now)/time.Second, 0))
			}
		}
		if ds == nil {
			return keep(&keyEntry{sec: secBogus, ede: edeBogus, why: "no DS for " + m.NameString(zone)}, bogusTTL)
		}
	}

	// DS records this server can use; SHA-1 only when nothing better is there (RFC 4509 3)
	var usable [][]byte
	better := slices.ContainsFunc(ds.data, func(d []byte) bool {
		return len(d) > 4 && algSupported(d[2]) && (d[3] == digestSHA256 || d[3] == digestSHA384)
	})
	algOK, digestOK := false, false
	for _, d := range ds.data {
		if len(d) < 5 {
			continue
		}
		a, dt := algSupported(d[2]), digestSupported(d[3])
		algOK, digestOK = algOK || a, digestOK || dt
		if a && dt && !(better && d[3] == digestSHA1) {
			usable = append(usable, d)
		}
	}
	if len(usable) == 0 { // RFC 4035 5.2: treat as unsigned
		if !algOK {
			return keep(&keyEntry{sec: secInsecure, ede: edeUnsupportedAlg, why: "unsupported DNSKEY algorithm for " + m.NameString(zone)}, dsTTL)
		}
		return keep(&keyEntry{sec: secInsecure, ede: edeUnsupportedDigest, why: "unsupported DS digest type for " + m.NameString(zone)}, dsTTL)
	}

	resp, err := r.iterate(ctx, t, zone, typeDNSKEY)
	if err != nil {
		return nil, err
	}
	var keyset *rrset
	for _, s := range groupRRsets(resp.msg.answer) {
		if s.name == zone && s.typ == typeDNSKEY {
			keyset = s
		}
	}
	if keyset == nil {
		return keep(&keyEntry{sec: secBogus, ede: edeDNSKEYMissing, why: "no DNSKEY for " + m.NameString(zone)}, bogusTTL)
	}
	var keys, sep []*dnskey
	for _, d := range keyset.data {
		k, ok := parseKey(d)
		if !ok || k.flags&keyFlagZone == 0 || k.flags&keyFlagRevoke != 0 {
			continue
		}
		if len(keys) < maxKeysPerSet {
			keys = append(keys, k)
		}
		for _, d := range usable {
			if dsMatches(zone, d, k) && !slices.Contains(sep, k) {
				sep = append(sep, k)
			}
		}
	}
	if len(sep) == 0 {
		return keep(&keyEntry{sec: secBogus, ede: edeDNSKEYMissing, why: "no DNSKEY matches the DS for " + m.NameString(zone)}, bogusTTL)
	}
	ttl, _, err := verifySet(keyset, zone, sep, now, &t.sigBudget)
	if err != nil {
		ede, why := sigEDE(err)
		return keep(&keyEntry{sec: secBogus, ede: ede, why: why + " for " + m.NameString(zone) + " DNSKEY"}, bogusTTL)
	}
	ttl = min(ttl, dsTTL, maxCacheTTL)
	cs := &cachedSet{set: keyset, zone: zone, sec: secSecure, orig: ttl}
	r.sets.set(tkey(zone, typeDNSKEY), cs, now.Add(time.Duration(ttl)*time.Second))
	return keep(&keyEntry{sec: secSecure, keys: keys}, ttl)
}

func negTTL(a *answer, now time.Time) uint32 {
	if a.neg == nil {
		return 3600
	}
	return uint32(max(a.negUntil.Sub(now)/time.Second, 0))
}
