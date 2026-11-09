package recursor

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strings"
)

// Proofs that a name or type does not exist (RFC 4035 5.4, RFC 5155 8,
// RFC 6840 4). Every NSEC and NSEC3 RRset passed here has already been
// verified with the zone's keys.

type proof int

const (
	proofBogus    proof = iota // no valid proof
	proofSecure                // proven
	proofInsecure              // opt-out or unusable parameters: cannot be proven either way
)

// maxNSEC3Iterations: NSEC3 with more iterations is treated as insecure
// (RFC 9276; the same limit as Unbound), so hashing cannot be used to tie
// up the server.
const maxNSEC3Iterations = 150

// ---- NSEC ----

type nsec struct {
	owner, next string // lowercase wire names
	bitmap      []byte
}

func parseNSEC(set *rrset) (*nsec, bool) {
	if len(set.data) != 1 {
		return nil, false
	}
	d := set.data[0]
	off := 0
	for {
		if off >= len(d) {
			return nil, false
		}
		l := int(d[off])
		off += 1 + l
		if l == 0 {
			break
		}
	}
	if off > len(d) {
		return nil, false
	}
	return &nsec{owner: set.name, next: lower(d[:off-1]), bitmap: d[off:]}, true
}

func (n *nsec) has(t uint16) bool { return typeBitmapHas(n.bitmap, t) }

// covers reports whether name falls strictly between owner and next.
func (n *nsec) covers(name string) bool {
	if canonicalCompare(n.owner, name) >= 0 {
		// before the owner: only the last NSEC of the zone (next is the
		// apex) wraps around to the beginning
		return false
	}
	if canonicalCompare(n.next, n.owner) <= 0 { // last NSEC: next is the apex
		return isSub(name, n.next)
	}
	return canonicalCompare(name, n.next) < 0
}

// delegation reports an NSEC from the parent side of a zone cut, which can
// only be used to deny DS (RFC 6840 4.1).
func (n *nsec) delegation() bool { return n.has(2) && !n.has(6) }

func commonAncestor(a, b string) string {
	for !isSub(a, b) {
		b = parent(b)
	}
	return b
}

// nsecClosestEncloser returns the closest encloser of qname implied by an
// NSEC that covers it.
func nsecClosestEncloser(n *nsec, qname string) string {
	a, b := commonAncestor(qname, n.owner), commonAncestor(qname, n.next)
	if len(a) > len(b) {
		return a
	}
	return b
}

// nsecUsable rejects an NSEC covering qname from above a delegation or a
// DNAME on the way (RFC 6840 4.1).
func nsecUsable(n *nsec, qname string) bool {
	if isSub(qname, n.owner) && qname != n.owner && (n.delegation() || n.has(typeDNAME)) {
		return false
	}
	return true
}

func nsecs(sets []*rrset) []*nsec {
	var out []*nsec
	for _, s := range sets {
		if s.typ == typeNSEC {
			if n, ok := parseNSEC(s); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// proveNXDomainNSEC: an NSEC covers qname and one covers the wildcard at
// the closest encloser.
func proveNXDomainNSEC(ns []*nsec, qname string) bool {
	for _, n := range ns {
		if !n.covers(qname) || !nsecUsable(n, qname) || isSub(n.next, qname) {
			continue // (names below qname mean it exists)
		}
		ce := nsecClosestEncloser(n, qname)
		wild := "\x01*" + ce
		for _, w := range ns {
			if w.covers(wild) {
				return true
			}
		}
	}
	return false
}

// proveNoDataNSEC: an NSEC at qname without qtype or CNAME, or a wildcard
// NODATA: qname covered and the wildcard's NSEC without qtype.
func proveNoDataNSEC(ns []*nsec, qname string, qtype uint16) (ok, delegation bool) {
	for _, n := range ns {
		if n.owner != qname {
			continue
		}
		if n.has(qtype) || n.has(5) {
			return false, false
		}
		if qtype != typeDS && n.delegation() {
			return false, false // the parent side of a cut says nothing about the child
		}
		if qtype == typeDS && n.has(6) && qname != "" {
			return false, false // the child's apex: DS lives in the parent
		}
		return true, n.has(2)
	}
	for _, n := range ns {
		if !n.covers(qname) || !nsecUsable(n, qname) {
			continue
		}
		if n.next != qname && isSub(n.next, qname) {
			return true, false // an empty non-terminal: names exist below, nothing at qname
		}
		wild := "\x01*" + nsecClosestEncloser(n, qname)
		for _, w := range ns {
			if w.owner == wild && !w.has(qtype) && !w.has(5) {
				return true, false
			}
		}
	}
	return false, false
}

// proveWildcardNSEC: the name an answer was expanded from a wildcard for
// does not exist.
func proveWildcardNSEC(ns []*nsec, qname string) bool {
	for _, n := range ns {
		if n.covers(qname) && nsecUsable(n, qname) {
			return true
		}
	}
	return false
}

// ---- NSEC3 ----

type nsec3 struct {
	zone       string
	hash, next []byte
	optOut     bool
	alg        uint8
	iterations uint16
	salt       []byte
	bitmap     []byte
}

var b32 = base32.HexEncoding.WithPadding(base32.NoPadding)

func parseNSEC3(set *rrset) (*nsec3, bool) {
	if len(set.data) != 1 || set.name == "" {
		return nil, false
	}
	d := set.data[0]
	if len(d) < 6 {
		return nil, false
	}
	n := &nsec3{alg: d[0], optOut: d[1]&1 != 0, iterations: binary.BigEndian.Uint16(d[2:]), zone: parent(set.name)}
	sl := int(d[4])
	if 5+sl+1 > len(d) {
		return nil, false
	}
	n.salt = d[5 : 5+sl]
	off := 5 + sl
	hl := int(d[off])
	if off+1+hl > len(d) || hl == 0 {
		return nil, false
	}
	n.next = d[off+1 : off+1+hl]
	n.bitmap = d[off+1+hl:]
	label := set.name[1 : 1+int(set.name[0])]
	h, err := b32.DecodeString(strings.ToUpper(label))
	if err != nil || len(h) != hl {
		return nil, false
	}
	n.hash = h
	return n, true
}

func (n *nsec3) has(t uint16) bool { return typeBitmapHas(n.bitmap, t) }

func nsec3Hash(name string, salt []byte, iterations uint16) []byte {
	h := sha1.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write(salt)
	sum := h.Sum(nil)
	for i := 0; i < int(iterations); i++ {
		h.Reset()
		h.Write(sum)
		h.Write(salt)
		sum = h.Sum(sum[:0])
	}
	return sum
}

func (n *nsec3) matches(hash []byte) bool { return bytes.Equal(n.hash, hash) }

func (n *nsec3) covers(hash []byte) bool {
	if bytes.Compare(n.next, n.hash) <= 0 { // the last one wraps around
		return bytes.Compare(hash, n.hash) > 0 || bytes.Compare(hash, n.next) < 0
	}
	return bytes.Compare(hash, n.hash) > 0 && bytes.Compare(hash, n.next) < 0
}

// nsec3Set holds the NSEC3 records of one response, all for one zone.
type nsec3Set struct {
	list   []*nsec3
	zone   string
	hashes map[string][]byte
}

// nsec3sFor collects the usable NSEC3 records for qname. insecure is set
// when the parameters cannot be used (unknown hash, too many iterations).
func nsec3sFor(sets []*rrset, qname string) (s *nsec3Set, insecure bool) {
	s = &nsec3Set{hashes: map[string][]byte{}}
	for _, r := range sets {
		if r.typ != typeNSEC3 {
			continue
		}
		n, ok := parseNSEC3(r)
		if !ok || !isSub(qname, n.zone) {
			continue
		}
		if n.alg != 1 || n.iterations > maxNSEC3Iterations {
			insecure = true
			continue
		}
		if s.zone == "" {
			s.zone = n.zone
		}
		if n.zone == s.zone {
			s.list = append(s.list, n)
		}
	}
	return s, insecure && len(s.list) == 0
}

func (s *nsec3Set) hash(name string, n *nsec3) []byte {
	k := name + "\x00" + string(n.salt) + string(rune(n.iterations))
	if h, ok := s.hashes[k]; ok {
		return h
	}
	h := nsec3Hash(name, n.salt, n.iterations)
	s.hashes[k] = h
	return h
}

func (s *nsec3Set) matching(name string) *nsec3 {
	for _, n := range s.list {
		if n.matches(s.hash(name, n)) {
			return n
		}
	}
	return nil
}

func (s *nsec3Set) covering(name string) *nsec3 {
	for _, n := range s.list {
		if n.covers(s.hash(name, n)) {
			return n
		}
	}
	return nil
}

// closestEncloser finds the closest encloser of qname and the NSEC3 that
// covers the next closer name (RFC 5155 8.3).
func (s *nsec3Set) closestEncloser(qname string) (ce string, nc *nsec3, ok bool) {
	for name := qname; isSub(name, s.zone); name = parent(name) {
		if m := s.matching(name); m != nil {
			if name == qname {
				return "", nil, false // the name exists
			}
			// a delegation or DNAME above qname makes the proof unusable
			if (m.has(2) && !m.has(6)) || m.has(typeDNAME) {
				return "", nil, false
			}
			next := ancestorAt(qname, labelCount(name)+1)
			if c := s.covering(next); c != nil {
				return name, c, true
			}
			return "", nil, false
		}
		if name == "" {
			break
		}
	}
	return "", nil, false
}

func proveNXDomainNSEC3(s *nsec3Set, qname string) proof {
	ce, nc, ok := s.closestEncloser(qname)
	if !ok {
		return proofBogus
	}
	if s.covering("\x01*"+ce) == nil {
		return proofBogus
	}
	if nc.optOut {
		return proofInsecure // an unsigned delegation could be there
	}
	return proofSecure
}

// proveNoDataNSEC3 returns the proof and, for DS, whether the name is a
// delegation (an insecure one when proven).
func proveNoDataNSEC3(s *nsec3Set, qname string, qtype uint16) (proof, bool) {
	if n := s.matching(qname); n != nil {
		if n.has(qtype) || n.has(5) {
			return proofBogus, false
		}
		if qtype != typeDS && n.has(2) && !n.has(6) {
			return proofBogus, false
		}
		if qtype == typeDS && n.has(6) && qname != "" {
			return proofBogus, false
		}
		return proofSecure, n.has(2)
	}
	ce, nc, ok := s.closestEncloser(qname)
	if !ok {
		return proofBogus, false
	}
	if qtype == typeDS {
		if nc.optOut { // RFC 5155 8.6: an unsigned delegation under opt-out
			return proofInsecure, true
		}
		return proofBogus, false
	}
	if w := s.matching("\x01*" + ce); w != nil && !w.has(qtype) && !w.has(5) {
		return proofSecure, false
	}
	return proofBogus, false
}

// proveWildcardNSEC3: the next closer name of a wildcard expansion is
// covered (RFC 5155 8.8). labels is the RRSIG labels field.
func proveWildcardNSEC3(s *nsec3Set, qname string, labels int) proof {
	nc := ancestorAt(qname, labels+1)
	c := s.covering(nc)
	if c == nil {
		return proofBogus
	}
	if c.optOut {
		return proofInsecure
	}
	return proofSecure
}
