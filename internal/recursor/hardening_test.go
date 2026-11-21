package recursor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

// Attacks on resolvers found in recent years, checked against DNSNova's
// own code.

// testZoneKey is an Ed25519 zone key that signs test RRsets.
type testZoneKey struct {
	zone string
	priv ed25519.PrivateKey
	key  *dnskey
}

func newTestZoneKey(t *testing.T, zone string) *testZoneKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rdata := append([]byte{1, 1, 3, algED25519}, pub...) // flags ZONE|SEP
	k, ok := parseKey(rdata)
	if !ok || k.pub == nil {
		t.Fatal("key")
	}
	return &testZoneKey{zone: zone, priv: priv, key: k}
}

// sign adds an RRSIG with the given labels field to set.
func (z *testZoneKey) sign(set *rrset, labels uint8, now time.Time) {
	d := binary.BigEndian.AppendUint16(nil, set.typ)
	d = append(d, algED25519, labels)
	d = binary.BigEndian.AppendUint32(d, set.ttl)
	d = binary.BigEndian.AppendUint32(d, uint32(now.Add(24*time.Hour).Unix()))
	d = binary.BigEndian.AppendUint32(d, uint32(now.Add(-time.Hour).Unix()))
	d = binary.BigEndian.AppendUint16(d, z.key.tag)
	d = append(append(d, z.zone...), 0)
	s, _ := parseSig(append(d, make([]byte, 64)...))
	d = append(d, ed25519.Sign(z.priv, signedData(set, s))...)
	set.sigs = append(set.sigs, d)
}

// An RRSIG whose labels field is below the signer's label count would put
// the wildcard it was expanded from above the zone: refused, though the
// signature itself is genuine.
func TestRRSIGLabelsBelowSigner(t *testing.T) {
	now := time.Now()
	zone := dotted("example.com.")
	z := newTestZoneKey(t, zone)
	for _, c := range []struct {
		labels uint8
		ok     bool
	}{{3, true}, {2, true}, {1, false}, {0, false}} { // www.example.com: 3; *.example.com: 2; *.com: 1
		set := &rrset{name: dotted("www.example.com."), typ: 1, class: 1, ttl: 300, data: [][]byte{{192, 0, 2, 1}}}
		z.sign(set, c.labels, now)
		budget := maxValidations
		_, _, err := verifySet(set, zone, []*dnskey{z.key}, now, &budget)
		if (err == nil) != c.ok {
			t.Errorf("labels %d: err %v", c.labels, err)
		}
	}
}

// An NSEC whose next name lies outside the zone that signed it is not used
// as a proof.
func TestNSECNextOutsideZone(t *testing.T) {
	zone := dotted("example.com.")
	nsecSet := func(owner, next string) *rrset {
		return &rrset{name: dotted(owner), typ: typeNSEC, class: 1, ttl: 300, data: [][]byte{append(append([]byte(dotted(next)), 0), 0, 1, 0x40)}}
	}
	in := nsecSet("a.example.com.", "c.example.com.")
	out := nsecSet("a.example.com.", "zzz.example.org.")
	if got := nsecs([]*rrset{in, out}, zone); len(got) != 1 || got[0].next != dotted("c.example.com.") {
		t.Fatalf("got %d NSEC records", len(got))
	}
}

// nsec3Record builds an NSEC3 RRset for name in zone with the given
// parameters, covering it (its hash sits just after the owner's).
func nsec3Record(zone, name string, iterations uint16, salt []byte, optOut bool) *rrset {
	h := nsec3Hash(name, salt, iterations)
	owner := append([]byte(nil), h...)
	owner[len(owner)-1]-- // just before the name's hash
	next := append([]byte(nil), h...)
	next[len(next)-1]++
	label := b32.EncodeToString(owner)
	flags := byte(0)
	if optOut {
		flags = 1
	}
	d := []byte{1, flags}
	d = binary.BigEndian.AppendUint16(d, iterations)
	d = append(d, byte(len(salt)))
	d = append(d, salt...)
	d = append(d, byte(len(next)))
	d = append(d, next...)
	return &rrset{name: string([]byte{byte(len(label))}) + lowerStr(label) + zone, typ: typeNSEC3, class: 1, ttl: 300, data: [][]byte{d}}
}

// NSEC3 records are used only for the zone that signed them (a child's
// cannot speak for its parent), with one set of
// parameters, and within the limits on iterations and salt (RFC 9276;
// 50 iterations at most).
func TestNSEC3Limits(t *testing.T) {
	zone, child := dotted("example.com."), dotted("sub.example.com.")
	q := dotted("x.sub.example.com.")
	good := nsec3Record(zone, q, 0, nil, false)
	if s, _ := nsec3sFor([]*rrset{good}, q, zone); len(s.list) != 1 {
		t.Fatal("a proper NSEC3 not used")
	}
	if s, _ := nsec3sFor([]*rrset{nsec3Record(child, q, 0, nil, false)}, q, zone); len(s.list) != 0 {
		t.Fatal("the child's NSEC3 used for the parent")
	}
	for _, c := range []struct {
		name   string
		iter   uint16
		salt   int
		usable bool
	}{{"50 iterations", 50, 8, true}, {"51 iterations", 51, 0, false}, {"64-byte salt", 0, 64, true}, {"65-byte salt", 0, 65, false}} {
		s, insecure := nsec3sFor([]*rrset{nsec3Record(zone, q, c.iter, make([]byte, c.salt), false)}, q, zone)
		if (len(s.list) == 1) != c.usable || insecure == c.usable {
			t.Errorf("%s: used %d, insecure %v", c.name, len(s.list), insecure)
		}
	}
	// another salt: not of this chain, and not hashed
	other := nsec3Record(zone, dotted("y.sub.example.com."), 0, []byte{1, 2}, false)
	if s, _ := nsec3sFor([]*rrset{good, other}, q, zone); len(s.list) != 1 {
		t.Fatalf("records with other parameters used: %d", len(s.list))
	}
}

// Many keys whose tags match the DS records, none whose digest does: the
// work stays bounded.
func TestDSMatchingBounded(t *testing.T) {
	zone := dotted("example.com.")
	z := newTestZoneKey(t, zone)
	keyset := &rrset{name: zone, typ: typeDNSKEY, class: 1, ttl: 300}
	var ds [][]byte
	for i := range 200 {
		k := append([]byte{1, 1, 3, algED25519}, make([]byte, 32)...)
		binary.BigEndian.PutUint32(k[4:], uint32(i))
		keyset.data = append(keyset.data, k)
		if i < maxDSUsed {
			tag := keyTag(k)
			d := []byte{byte(tag >> 8), byte(tag), algED25519, digestSHA256}
			ds = append(ds, append(d, make([]byte, sha256.Size)...)) // a digest that matches nothing
		}
	}
	_, sep, digests := matchDS(zone, keyset, ds)
	if len(sep) != 0 || digests > maxDSDigests {
		t.Fatalf("%d keys matched, %d digests", len(sep), digests)
	}
	// the genuine key among the first ones still matches
	keyset.data = append([][]byte{z.key.rdata}, keyset.data...)
	h := sha256.Sum256(append(append([]byte(zone), 0), z.key.rdata...))
	real := append([]byte{byte(z.key.tag >> 8), byte(z.key.tag), algED25519, digestSHA256}, h[:]...)
	if _, sep, _ := matchDS(zone, keyset, [][]byte{real}); len(sep) != 1 {
		t.Fatal("the genuine key not matched")
	}
}

// A response of many records, or of pointers to long names that take far
// more room expanded than in the message, is refused rather than held.
func TestResponseExpansionBounded(t *testing.T) {
	// the question: a 250-byte name; then records whose owner is a
	// two-byte pointer to it, each costing 12 bytes in the message
	long := []byte{}
	for len(long) < 240 {
		long = append(long, 9, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i')
	}
	msg := []byte{0, 1, 0x84, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	msg = append(append(msg, long...), 0, 0, 16, 0, 1)
	// NS records: owner and target both pointers to the long name
	build := func(n int) []byte {
		b := append([]byte(nil), msg...)
		binary.BigEndian.PutUint16(b[6:], uint16(n))
		for range n {
			b = append(b, 0xC0, 12, 0, 2, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 12)
		}
		return b
	}
	if _, err := parseMessage(build(100)); err != nil {
		t.Fatalf("100 records: %v", err)
	}
	if _, err := parseMessage(build(maxRecords + 1)); err == nil {
		t.Fatal("more than maxRecords accepted")
	}
	// under the record limit, but 2000 copies of a 250-byte name
	if _, err := parseMessage(build(1000)); err == nil {
		t.Fatal("expansion beyond maxExpanded accepted")
	}
}

// Many NS records sharing a long list of glue addresses: each address once,
// at most six per name and 32 per zone.
func TestNSAddressesBounded(t *testing.T) {
	zone := dotted("example.com.")
	var ns, glue []rr
	for i := range 20 {
		host := dotted(fmt.Sprintf("ns%d.example.com.", i))
		ns = append(ns, rr{name: zone, typ: 2, class: 1, ttl: 300, data: append([]byte(host), 0)})
		for j := range 50 {
			glue = append(glue, rr{name: host, typ: 1, class: 1, ttl: 300, data: []byte{192, 0, 2, byte(j)}})
		}
	}
	d, _ := delegFrom(ns, glue, zone)
	for _, h := range d.ns {
		if len(h.addrs) > maxAddrsPerNS {
			t.Fatalf("%d addresses for one name", len(h.addrs))
		}
	}
	r := newTest(t, world(), true)
	addrs := r.serverAddrs(t.Context(), newTask(), d, r.cfg.Load(), false)
	if len(addrs) != maxAddrsPerNS { // the six shared ones, once each
		t.Fatalf("%d addresses", len(addrs))
	}
}
