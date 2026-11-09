package recursor

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// testdata/zones.json holds zones signed by ldns-signzone (an independent
// implementation): per zone, [owner, type, ttl, rdata hex] for every
// record, plus the root trust anchor and the time they were signed.

type fixture struct {
	sets   map[string]map[string]*rrset // zone -> key(name,type) -> set
	anchor string
	now    time.Time
}

func dotted(name string) string {
	if name == "." {
		return ""
	}
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return lower(b)
}

func loadFixture(t testing.TB) *fixture {
	t.Helper()
	data, err := os.ReadFile("testdata/zones.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	f := &fixture{sets: map[string]map[string]*rrset{}}
	var now int64
	json.Unmarshal(raw["_now"], &now)
	json.Unmarshal(raw["_anchor"], &f.anchor)
	f.now = time.Unix(now, 0)
	for zone, msg := range raw {
		if strings.HasPrefix(zone, "_") {
			continue
		}
		var recs [][]any
		json.Unmarshal(msg, &recs)
		var rrs []rr
		for _, rec := range recs {
			d, _ := hex.DecodeString(rec[3].(string))
			rrs = append(rrs, rr{name: dotted(rec[0].(string)), typ: uint16(rec[1].(float64)), class: 1, ttl: uint32(rec[2].(float64)), data: d})
		}
		m := map[string]*rrset{}
		for _, s := range groupRRsets(rrs) {
			m[tkey(s.name, s.typ)] = s
		}
		f.sets[dotted(zone)] = m
	}
	return f
}

func (f *fixture) set(t testing.TB, zone, name string, typ uint16) *rrset {
	t.Helper()
	s := f.sets[dotted(zone)][tkey(dotted(name), typ)]
	if s == nil {
		t.Fatalf("no %s %d in %s", name, typ, zone)
	}
	return s
}

func (f *fixture) keys(t testing.TB, zone string) []*dnskey {
	var out []*dnskey
	for _, d := range f.set(t, zone, zone, typeDNSKEY).data {
		k, ok := parseKey(d)
		if !ok {
			t.Fatalf("key in %s does not parse", zone)
		}
		out = append(out, k)
	}
	return out
}

func (f *fixture) proofs(zone string) []*rrset {
	var out []*rrset
	for _, s := range f.sets[dotted(zone)] {
		if s.typ == typeNSEC || s.typ == typeNSEC3 {
			out = append(out, s)
		}
	}
	return out
}

func TestSignaturesFromAnotherImplementation(t *testing.T) {
	f := loadFixture(t)
	budget := 1000
	for _, zone := range []string{".", "com.", "example.com.", "example.net.", "ed.com.", "manyiter.com.", "signed.example.com."} {
		keys := f.keys(t, zone)
		n := 0
		for _, s := range f.sets[dotted(zone)] {
			if len(s.sigs) == 0 {
				continue // delegations and glue are not signed
			}
			if _, _, err := verifySet(s, dotted(zone), keys, f.now, &budget); err != nil {
				t.Errorf("%s: %q type %d: %v", zone, s.name, s.typ, err)
			}
			n++
			budget = 1000
		}
		if n < 4 {
			t.Errorf("%s: only %d signed sets", zone, n)
		}
	}
	// the root's KSK matches the trust anchor
	anchor, err := ParseAnchor(f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range f.keys(t, ".") {
		found = found || dsMatches("", anchor, k)
	}
	if !found {
		t.Fatal("no root key matches the anchor")
	}
	// so do the DS records in parents
	ds := f.set(t, "com.", "example.com.", typeDS)
	found = false
	for _, k := range f.keys(t, "example.com.") {
		for _, d := range ds.data {
			found = found || dsMatches(dotted("example.com."), d, k)
		}
	}
	if !found {
		t.Fatal("example.com DS does not match its key")
	}
	// example.net's DS uses SHA-384
	ds = f.set(t, "net.", "example.net.", typeDS)
	if ds.data[0][3] != digestSHA384 || !dsMatches(dotted("example.net."), ds.data[0], f.keys(t, "example.net.")[0]) &&
		!dsMatches(dotted("example.net."), ds.data[0], f.keys(t, "example.net.")[1]) {
		t.Fatal("SHA-384 DS does not match")
	}
}

func TestBadSignatures(t *testing.T) {
	f := loadFixture(t)
	budget := 100
	_, _, err := verifySet(f.set(t, "badsig.com.", "www.badsig.com.", 1), dotted("badsig.com."), f.keys(t, "badsig.com."), f.now, &budget)
	if !errors.Is(err, errSigBad) {
		t.Fatalf("changed data: %v", err)
	}
	_, _, err = verifySet(f.set(t, "expired.com.", "www.expired.com.", 1), dotted("expired.com."), f.keys(t, "expired.com."), f.now, &budget)
	if !errors.Is(err, errSigExpired) {
		t.Fatalf("expired: %v", err)
	}
	// valid signatures, but too early
	_, _, err = verifySet(f.set(t, "example.com.", "www.example.com.", 1), dotted("example.com."), f.keys(t, "example.com."), f.now.Add(-30*24*time.Hour), &budget)
	if !errors.Is(err, errSigNotYet) {
		t.Fatalf("not yet valid: %v", err)
	}
	// a key from another zone
	_, _, err = verifySet(f.set(t, "example.com.", "www.example.com.", 1), dotted("example.com."), f.keys(t, "ed.com."), f.now, &budget)
	if !errors.Is(err, errNoKey) {
		t.Fatalf("wrong keys: %v", err)
	}
	// the signature budget stops work (KeyTrap)
	budget = 0
	if _, _, err := verifySet(f.set(t, "example.com.", "www.example.com.", 1), dotted("example.com."), f.keys(t, "example.com."), f.now, &budget); err == nil {
		t.Fatal("verified without budget")
	}
	// one changed byte in the data
	s := *f.set(t, "ed.com.", "www.ed.com.", 1)
	s.data = [][]byte{{192, 0, 2, 8}}
	budget = 100
	if _, _, err := verifySet(&s, dotted("ed.com."), f.keys(t, "ed.com."), f.now, &budget); !errors.Is(err, errSigBad) {
		t.Fatalf("Ed25519 with changed data: %v", err)
	}
}

func TestWildcardSignature(t *testing.T) {
	f := loadFixture(t)
	w := f.set(t, "example.com.", "*.wild.example.com.", 1)
	// the same records and signatures, as an answer for another name
	s := &rrset{name: dotted("x.y.wild.example.com."), typ: 1, class: 1, ttl: w.ttl, data: w.data, sigs: w.sigs}
	budget := 10
	_, labels, err := verifySet(s, dotted("example.com."), f.keys(t, "example.com."), f.now, &budget)
	if err != nil || labels != 3 {
		t.Fatalf("wildcard expansion: %v labels %d", err, labels)
	}
	if !wildcardExpanded(s) {
		t.Fatal("not recognized as expanded")
	}
	ns := nsecs(f.proofs("example.com."))
	if !proveWildcardNSEC(ns, s.name) {
		t.Fatal("no proof that the expanded name does not exist")
	}
}

func TestNSECProofs(t *testing.T) {
	f := loadFixture(t)
	ns := nsecs(f.proofs("example.com."))
	q := dotted
	if !proveNXDomainNSEC(ns, q("nope.example.com.")) {
		t.Error("NXDOMAIN not proven")
	}
	if proveNXDomainNSEC(ns, q("www.example.com.")) || proveNXDomainNSEC(ns, q("b.c.example.com.")) {
		t.Error("NXDOMAIN proven for a name that exists")
	}
	if proveNXDomainNSEC(ns, q("nope.wild.example.com.")) {
		t.Error("NXDOMAIN proven under a wildcard")
	}
	if ok, _ := proveNoDataNSEC(ns, q("www.example.com."), typeTXT); !ok {
		t.Error("NODATA not proven")
	}
	if ok, _ := proveNoDataNSEC(ns, q("www.example.com."), 1); ok {
		t.Error("NODATA proven for a type that exists")
	}
	if ok, _ := proveNoDataNSEC(ns, q("alias.example.com."), 1); ok {
		t.Error("NODATA proven at a CNAME")
	}
	if ok, _ := proveNoDataNSEC(ns, q("b.c.example.com."), 1); !ok {
		t.Error("empty non-terminal not proven")
	}
	// DS for an unsigned child: the parent's NSEC shows a delegation without DS
	if ok, cut := proveNoDataNSEC(ns, q("sub.example.com."), typeDS); !ok || !cut {
		t.Errorf("insecure delegation: %v %v", ok, cut)
	}
	// that NSEC must not deny other types at the child
	if ok, _ := proveNoDataNSEC(ns, q("sub.example.com."), 1); ok {
		t.Error("parent-side NSEC used to deny a child type")
	}
	if ok, _ := proveNoDataNSEC(ns, q("signed.example.com."), typeDS); ok {
		t.Error("DS denied where there is one")
	}
	// nothing under a delegation can be denied with the parent's NSEC
	if proveNXDomainNSEC(ns, q("deep.sub.example.com.")) {
		t.Error("NXDOMAIN proven below a delegation")
	}
}

func TestNSEC3Proofs(t *testing.T) {
	f := loadFixture(t)
	q := dotted
	s, insecure := nsec3sFor(f.proofs("example.net."), q("nope.example.net."))
	if insecure || len(s.list) == 0 {
		t.Fatal("no NSEC3")
	}
	if p := proveNXDomainNSEC3(s, q("nope.example.net.")); p != proofSecure {
		t.Errorf("NXDOMAIN: %v", p)
	}
	if p := proveNXDomainNSEC3(s, q("www.example.net.")); p == proofSecure {
		t.Error("NXDOMAIN proven for a name that exists")
	}
	if p, _ := proveNoDataNSEC3(s, q("api.example.net."), 28); p != proofSecure {
		t.Errorf("NODATA: %v", p)
	}
	if p, _ := proveNoDataNSEC3(s, q("api.example.net."), 1); p == proofSecure {
		t.Error("NODATA proven for a type that exists")
	}
	if p := proveWildcardNSEC3(s, q("x.apps.example.net."), 3); p != proofSecure {
		t.Errorf("wildcard: %v", p)
	}
	if p := proveWildcardNSEC3(s, q("api.example.net."), 2); p == proofSecure {
		t.Error("wildcard proof for an existing name")
	}

	// com uses opt-out: a missing name could be an unsigned delegation
	c, _ := nsec3sFor(f.proofs("com."), q("nope.com."))
	if p := proveNXDomainNSEC3(c, q("nope.com.")); p != proofInsecure {
		t.Errorf("opt-out NXDOMAIN: %v", p)
	}
	if p, cut := proveNoDataNSEC3(c, q("unsigned.com."), typeDS); p == proofBogus || !cut {
		t.Errorf("unsigned delegation: %v %v", p, cut)
	}
	if p, _ := proveNoDataNSEC3(c, q("example.com."), typeDS); p != proofBogus {
		t.Error("DS denied where there is one")
	}

	// too many iterations: not usable
	if _, insecure := nsec3sFor(f.proofs("manyiter.com."), q("nope.manyiter.com.")); !insecure {
		t.Error("200 iterations accepted")
	}
}

func TestAggressiveNSEC(t *testing.T) {
	f := loadFixture(t)
	var x nsecIndex
	now := f.now
	x.add(dotted("example.com."), f.set(t, "example.com.", "example.com.", 6), f.proofs("example.com."), 300, now)
	q := dotted
	cases := []struct {
		name  string
		qtype uint16
		rcode int // -1: not answered from the NSEC records
	}{
		{"nope.example.com.", 1, 3},
		{"zzz.nope.example.com.", 28, 3},
		{"www.example.com.", typeTXT, 0},
		{"www.example.com.", 1, -1},       // exists
		{"alias.example.com.", 1, -1},     // a CNAME
		{"nope.wild.example.com.", 1, -1}, // a wildcard answers it
		{"b.c.example.com.", 1, 0},        // empty non-terminal
		{"sub.example.com.", typeDS, 0},   // insecure delegation
		{"www.sub.example.com.", 1, -1},   // below a delegation: the child answers
		{"signed.example.com.", typeDS, -1},
		{"nope.example.org.", 1, -1}, // another zone
	}
	for _, c := range cases {
		ne, exp := x.synth(q(c.name), c.qtype, now)
		got := -1
		if ne != nil {
			got = ne.rcode
			if ne.sec != secSecure || ne.soa == nil || len(ne.proof) == 0 || !exp.After(now) {
				t.Errorf("%s: incomplete %+v", c.name, ne)
			}
		}
		if got != c.rcode {
			t.Errorf("%s %d: rcode %d, want %d", c.name, c.qtype, got, c.rcode)
		}
	}
	if ne, _ := x.synth(q("nope.example.com."), 1, now.Add(time.Hour)); ne != nil {
		t.Error("expired records used")
	}
}
