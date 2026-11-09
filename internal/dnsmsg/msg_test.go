package dnsmsg_test

import (
	"bytes"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

func TestParseQuery(t *testing.T) {
	q, rc, err := m.ParseQuery(dnstest.Query(0x1234, "WwW.Example.COM", m.TypeAAAA, true, true))
	if err != nil || rc != 0 {
		t.Fatal(err, rc)
	}
	if m.NameString(q.Name) != "www.example.com." || q.Type != m.TypeAAAA || !q.EDNS || !q.DO || q.UDPSize != 1232 {
		t.Fatalf("bad parse: %+v", q)
	}

	two := dnstest.Query(1, "a.test", 1, false, false)
	two[5] = 2
	if _, rc, _ := m.ParseQuery(two); rc != m.RcodeFormErr {
		t.Fatalf("two questions: want FORMERR, got %d", rc)
	}
	if _, rc, err := m.ParseQuery(two[:15]); err == nil && rc == 0 {
		t.Fatal("truncated packet accepted")
	}
	resp := dnstest.Query(1, "a.test", 1, false, false)
	resp[2] |= 0x80
	if _, _, err := m.ParseQuery(resp); err == nil {
		t.Fatal("a response must be rejected")
	}
	op := dnstest.Query(1, "a.test", 1, false, false)
	op[2] |= 0x28 // opcode 5 (UPDATE)
	if _, rc, _ := m.ParseQuery(op); rc != m.RcodeNotImp {
		t.Fatalf("UPDATE: want NOTIMP, got %d", rc)
	}
	dupOPT := dnstest.Query(1, "a.test", 1, true, false)
	dupOPT[11] = 2
	dupOPT = m.AppendOPT(dupOPT, 512, false)
	if _, rc, _ := m.ParseQuery(dupOPT); rc != m.RcodeFormErr {
		t.Fatalf("two OPT records: want FORMERR, got %d", rc)
	}
}

func TestCacheKeySeparatesDNSSECFlags(t *testing.T) {
	plain, _, _ := m.ParseQuery(dnstest.Query(1, "a.test", 1, true, false))
	do, _, _ := m.ParseQuery(dnstest.Query(1, "A.TEST", 1, true, true))
	cdReq := dnstest.Query(1, "a.test", 1, true, false)
	cdReq[3] |= byte(m.FlagCD)
	cd, _, _ := m.ParseQuery(cdReq)
	if plain.CacheKey() == do.CacheKey() || plain.CacheKey() == cd.CacheKey() || do.CacheKey() == cd.CacheKey() {
		t.Fatal("DO and CD must change the cache key")
	}
	same, _, _ := m.ParseQuery(dnstest.Query(9, "A.Test", 1, false, false))
	if plain.CacheKey() != same.CacheKey() {
		t.Fatal("case and ID must not change the cache key")
	}
}

func TestMatchResponse(t *testing.T) {
	q := dnstest.Query(7, "a.test", 1, false, false)
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	if !m.MatchResponse(q, r) {
		t.Fatal("should match")
	}
	r2 := append([]byte(nil), r...)
	r2[1] = 8
	if m.MatchResponse(q, r2) {
		t.Fatal("different ID must not match")
	}
	r3 := dnstest.Query(7, "b.test", 1, false, false)
	r3[2] |= 0x80
	if m.MatchResponse(q, r3) {
		t.Fatal("different question must not match")
	}
	r4 := dnstest.Query(7, "A.TEST", 1, false, false)
	r4[2] |= 0x80
	if !m.MatchResponse(q, r4) {
		t.Fatal("case must not matter")
	}
}

func TestSynthesizedResponses(t *testing.T) {
	req := dnstest.Query(5, "x.10.in-addr.arpa", m.TypePTR, true, true)
	q, _, _ := m.ParseQuery(req)
	zone := m.WireName("10", "in-addr", "arpa")
	r := dnstest.Parse(t, m.NegativeSOA(req, q, zone, 10800, m.RcodeNXDomain))
	if r.Rcode != m.RcodeNXDomain || r.NS != 1 || r.Types[0] != m.TypeSOA || r.AD() || !r.HasOPT || !r.OPTDO || r.ID != 5 {
		t.Fatalf("negative SOA: %+v", r)
	}
	a := dnstest.Parse(t, m.Answer(req, q, 60, []byte{127, 0, 0, 1}))
	if a.AN != 1 || a.TTLs[0] != 60 || a.AD() {
		t.Fatalf("answer: %+v", a)
	}
	tc := dnstest.Parse(t, m.Truncated(req, q, 0))
	if !tc.TC() || tc.AN != 0 {
		t.Fatalf("truncated: %+v", tc)
	}
}

func TestNameHelpers(t *testing.T) {
	w := m.WireName("www", "example", "com")
	if m.NameString(w) != "www.example.com." || m.NameString("") != "." {
		t.Fatal(m.NameString(w))
	}
	if got := m.Labels(w); len(got) != 3 || got[1] != "example" {
		t.Fatal(got)
	}
	if !bytes.Equal([]byte(w+"\x00"), dnstest.Wire("www.example.com")) {
		t.Fatal("wire mismatch")
	}
}

// FuzzParseQuery feeds arbitrary bytes to every parser: none may panic, and
// any query they accept must produce a well-formed error response.
func FuzzParseQuery(f *testing.F) {
	f.Add(dnstest.Query(1, "example.com", 1, true, true))
	f.Add(dnstest.Query(2, "a.b.c.d.e", 28, false, false))
	f.Add([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		q, rc, err := m.ParseQuery(b)
		m.ResponseMinTTL(b)
		m.MatchResponse(b, b)
		m.SkipName(b, 0)
		m.WalkRRs(b, 0, 16, nil)
		if err != nil {
			return
		}
		r := m.ErrorResponse(b, q, rc)
		if len(r) < m.HeaderLen {
			t.Fatal("short error response")
		}
		if rc == 0 {
			up := m.BuildUpstreamQuery(q)
			if _, _, err := m.ParseQuery(up); err != nil {
				t.Fatalf("upstream query does not parse: %v", err)
			}
			m.Truncated(b, q, 0)
			m.NegativeSOA(b, q, q.Name, 60, m.RcodeNXDomain)
		}
	})
}

func TestReadName(t *testing.T) {
	// "www.Example.com" at 12, then "a" + pointer to "example.com" at 16
	msg := make([]byte, 12)
	msg = append(msg, 3, 'w', 'w', 'w', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	ptr := len(msg)
	msg = append(msg, 1, 'a', 0xC0, 16)
	name, next, err := m.ReadName(msg, ptr)
	if err != nil || name != "\x01a\x07example\x03com" || next != ptr+4 {
		t.Fatalf("%q %d %v", name, next, err)
	}
	if name, next, err := m.ReadName(msg, 12); err != nil || name != "\x03www\x07example\x03com" || next != ptr {
		t.Fatalf("%q %d %v", name, next, err)
	}
	for _, bad := range [][]byte{
		append(make([]byte, 12), 0xC0, 12),       // points at itself
		append(make([]byte, 12), 0xC0, 20, 0, 0), // forward pointer
		append(make([]byte, 12), 5, 'a'),         // runs past the end
		append(make([]byte, 12), 0x80, 0),        // reserved label type
	} {
		if _, _, err := m.ReadName(bad, 12); err == nil {
			t.Fatalf("accepted %v", bad[12:])
		}
	}
}

// TestMatchResponseExactTypeAndClass: only the name is compared without
// regard to letter case. Type 65 (HTTPS, 0x41) and type 97 (0x61) differ
// by the bit that separates "A" from "a".
func TestMatchResponseExactTypeAndClass(t *testing.T) {
	q := dnstest.Query(7, "a.test", 65, false, false)
	resp := func(change func(r []byte)) []byte {
		r := append([]byte(nil), q...)
		r[2] |= 0x80
		change(r)
		return r
	}
	n := len(q)
	if !m.MatchResponse(q, resp(func([]byte) {})) {
		t.Fatal("the same question must match")
	}
	if m.MatchResponse(q, resp(func(r []byte) { r[n-3] = 97 })) {
		t.Error("type 97 matched a query for type 65")
	}
	if m.MatchResponse(q, resp(func(r []byte) { r[n-4] = 0x20 })) {
		t.Error("a different type (high byte) matched")
	}
	qc := dnstest.Query(7, "a.test", 1, false, false)
	qc[len(qc)-1] = 0x41
	rc := append([]byte(nil), qc...)
	rc[2] |= 0x80
	rc[len(rc)-1] = 0x61
	if m.MatchResponse(qc, rc) {
		t.Error("class 0x61 matched a query for class 0x41")
	}
	if m.MatchResponse(q, resp(func(r []byte) { r[2] |= 0x28 })) { // opcode 5 (UPDATE)
		t.Error("a response with another opcode matched")
	}
}

// TestStripOPTExtendedRcode: BADVERS is RCODE 16: 0 in the header and 1 in
// the OPT record. Without OPT it would read as "no error".
func TestStripOPTExtendedRcode(t *testing.T) {
	r := dnstest.Query(7, "a.test", 1, true, false)
	r[2] |= 0x80
	if _, _, err := m.StripOPT(r); err != nil {
		t.Fatalf("plain OPT: %v", err)
	}
	r[len(r)-6] = 1 // the first byte of the OPT record's TTL field
	if _, _, err := m.StripOPT(r); err != m.ErrExtendedRcode {
		t.Fatalf("extended RCODE: err = %v", err)
	}
}
