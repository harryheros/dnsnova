package recursor

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// signedNet serves the signed fixture (testdata/zones.json, made with
// another implementation's tools) as the real hierarchy would: each zone on
// the addresses its name servers have in the fixture, with referrals, DS
// records, signatures and denial proofs. It tests validation end to end,
// through iteration, rather than one function at a time.
type signedNet struct {
	f      *fixture
	byAddr map[netip.Addr][]string // server -> zones it serves
	roots  []netip.Addr
}

func newSignedNet(t *testing.T) *signedNet {
	t.Helper()
	f := loadFixture(t)
	n := &signedNet{f: f, byAddr: map[netip.Addr][]string{}}
	addrOf := func(host string) []netip.Addr {
		var out []netip.Addr
		for _, sets := range f.sets {
			if s := sets[tkey(host, m.TypeA)]; s != nil {
				for _, d := range s.data {
					a, _ := netip.AddrFromSlice(d)
					if !slices.Contains(out, a) {
						out = append(out, a)
					}
				}
			}
		}
		return out
	}
	for zone, sets := range f.sets {
		ns := sets[tkey(zone, m.TypeNS)]
		if ns == nil {
			continue
		}
		for _, d := range ns.data {
			for _, a := range addrOf(lower(nameOf(d))) {
				n.byAddr[a] = append(n.byAddr[a], zone)
				if zone == "" && !slices.Contains(n.roots, a) {
					n.roots = append(n.roots, a)
				}
			}
		}
	}
	if len(n.roots) == 0 {
		t.Fatal("fixture: no root server addresses")
	}
	return n
}

func (n *signedNet) denial(sets map[string]*rrset) []rr {
	var out []rr
	for _, s := range sets {
		if s.typ == typeNSEC || s.typ == typeNSEC3 {
			out = append(append(out, s.records()...), s.sigRecords(s.ttl)...)
		}
	}
	return out
}

func (n *signedNet) send(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
	zones := n.byAddr[addr.Addr()]
	if len(zones) == 0 {
		return nil, context.DeadlineExceeded
	}
	msg, err := parseMessage(q)
	if err != nil {
		return nil, err
	}
	qn, qt := msg.qname, msg.qtype
	zone, found := "", false
	for _, z := range zones {
		if isSub(qn, z) && (!found || len(z) > len(zone)) {
			zone, found = z, true
		}
	}
	if !found {
		return buildMessage(msg.id, m.FlagQR|m.RcodeRefused, qn, qt, nil, nil, nil, true, true, nil), nil
	}
	sets := n.f.sets[zone]
	with := func(s *rrset) []rr { return append(s.records(), s.sigRecords(s.ttl)...) }
	// a delegation on the way down?
	for c := qn; c != zone && isSub(c, zone); c = parent(c) {
		ns := sets[tkey(c, m.TypeNS)]
		if ns == nil || (qt == typeDS && c == qn) {
			continue
		}
		auth := ns.records()
		if ds := sets[tkey(c, typeDS)]; ds != nil {
			auth = append(auth, with(ds)...)
		} else {
			auth = append(auth, n.denial(sets)...)
		}
		var glue []rr
		for _, d := range ns.data {
			if a := sets[tkey(lower(nameOf(d)), m.TypeA)]; a != nil {
				glue = append(glue, a.records()...)
			}
		}
		return buildMessage(msg.id, m.FlagQR, qn, qt, nil, auth, glue, true, true, nil), nil
	}
	flags := uint16(m.FlagQR | m.FlagAA)
	if s := sets[tkey(qn, qt)]; s != nil {
		return buildMessage(msg.id, flags, qn, qt, with(s), nil, nil, true, true, nil), nil
	}
	if s := sets[tkey(qn, m.TypeCNAME)]; s != nil {
		return buildMessage(msg.id, flags, qn, qt, with(s), nil, nil, true, true, nil), nil
	}
	exists := false
	for k := range sets {
		if owner := k[:len(k)-2]; isSub(owner, qn) {
			exists = true // the name, or an empty non-terminal above names
		}
	}
	auth := append(with(sets[tkey(zone, m.TypeSOA)]), n.denial(sets)...)
	if !exists {
		flags |= m.RcodeNXDomain
	}
	return buildMessage(msg.id, flags, qn, qt, nil, auth, nil, true, true, nil), nil
}

func newSignedTest(t *testing.T, ntas ...string) (*Recursor, *signedNet) {
	t.Helper()
	n := newSignedNet(t)
	cfg := Config{DNSSEC: true, QNameMinimisation: true, RootHints: n.roots, TrustAnchors: []string{n.f.anchor},
		Allow: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	for _, d := range ntas {
		cfg.NTAs = append(cfg.NTAs, dotted(d))
	}
	r := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.send = n.send
	r.now = func() time.Time { return n.f.now }
	return r, n
}

func askDO(t *testing.T, r *Recursor, name string, qtype uint16) *message {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q := buildQuery(9, dotted(name), qtype, true, nil)
	q[2] |= 1 // RD
	resp, err := r.Exchange(ctx, q)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	msg, err := parseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// Through the whole hierarchy: a good chain validates; a bad signature and
// an expired one are refused, with the reason.
func TestSignedHierarchy(t *testing.T) {
	r, _ := newSignedTest(t)
	if msg := askDO(t, r, "www.ed.com.", m.TypeA); msg.rcode != m.RcodeNoError || msg.flags&m.FlagAD == 0 || len(msg.answer) == 0 {
		t.Fatalf("www.ed.com: rcode %d AD %v answers %d", msg.rcode, msg.flags&m.FlagAD != 0, len(msg.answer))
	}
	for name, ede := range map[string]uint16{"www.badsig.com.": edeBogus, "www.expired.com.": edeSigExpired} {
		msg := askDO(t, r, name, m.TypeA)
		if msg.rcode != m.RcodeServFail || len(msg.answer) != 0 {
			t.Fatalf("%s: rcode %d with %d answers, want SERVFAIL", name, msg.rcode, len(msg.answer))
		}
		if !slices.Contains(msg.ede, ede) {
			t.Errorf("%s: EDE %v, want %d", name, msg.ede, ede)
		}
	}
	fails := r.Failures()
	if len(fails) != 2 || fails[0].Count != 1 {
		t.Fatalf("failures %+v", fails)
	}
	got := map[string]string{}
	for _, f := range fails {
		got[f.Name] = f.EDE + ": " + f.Why
	}
	if !strings.HasPrefix(got["www.badsig.com."], "DNSSEC Bogus: signature does not verify") || !strings.HasPrefix(got["www.expired.com."], "Signature Expired: signature expired") {
		t.Fatalf("failure reasons %v", got)
	}
	r.ClearFailures()
	if len(r.Failures()) != 0 {
		t.Fatal("not cleared")
	}
}

// A negative trust anchor: the broken domain answers again, unsigned (no
// AD); its neighbours are still validated.
func TestNegativeTrustAnchor(t *testing.T) {
	r, _ := newSignedTest(t, "badsig.com")
	msg := askDO(t, r, "www.badsig.com.", m.TypeA)
	if msg.rcode != m.RcodeNoError || len(msg.answer) == 0 || msg.flags&m.FlagAD != 0 {
		t.Fatalf("www.badsig.com under an NTA: rcode %d answers %d AD %v", msg.rcode, len(msg.answer), msg.flags&m.FlagAD != 0)
	}
	if msg := askDO(t, r, "www.expired.com.", m.TypeA); msg.rcode != m.RcodeServFail {
		t.Fatalf("www.expired.com (no NTA): rcode %d, want SERVFAIL", msg.rcode)
	}
	if msg := askDO(t, r, "www.ed.com.", m.TypeA); msg.flags&m.FlagAD == 0 {
		t.Fatal("www.ed.com lost its AD")
	}
	if len(r.Failures()) != 1 {
		t.Fatalf("failures %+v", r.Failures())
	}
	// changing the anchors forgets what was validated with the old ones
	c := *r.cfg.Load()
	c.NTAs = nil
	r.SetConfig(c)
	if msg := askDO(t, r, "www.badsig.com.", m.TypeA); msg.rcode != m.RcodeServFail {
		t.Fatalf("NTA removed: rcode %d, want SERVFAIL", msg.rcode)
	}
}

// A trace shows the way down and where validation fails, and asks again
// even what the cache holds.
func TestTrace(t *testing.T) {
	r, _ := newSignedTest(t)
	askDO(t, r, "www.badsig.com.", m.TypeA) // now cached
	tr := r.Trace(context.Background(), dotted("www.badsig.com."), m.TypeA)
	if tr.Rcode != "SERVFAIL" || tr.DNSSEC != "bogus" || tr.EDE != "DNSSEC Bogus" || !strings.Contains(tr.Why, "www.badsig.com") {
		t.Fatalf("result %+v", tr)
	}
	var zonesAsked []string
	keys := map[string]string{}
	var verdict *TraceStep
	for i, s := range tr.Steps {
		switch s.Kind {
		case "query":
			if !slices.Contains(zonesAsked, s.Zone) {
				zonesAsked = append(zonesAsked, s.Zone)
			}
			if s.Server == "" || s.Result == "" {
				t.Fatalf("query step without server or result: %+v", s)
			}
		case "keys":
			keys[s.Zone] = s.Sec
		case "validate":
			if s.Name == "www.badsig.com." {
				verdict = &tr.Steps[i]
			}
		}
	}
	for _, z := range []string{".", "com.", "badsig.com."} {
		if !slices.Contains(zonesAsked, z) {
			t.Errorf("no query to the servers of %s (asked: %v)", z, zonesAsked)
		}
		if keys[z] != "secure" {
			t.Errorf("keys of %s: %q", z, keys[z])
		}
	}
	if verdict == nil || verdict.Sec != "bogus" || !strings.Contains(verdict.Why, "does not verify") {
		t.Fatalf("no bogus verdict for www.badsig.com: %+v", verdict)
	}
	if tr.Queries == 0 {
		t.Fatal("the trace asked no one: it used the cache")
	}
	// a good name: secure all the way, and the answer
	ok := r.Trace(context.Background(), dotted("www.ed.com."), m.TypeA)
	if ok.Rcode != "NOERROR" || ok.DNSSEC != "secure" || len(ok.Answers) == 0 || !strings.Contains(ok.Answers[0], "www.ed.com.") {
		t.Fatalf("www.ed.com trace: %+v", ok)
	}
	// with an NTA the trace says so
	r2, _ := newSignedTest(t, "badsig.com")
	nt := r2.Trace(context.Background(), dotted("www.badsig.com."), m.TypeA)
	if nt.Rcode != "NOERROR" || nt.DNSSEC != "insecure" || !strings.Contains(nt.Why, "negative trust anchor") {
		t.Fatalf("NTA trace: %+v", nt)
	}
}

// TestServeSignedFixture serves the signed fixture over real UDP and TCP on
// port 53 of its 127.x addresses for DNSNOVA_FIXTURE_SECONDS, so a running
// dnsnova can resolve through it (root_hints = the addresses it prints,
// trust_anchors = its anchor, allow_networks = ["127.0.0.0/8"]). Manual
// use only; skipped otherwise. Needs the right to bind port 53.
func TestServeSignedFixture(t *testing.T) {
	secs := os.Getenv("DNSNOVA_FIXTURE_SECONDS")
	if secs == "" {
		t.Skip("DNSNOVA_FIXTURE_SECONDS not set")
	}
	d, _ := time.ParseDuration(secs + "s")
	n := newSignedNet(t)
	fmt.Printf("root hints: %v\nanchor: %s\n", n.roots, n.f.anchor)
	for a := range n.byAddr {
		ap := netip.AddrPortFrom(a, 53)
		pc, err := net.ListenPacket("udp", ap.String())
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		go func() {
			buf := make([]byte, 4096)
			for {
				k, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if resp, err := n.send(context.Background(), ap, buf[:k], false); err == nil {
					pc.WriteTo(resp, from)
				}
			}
		}()
		ln, err := net.Listen("tcp", ap.String())
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					var lb [2]byte
					if _, err := io.ReadFull(c, lb[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(lb[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					if resp, err := n.send(context.Background(), ap, q, true); err == nil {
						c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
					}
				}()
			}
		}()
	}
	time.Sleep(d)
}
