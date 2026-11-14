package resolver

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/stats"
)

// forwardTest has an upstream and an office server for corp.test and the
// 10.in-addr.arpa reverse zone.
func forwardTest(t *testing.T) (r *Resolver, up, office *dnstest.Auth) {
	t.Helper()
	up, office = dnstest.NewAuth(), dnstest.NewAuth()
	s := settings()
	s.Forward = NewForwards("one")
	s.Forward.Add("corp.test", dnstest.Exchanger{Auth: office})
	s.Forward.Add("10.in-addr.arpa.", dnstest.Exchanger{Auth: office})
	s.ECS = m.ClientSubnet(mustPrefix(t, "198.51.100.0/24"))
	return New(s, dnstest.Exchanger{Auth: up}, stats.New()), up, office
}

func TestForwardedDomains(t *testing.T) {
	r, up, office := forwardTest(t)
	for _, name := range []string{"dc1.corp.test", "DC2.Corp.Test", "corp.test"} {
		res := r.Resolve(dnstest.Query(1, name, m.TypeA, false, false), true)
		if p := dnstest.Parse(t, res.Resp); res.Status != "miss" || p.AN != 1 {
			t.Fatalf("%s: %s %+v", name, res.Status, p)
		}
	}
	if office.Count("dc1.corp.test.") != 1 || up.Count("dc1.corp.test.") != 0 {
		t.Fatal("a forwarded name went to the upstreams")
	}
	// Names around it still go to the upstreams.
	for _, name := range []string{"www.test", "notcorp.test", "corp.test.example"} {
		r.Resolve(dnstest.Query(1, name, m.TypeA, false, false), true)
		if up.Count(name+".") != 1 || office.Count(name+".") != 0 {
			t.Fatalf("%s: upstream %d, office %d", name, up.Count(name+"."), office.Count(name+"."))
		}
	}
	// Cached like any answer.
	if res := r.Resolve(dnstest.Query(2, "dc1.corp.test", m.TypeA, false, false), true); res.Status != "hit" {
		t.Fatalf("second lookup: %s", res.Status)
	}
}

func TestForwardedReverseZone(t *testing.T) {
	r, up, office := forwardTest(t)
	// A private reverse zone that is forwarded goes to its server ...
	res := r.Resolve(dnstest.Query(1, "5.1.0.10.in-addr.arpa", m.TypePTR, false, false), true)
	if res.Status != "miss" || office.Count("5.1.0.10.in-addr.arpa.") != 1 {
		t.Fatalf("forwarded reverse zone answered %s", res.Status)
	}
	// ... the others are still answered here, and nothing leaks.
	res = r.Resolve(dnstest.Query(1, "5.1.168.192.in-addr.arpa", m.TypePTR, false, false), true)
	if res.Status != "local" || up.Count("5.1.168.192.in-addr.arpa.")+office.Count("5.1.168.192.in-addr.arpa.") != 0 {
		t.Fatalf("other private reverse zone: %s", res.Status)
	}
}

func TestForwardedAnswersCarryNoADAndNoSubnet(t *testing.T) {
	r, _, _ := forwardTest(t)
	// signed.test is answered with AD; under corp.test it must lose it.
	s := settings()
	office := dnstest.NewAuth()
	s.Forward = NewForwards("x")
	s.Forward.Add("test", dnstest.Exchanger{Auth: office})
	r = New(s, failing{}, stats.New())
	p := dnstest.Parse(t, r.Resolve(dnstest.Query(1, "signed.test", m.TypeA, true, true), true).Resp)
	if p.AN != 1 || p.AD() {
		t.Fatalf("forwarded answer: an=%d ad=%v", p.AN, p.AD())
	}

	// The client subnet goes to the upstreams only.
	var sawECS []bool
	rec := recorder(func(msg []byte) { sawECS = append(sawECS, hasOption(msg, 8)) })
	s = settings()
	s.ECS = m.ClientSubnet(mustPrefix(t, "198.51.100.0/24"))
	s.Forward = NewForwards("x")
	s.Forward.Add("corp.test", rec)
	r = New(s, rec, stats.New())
	r.Resolve(dnstest.Query(1, "a.corp.test", m.TypeA, false, false), true)
	r.Resolve(dnstest.Query(1, "a.example", m.TypeA, false, false), true)
	if len(sawECS) != 2 || sawECS[0] || !sawECS[1] {
		t.Fatalf("client subnet sent (forwarded, upstream): %v", sawECS)
	}
}

func TestForwardChangeClearsCache(t *testing.T) {
	r, _, office := forwardTest(t)
	r.Resolve(dnstest.Query(1, "dc1.corp.test", m.TypeA, false, false), true)
	s := *r.set.Load()
	r.SetSettings(s) // same servers: kept
	if res := r.Resolve(dnstest.Query(1, "dc1.corp.test", m.TypeA, false, false), true); res.Status != "hit" {
		t.Fatalf("unchanged settings: %s", res.Status)
	}
	s.Forward = NewForwards("two")
	s.Forward.Add("corp.test", dnstest.Exchanger{Auth: office})
	r.SetSettings(s)
	if res := r.Resolve(dnstest.Query(1, "dc1.corp.test", m.TypeA, false, false), true); res.Status != "miss" {
		t.Fatalf("after the servers changed: %s", res.Status)
	}
}

func TestNSID(t *testing.T) {
	s := settings()
	s.ServerID = "fra-1"
	r := New(s, dnstest.Exchanger{Auth: dnstest.NewAuth()}, stats.New())
	ask := func(edns, nsid bool) []byte {
		q := dnstest.Query(1, "a.test", m.TypeA, edns, false)
		if nsid {
			q = m.AddOptions(q, []byte{0, 3, 0, 0})
		}
		return r.Resolve(q, true).Resp
	}
	if got := optionData(ask(true, true), m.OptNSID); string(got) != "fra-1" {
		t.Fatalf("NSID: %q", got)
	}
	if optionData(ask(true, false), m.OptNSID) != nil {
		t.Fatal("NSID sent to a client that did not ask")
	}
	s.ServerID = ""
	r.SetSettings(s)
	if optionData(ask(true, true), m.OptNSID) != nil {
		t.Fatal("NSID sent with no server ID")
	}
}

func TestIDServer(t *testing.T) {
	s := settings()
	s.ServerID = "fra-1"
	r := New(s, failing{}, stats.New())
	for _, name := range []string{"id.server", "hostname.bind", "ID.Server"} {
		q := dnstest.Query(1, name, 16, false, false)
		q[len(q)-1] = 3 // class CHAOS
		p := dnstest.Parse(t, r.Resolve(q, true).Resp)
		if p.Rcode != 0 || p.AN != 1 {
			t.Fatalf("%s: rcode %d, %d answers", name, p.Rcode, p.AN)
		}
	}
	q := dnstest.Query(1, "version.bind", 16, false, false)
	q[len(q)-1] = 3
	if p := dnstest.Parse(t, r.Resolve(q, true).Resp); p.Rcode != m.RcodeRefused {
		t.Fatal("version.bind must stay refused")
	}
	s.ServerID = ""
	r.SetSettings(s)
	q = dnstest.Query(1, "id.server", 16, false, false)
	q[len(q)-1] = 3
	if p := dnstest.Parse(t, r.Resolve(q, true).Resp); p.Rcode != m.RcodeRefused {
		t.Fatal("id.server answered with no server ID")
	}
}

// ---- helpers ----

type recorder func(msg []byte)

func (f recorder) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	f(msg)
	return dnstest.Exchanger{Auth: dnstest.NewAuth()}.Exchange(ctx, msg)
}

// hasOption reports whether msg's OPT record carries option code.
func hasOption(msg []byte, code uint16) bool { return optionData(msg, code) != nil }

// optionData returns the data of an EDNS option in msg (non-nil, possibly
// empty, when present).
func optionData(msg []byte, code uint16) []byte {
	off, err := m.SkipName(msg, m.HeaderLen)
	if err != nil {
		return nil
	}
	n := 0
	for i := 6; i < 12; i += 2 {
		n += int(m.U16(msg, i))
	}
	var out []byte
	m.WalkRRs(msg, off+4, n, func(rr m.RR) error {
		if rr.Type != 41 {
			return nil
		}
		for d := msg[rr.RDOff:rr.End]; len(d) >= 4; {
			c, l := binary.BigEndian.Uint16(d), int(binary.BigEndian.Uint16(d[2:]))
			if 4+l > len(d) {
				break
			}
			if c == code && out == nil {
				out = append([]byte{}, d[4:4+l]...)
			}
			d = d[4+l:]
		}
		return nil
	})
	return out
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
