package resolver

import (
	"net/netip"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

func TestDDRRecordsAndAnswer(t *testing.T) {
	d := DDR{Name: "DNS.Example.com.", DoTPort: 853, DoHPort: 8443, DoHPath: "/dns-query",
		IPv4: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, IPv6: []netip.Addr{netip.MustParseAddr("2001:db8::10")}}
	recs := d.Records()
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	dot := recs[0]
	if m.U16(dot, 0) != 1 {
		t.Fatal("DoT has priority 1")
	}
	target := dnstest.Wire("dns.example.com")
	if string(dot[2:2+len(target)]) != string(target) {
		t.Fatal("target name")
	}
	params := parseParams(t, dot[2+len(target):])
	if string(params[m.SvcALPN]) != "\x03dot" || params[m.SvcPort] != nil || len(params[m.SvcIPv4Hint]) != 4 || len(params[m.SvcIPv6Hint]) != 16 {
		t.Fatalf("dot params: %v", params)
	}
	doh := parseParams(t, recs[1][2+len(target):])
	if string(doh[m.SvcALPN]) != "\x02h2" || m.U16(doh[m.SvcPort], 0) != 8443 || string(doh[m.SvcDoHPath]) != "/dns-query{?dns}" {
		t.Fatalf("doh params: %v", doh)
	}

	r, auth, _ := newTest(t)
	s := settings()
	s.DDR = recs
	r.SetSettings(s)
	res := r.Resolve(dnstest.Query(1, "_dns.resolver.arpa", m.TypeSVCB, true, false), true)
	p := dnstest.Parse(t, res.Resp)
	if res.Status != "local" || p.AN != 2 || p.Types[0] != m.TypeSVCB || p.AD() {
		t.Fatalf("ddr answer: %s %+v", res.Status, p)
	}
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(2, "_dns.resolver.arpa", m.TypeA, false, false), true).Resp); p.Rcode != 0 || p.AN != 0 {
		t.Fatalf("other types: NODATA, got %+v", p)
	}
	s.DDR = nil
	r.SetSettings(s)
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(3, "_dns.resolver.arpa", m.TypeSVCB, false, false), true).Resp); p.AN != 0 || p.Rcode != 0 {
		t.Fatalf("DDR off: %+v", p)
	}
	if auth.Count("_dns.resolver.arpa.") != 0 {
		t.Fatal("resolver.arpa must never go upstream")
	}
}

func parseParams(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	out := map[uint16][]byte{}
	last := -1
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatal("short param")
		}
		k, l := m.U16(b, 0), int(m.U16(b, 2))
		if int(k) <= last {
			t.Fatal("params not in ascending key order")
		}
		last = int(k)
		out[k] = b[4 : 4+l]
		b = b[4+l:]
	}
	return out
}
