package resolver

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/stats"
)

// addrUpstream answers every A and AAAA query with the address it has for
// the name.
type addrUpstream map[string]string

func (u addrUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	q, _, _ := m.ParseQuery(msg)
	name := strings.TrimSuffix(m.NameString(q.Name), ".")
	a := netip.MustParseAddr(u[name])
	b := []byte{msg[0], msg[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	b = append(b, msg[m.HeaderLen:q.QEnd]...)
	if a.Is4() {
		return append(append(b, 0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4), a.AsSlice()...), nil
	}
	return append(append(b, 0xC0, 12, 0, 28, 0, 1, 0, 0, 1, 44, 0, 16), a.AsSlice()...), nil
}

// A name from outside that answers with an address of a private network
// gets no address (DNS rebinding protection), also from the cache; the
// network's own names, and names the administrator allowed, are answered.
func TestRebindingProtection(t *testing.T) {
	up := addrUpstream{
		"attacker.example":  "192.168.1.1",
		"loopback.example":  "127.0.0.1",
		"ula.example":       "fd00::1",
		"mapped.example":    "::ffff:10.0.0.1",
		"cgnat.example":     "100.64.0.7",
		"public.example":    "93.184.216.34",
		"sinkhole.example":  "0.0.0.0",
		"nas.lan":           "192.168.1.5",
		"printer.home.arpa": "192.168.1.6",
		"router":            "192.168.1.1",
		"nas.example.com":   "192.168.1.5",
		"dc1.corp.example":  "10.0.0.10",
		"other.example.com": "192.168.1.7",
	}
	s := settings()
	s.Rebinding = NewRebinding([]string{"nas.example.com"})
	s.Forward = NewForwards("corp")
	s.Forward.Add("corp.example", up)
	r := New(s, up, stats.New())
	ask := func(name string, qtype uint16) Result {
		return r.ResolveOpts(dnstest.Query(7, name, qtype, false, false), Opts{UDP: true})
	}
	for _, c := range []struct {
		name    string
		qtype   uint16
		refused bool
	}{
		{"attacker.example", m.TypeA, true},
		{"loopback.example", m.TypeA, true},
		{"ula.example", m.TypeAAAA, true},
		{"mapped.example", m.TypeAAAA, true},
		{"cgnat.example", m.TypeA, true},
		{"other.example.com", m.TypeA, true}, // only nas.example.com is allowed
		{"public.example", m.TypeA, false},
		{"sinkhole.example", m.TypeA, false},
		{"nas.lan", m.TypeA, false},
		{"printer.home.arpa", m.TypeA, false},
		{"router", m.TypeA, false},
		{"nas.example.com", m.TypeA, false},
		{"dc1.corp.example", m.TypeA, false},
	} {
		for round := range 2 { // fetched, then from the cache
			res := ask(c.name, c.qtype)
			p := dnstest.Parse(t, res.Resp)
			if c.refused != res.Rebinding || c.refused && (p.Rcode != m.RcodeNoError || p.AN != 0 || res.Status != "rebinding") || !c.refused && p.AN != 1 {
				t.Fatalf("%s (round %d): status %s, rebinding %v, %+v", c.name, round, res.Status, res.Rebinding, p)
			}
		}
	}

	// off: answered as they are
	s.Rebinding = nil
	r.SetSettings(s)
	if res := ask("attacker.example", m.TypeA); res.Rebinding || dnstest.Parse(t, res.Resp).AN != 1 {
		t.Fatalf("protection off: %s", res.Status)
	}
}
