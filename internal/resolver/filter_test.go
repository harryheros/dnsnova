package resolver

import (
	"context"
	"strings"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/filter"
	"github.com/harryheros/dnsnova/internal/stats"
)

func TestFilteredDoorOnly(t *testing.T) {
	st := stats.New()
	r := New(settings(), optUpstream{}, st)
	b := filter.NewBuilder()
	filter.Parse(strings.NewReader("||ads.example^\n@@||ok.ads.example^\n"), b)
	r.SetFilter(b.Set())

	// the unfiltered door answers as always, from the upstream
	if res := r.ResolveOpts(dnstest.Query(1, "x.ads.example", 1, true, false), Opts{UDP: true}); res.Status != "miss" {
		t.Fatalf("unfiltered door: %s", res.Status)
	}
	// the filtered door blocks, even though the answer is now cached
	res := r.ResolveOpts(dnstest.Query(2, "x.ads.example", 1, true, false), Opts{UDP: true, Filter: true})
	p := dnstest.Parse(t, res.Resp)
	if res.Status != "blocked" || res.Source != stats.SourceBlocked || p.Rcode != m.RcodeNXDomain || p.NS != 1 {
		t.Fatalf("filtered door: %s source %d %+v", res.Status, res.Source, p)
	}
	if p.TTLs[0] != BlockedTTL {
		t.Fatalf("blocked TTL %d, want %d", p.TTLs[0], BlockedTTL)
	}
	if code, ok := edeCode(res.Resp); !ok || code != m.EDEBlocked {
		t.Fatalf("EDE %d %v, want Blocked", code, ok)
	}
	if st.Sources[stats.SourceBlocked].Load() != 1 {
		t.Fatal("blocked answer not counted")
	}
	// an exception and an unlisted name pass
	for _, n := range []string{"ok.ads.example", "www.example.net"} {
		if res := r.ResolveOpts(dnstest.Query(3, n, 1, false, false), Opts{UDP: true, Filter: true}); res.Status == "blocked" {
			t.Fatalf("%s blocked", n)
		}
	}
	// no rules: nothing blocked
	r.SetFilter(nil)
	if res := r.ResolveOpts(dnstest.Query(4, "x.ads.example", 1, false, false), Opts{Filter: true}); res.Status == "blocked" {
		t.Fatal("blocked without rules")
	}
}

// cnameUpstream answers every name with a CNAME to target (compressed) and
// an A record for target.
type cnameUpstream struct{ target string }

func (u cnameUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	q, _, _ := m.ParseQuery(msg)
	b := []byte{msg[0], msg[1], 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0}
	b = append(b, msg[m.HeaderLen:q.QEnd]...)
	t := dnstest.Wire(u.target)
	b = append(b, 0xC0, 12, 0, 5, 0, 1, 0, 0, 1, 44, 0, byte(len(t)))
	tOff := len(b)
	b = append(b, t...)
	return append(b, 0xC0|byte(tOff>>8), byte(tOff), 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1), nil
}

func TestFilteredCNAMECloaking(t *testing.T) {
	r := New(settings(), cnameUpstream{"collect.tracker.example"}, stats.New())
	b := filter.NewBuilder()
	filter.Parse(strings.NewReader("||tracker.example^\n@@||allowed.shop.example^\n"), b)
	r.SetFilter(b.Set())
	ask := func(id uint16, name string, o Opts) Result {
		return r.ResolveOpts(dnstest.Query(id, name, 1, false, false), o)
	}
	// unfiltered: answered as usual
	if res := ask(1, "metrics.shop.example", Opts{UDP: true}); res.Status != "miss" {
		t.Fatalf("unfiltered: %s", res.Status)
	}
	// filtered: the disguised tracker is blocked, also from the cache
	for i, name := range []string{"metrics.shop.example", "metrics2.shop.example"} {
		if res := ask(uint16(2+i), name, Opts{UDP: true, Filter: true}); res.Status != "blocked" {
			t.Fatalf("%s through a CNAME to a blocked name: %s", name, res.Status)
		}
	}
	// an explicitly allowed name is not blocked for its CNAME
	if res := ask(5, "allowed.shop.example", Opts{UDP: true, Filter: true}); res.Status == "blocked" {
		t.Fatal("allow rule ignored for a CNAME")
	}
	// a CNAME to an unlisted name passes
	r.SetUpstreams(cnameUpstream{"cdn.example.net"})
	if res := ask(6, "www.shop.example", Opts{UDP: true, Filter: true}); res.Status != "miss" {
		t.Fatalf("CNAME to an unlisted name: %s", res.Status)
	}
}
