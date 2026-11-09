package resolver

import (
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
