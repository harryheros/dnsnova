package resolver

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/filter"
	"github.com/harryheros/dnsnova/internal/stats"
)

func rules(t *testing.T, src string) *filter.Set {
	t.Helper()
	b := filter.NewBuilder()
	if _, err := filter.Parse(strings.NewReader(src), b); err != nil {
		t.Fatal(err)
	}
	return b.Set()
}

// groupTest: the block lists block ads.example; finance (10.1.0.0/24) is
// always filtered and also blocks social.example; lab (10.9.0.0/16) is
// never filtered; boss (10.1.0.9) is in finance's network but its own group.
func groupTest(t *testing.T, up Exchanger) *Resolver {
	t.Helper()
	gs := NewGroups()
	finance := &Group{Name: "finance", Filter: 1, Rules: rules(t, "social.example\n@@||ok.ads.example^\n")}
	gs.Add(netip.MustParsePrefix("10.1.0.0/24"), finance)
	gs.Add(netip.MustParsePrefix("10.9.0.0/16"), &Group{Name: "lab", Filter: -1})
	gs.Add(netip.MustParsePrefix("10.1.0.9/32"), &Group{Name: "boss"})
	s := settings()
	s.Groups = gs
	r := New(s, up, stats.New())
	r.SetFilter(rules(t, "||ads.example^\n"))
	return r
}

func ask(r *Resolver, name, client string, door bool) Result {
	return r.ResolveOpts(dnstest.Query(1, name, 1, false, false), Opts{UDP: true, Filter: door, Client: netip.MustParseAddr(client)})
}

func TestGroupFiltering(t *testing.T) {
	r := groupTest(t, dnstest.Exchanger{Auth: dnstest.NewAuth()})
	cases := []struct {
		name, client string
		door         bool
		status       string
		group        string
	}{
		// finance: filtered on every address, plus its own block rule
		{"x.ads.example", "10.1.0.20", false, "blocked", "finance"},
		{"www.social.example", "10.1.0.20", false, "blocked", "finance"},
		{"ok.ads.example", "10.1.0.20", true, "miss", "finance"}, // its allow rule wins over the lists
		{"www.example", "10.1.0.20", false, "miss", "finance"},
		// lab: never filtered, even on the filtered address
		{"x.ads.example", "10.9.3.4", true, "miss", "lab"},
		// boss: the narrowest network wins; no choice of its own, so the address decides
		{"www.social.example", "10.1.0.9", false, "miss", "boss"},
		{"y.ads.example", "10.1.0.9", false, "miss", "boss"},
		{"z.ads.example", "10.1.0.9", true, "blocked", "boss"},
		// no group: as before
		{"w.ads.example", "192.0.2.1", false, "miss", ""},
		{"v.ads.example", "192.0.2.1", true, "blocked", ""},
		{"v.ads.example", "::ffff:10.1.0.20", false, "blocked", "finance"}, // a mapped IPv4 address
	}
	for _, c := range cases {
		res := ask(r, c.name, c.client, c.door)
		if res.Status != c.status || res.Group != c.group {
			t.Errorf("%s from %s (filtered address %v): %s in %q, want %s in %q", c.name, c.client, c.door, res.Status, res.Group, c.status, c.group)
		}
	}
}

func TestGroupCNAMECloaking(t *testing.T) {
	// Every name is a CNAME to collect.social.example: blocked for finance
	// by its own rule even though the lists do not list it.
	r := groupTest(t, cnameUpstream{"collect.social.example"})
	if res := ask(r, "metrics.shop.test", "10.1.0.20", false); res.Status != "blocked" {
		t.Fatalf("finance: %s", res.Status)
	}
	if res := ask(r, "metrics.shop.test", "10.9.0.1", false); res.Status != "hit" && res.Status != "miss" {
		t.Fatalf("lab: %s", res.Status)
	}
}

func TestGroupBlockIsToldApart(t *testing.T) {
	r := groupTest(t, dnstest.Exchanger{Auth: dnstest.NewAuth()})
	q := dnstest.Query(1, "www.social.example", 1, true, false)
	if res := r.ResolveOpts(q, Opts{UDP: true, Client: netip.MustParseAddr("10.1.0.20")}); !res.BlockedByGroup || !strings.Contains(string(res.Resp), "client's group") {
		t.Fatalf("group rule: by group %v", res.BlockedByGroup)
	}
	if res := ask(r, "x.ads.example", "10.1.0.20", false); res.Status != "blocked" || res.BlockedByGroup {
		t.Fatalf("block lists: %s, by group %v", res.Status, res.BlockedByGroup)
	}
}
