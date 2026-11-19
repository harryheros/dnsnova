package server

import (
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// metricRoles returns the role label of every dnsnova_upstream_* sample.
func metricRoles(t *testing.T, metrics string) map[string]int {
	t.Helper()
	hr, err := http.Get("http://" + metrics + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(hr.Body)
	hr.Body.Close()
	roles := map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^dnsnova_upstream_\w+\{upstream="[^"]*",role="(\w+)"\}`).FindAllStringSubmatch(string(body), -1) {
		roles[m[1]]++
	}
	return roles
}

// With recursion on, the upstreams answer only when no name server does:
// every page and every metric calls them fallbacks. The Upstreams page said
// "primary" while the overview said "fallback", and two of the four metrics
// disagreed with the other two.
func TestUpstreamRoleWithRecursion(t *testing.T) {
	s, _, _ := start(t, "\n[recursion]\nenabled = true\nfallback = true\nroot_hints = [\"127.0.0.1\"]\n")
	ups := s.Upstreams()
	if len(ups) != 1 || ups[0].Role != "fallback" {
		t.Fatalf("upstreams %+v", ups)
	}
	_, _, _, metrics := s.Addrs()
	if roles := metricRoles(t, metrics); roles["primary"] != 0 || roles["fallback"] != 4 {
		t.Fatalf("metric roles %v, want 4 samples, all fallback", roles)
	}
}

func TestUpstreamRoleWithoutRecursion(t *testing.T) {
	s, _, _ := start(t, "")
	if ups := s.Upstreams(); len(ups) != 1 || ups[0].Role != "primary" {
		t.Fatalf("upstreams %+v", ups)
	}
	_, _, _, metrics := s.Addrs()
	if roles := metricRoles(t, metrics); roles["primary"] != 4 || roles["fallback"] != 0 {
		t.Fatalf("metric roles %v", roles)
	}
}

// The public status page keeps counting a healthy upstream as a way to
// answer when recursion is on, as /healthz does, now that it is a fallback.
func TestPublicHealthCountsFallbackUpstreamsWithRecursion(t *testing.T) {
	fb := []admin.Upstream{{Role: "fallback", Healthy: true}}
	if !upstreamsAnswer(fb, true) {
		t.Fatal("with recursion, a healthy fallback answers")
	}
	if upstreamsAnswer(fb, false) {
		t.Fatal("without recursion, a fallback alone is not the answer")
	}
	if upstreamsAnswer([]admin.Upstream{{Role: "primary"}}, false) {
		t.Fatal("a failing primary counted")
	}
	if !upstreamsAnswer([]admin.Upstream{{Role: "primary", Healthy: true}}, false) {
		t.Fatal("a healthy primary did not count")
	}
}

// Saving any setting builds the upstreams afresh; what is known about the
// unchanged ones (counters, latency, health) is kept, not reset.
func TestSettingsChangeKeepsUpstreamCounters(t *testing.T) {
	s, _, _ := start(t, "")
	udp, _, _, _ := s.Addrs()
	if _, err := udpAsk(t, udp[0], dnstest.Query(1, "keep.test", 1, false, false), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	before := s.Upstreams()[0]
	if before.Queries == 0 || before.LatencyMS == 0 {
		t.Fatalf("no query reached the upstream: %+v", before)
	}
	snap, _ := s.Store.Load()
	out, _ := snap.Doc.Set("access", "deny", config.StrList([]string{"198.51.100.0/24"}))
	snap2, err := s.Store.Write(out, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap2); err != nil {
		t.Fatal(err)
	}
	if after := s.Upstreams()[0]; after.Queries != before.Queries || after.LatencyMS != before.LatencyMS {
		t.Fatalf("reset by an unrelated change: %+v, was %+v", after, before)
	}
}
