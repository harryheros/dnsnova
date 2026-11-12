package server

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

const clientPath = "/ecs-k3v9q2m8x7w4r1t6y5u0p2z8"

// On ecs.client_path a query goes straight to the recursion, for the
// network it names: not to the cache, local names or filtering, which
// answer on doh.path. (.test is a reserved name, which the recursion
// answers NXDOMAIN itself; what matters is which way the query went.)
func TestClientSubnetPath(t *testing.T) {
	s, _, _ := start(t, `
[recursion]
enabled = true
fallback = false
root_hints = ["127.0.0.1"]

[local]
records = ["geo.test 192.0.2.5"]

[ecs]
client_path = "`+clientPath+`"
`)
	_, _, doh, _ := s.Addrs()
	base := "http://" + doh
	q := dnstest.Query(9, "geo.test", m.TypeA, true, false)
	withECS := m.AddOptions(q, m.ClientSubnet(netip.MustParsePrefix("203.0.113.0/24")))

	code, resp := dohAsk(t, base+"/dns-query", withECS)
	if p := dnstest.Parse(t, resp); code != 200 || p.AN != 1 {
		t.Fatalf("doh.path: %d %+v", code, p)
	}
	code, resp = dohAsk(t, base+clientPath, withECS)
	if p := dnstest.Parse(t, resp); code != 200 || p.AN != 0 || p.Rcode == m.RcodeNoError {
		t.Fatalf("client path answered from the local names: %d %+v", code, p)
	}
	// not cacheable by anyone between
	c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	hr, err := c.Post(base+clientPath, "application/dns-message", strings.NewReader(string(withECS)))
	if err != nil {
		t.Fatal(err)
	}
	hr.Body.Close()
	if hr.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", hr.Header.Get("Cache-Control"))
	}
	// a broken client subnet option is refused
	bad := m.AddOptions(q, []byte{0, 8, 0, 5, 0, 1, 40, 0, 1})
	if code, _ := dohAsk(t, base+clientPath, bad); code != http.StatusBadRequest {
		t.Fatalf("malformed option: %d", code)
	}
	// a near miss of the path is the public page, not a resolver
	if code, _ := dohAsk(t, base+clientPath[:len(clientPath)-1], withECS); code == 200 {
		t.Fatal("a wrong path answered")
	}
}

// Without recursion there is no client path.
func TestClientSubnetPathNeedsRecursion(t *testing.T) {
	s, _, _ := start(t, "")
	_, _, doh, _ := s.Addrs()
	if code, _ := dohAsk(t, "http://"+doh+clientPath, dnstest.Query(9, "geo.test", m.TypeA, true, false)); code == 200 {
		t.Fatal("client path served without recursion")
	}
}
