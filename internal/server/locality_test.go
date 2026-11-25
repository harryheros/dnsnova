package server

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

const measurePath = "/exit-k3v9q2m8x7w4r1t6y5u0p2z8"

// chQuery asks CH TXT name.
func chQuery(name string) []byte {
	q := dnstest.Query(5, name, 16, false, false)
	q[len(q)-1] = 3
	return q
}

// Private locality on a running server: the measurement path asks through
// the exit named after it (and only an exit that exists), the diagnostic
// name tells a client its view, and the admin interface shows the exits.
// (.test is a reserved name the recursion answers itself: what matters is
// which way the query went, not what the exit got.)
func TestLocalityServer(t *testing.T) {
	s, _, _ := start(t, `
[recursion]
enabled = true
fallback = false
root_hints = ["127.0.0.1"]

[locality]
enabled = true
exits = ["exit-a 10.66.1.2 127.0.0.0/8", "exit-b 10.66.2.2 192.0.2.0/24"]
measure_path = "`+measurePath+`"
`)
	_, _, doh, _ := s.Addrs()
	base := "http://" + doh
	q := dnstest.Query(9, "geo.test", m.TypeA, true, false)
	code, resp := dohAsk(t, base+measurePath+"/exit-a", q)
	if p := dnstest.Parse(t, resp); code != 200 || p.Rcode != m.RcodeNXDomain {
		t.Fatalf("through exit-a: %d %+v", code, p)
	}
	if code, _ := dohAsk(t, base+measurePath+"/nope", q); code != http.StatusNotFound {
		t.Fatalf("unknown exit: %d", code)
	}
	if code, _ := dohAsk(t, base+measurePath, q); code == 200 {
		t.Fatal("the path without an exit answered")
	}
	code, resp = dohAsk(t, base+"/dns-query", chQuery("locality.server"))
	if code != 200 || !bytes.Contains(resp, []byte("view=exit-a")) || !bytes.Contains(resp, []byte("by=127.0.0.0/8")) {
		t.Fatalf("diagnostic name: %d %q", code, resp)
	}
	l := s.Locality()
	if !l.Enabled || len(l.Exits) != 2 || l.Exits[0].Name != "exit-a" || l.Exits[0].Serves[0] != "127.0.0.0/8" || !l.Exits[0].Up {
		t.Fatalf("%+v", l)
	}
	if l.Countries != nil {
		t.Fatal("no exit serves countries: no country table should be downloaded")
	}
	// the siting report counts the queries answered from the cache or asked
	code, _ = dohAsk(t, base+"/dns-query", q)
	if rows := s.Locality().Report; code != 200 || len(rows) != 1 || rows[0].Queries == 0 {
		t.Fatalf("report %+v", rows)
	}
}

// A country table comes from the registries' files (here a local one), and
// places clients by country; turned off, the table and counts are dropped.
func TestLocalityCountries(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("apnic|XA|ipv4|127.0.0.0|16777216|20100101|allocated|X\n")
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "apnic|XB|ipv4|10.%d.%d.0|256|20100101|allocated|Y\n", i/256, i%256)
	}
	reg := filepath.Join(dir, "apnic.txt")
	os.WriteFile(reg, []byte(b.String()), 0o600)
	s, _, path := start(t, `
[recursion]
enabled = true
fallback = false
root_hints = ["127.0.0.1"]

[locality]
enabled = true
exits = ["exit-a 10.66.1.2 XA"]
country_sources = ["`+reg+`"]
`)
	_, _, doh, _ := s.Addrs()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, resp := dohAsk(t, "http://"+doh+"/dns-query", chQuery("locality.server"))
		if bytes.Contains(resp, []byte("view=exit-a")) && bytes.Contains(resp, []byte("by=XA")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not placed by country: %q", resp)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if c := s.Locality().Countries; c == nil || c.Blocks == 0 {
		t.Fatalf("country status %+v", c)
	}
	// off: nothing kept
	src, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.Replace(src, []byte("enabled = true\nexits"), []byte("enabled = false\nexits"), 1), 0o640)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.loc.countries.Load() != nil || s.Locality().Enabled || s.Rec.Locality() != nil {
		t.Fatal("still on after being turned off")
	}
}

// [locality] is the node's own (its exits are its own tunnels): it is
// neither taken from a primary nor changed through the admin API.
func TestLocalityIsNodeLocal(t *testing.T) {
	for _, list := range [][]string{config.NodeLocalTables, config.FileOnlyTables} {
		found := false
		for _, x := range list {
			found = found || x == "locality"
		}
		if !found {
			t.Fatalf("locality missing from %v", list)
		}
	}
}
