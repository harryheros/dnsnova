package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// TestForwardZones runs a server whose corp.test names go to an office
// server over real UDP, and checks that a reload with other servers takes
// effect at once.
func TestForwardZones(t *testing.T) {
	office := dnstest.Serve(t)
	s, up, _ := start(t, fmt.Sprintf("\n[local]\nforward = [\"corp.test %s\"]\n", office.Addr))
	udp, _, _, _ := s.Addrs()
	ask := func(name string) {
		t.Helper()
		resp, err := udpAsk(t, udp[0], dnstest.Query(1, name, 1, false, false), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if p := dnstest.Parse(t, resp); p.AN != 1 {
			t.Fatalf("%s: %+v", name, p)
		}
	}
	ask("dc1.corp.test")
	ask("www.test")
	if office.Count("dc1.corp.test.") != 1 || up.Count("dc1.corp.test.") != 0 {
		t.Fatalf("dc1.corp.test: office %d, upstream %d", office.Count("dc1.corp.test."), up.Count("dc1.corp.test."))
	}
	if office.Count("www.test.") != 0 || up.Count("www.test.") != 1 {
		t.Fatal("www.test did not go to the upstream")
	}

	// Another server for corp.test: the cached answer from the old one goes.
	office2 := dnstest.Serve(t)
	snap, _ := s.Store.Load()
	out, _ := snap.Doc.Set("local", "forward", config.StrList([]string{"corp.test " + office2.Addr}))
	snap2, err := s.Store.Write(out, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap2); err != nil {
		t.Fatal(err)
	}
	ask("dc1.corp.test")
	if office2.Count("dc1.corp.test.") != 1 {
		t.Fatal("after the reload, corp.test did not go to the new server")
	}
}

func TestServerID(t *testing.T) {
	var c config.Config
	if serverID(&c) != "" {
		t.Fatal("a single server must not give its name")
	}
	c.Cluster.Role, c.Cluster.Name = "follower", "fra-1"
	if serverID(&c) != "fra-1" {
		t.Fatal("cluster node")
	}
	c.Cluster.Role, c.Anycast.Enabled = "", true
	if serverID(&c) != "fra-1" {
		t.Fatal("anycast node")
	}
}
