package server

import (
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// TestClientGroups: the usual address is unfiltered, but the clients on
// 127.0.0.0/8 form a group that is always filtered and blocks social.test.
func TestClientGroups(t *testing.T) {
	s, _, _ := start(t, "\n[filter]\nenabled = true\nlists = []\nblock = [\"ads.test\"]\ndoh_path = \"/filtered\"\n")
	udp, _, _, _ := s.Addrs()
	rcode := func(name string) int {
		t.Helper()
		resp, err := udpAsk(t, udp[0], dnstest.Query(1, name, 1, false, false), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return dnstest.Parse(t, resp).Rcode
	}
	for deadline := time.Now().Add(3 * time.Second); s.Filter.Status().Rules == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the block rules never loaded")
		}
	}
	if rcode("x.ads.test") != m.RcodeNoError || rcode("www.social.test") != m.RcodeNoError {
		t.Fatal("without groups the usual address must not filter")
	}

	snap, _ := s.Store.Load()
	out, _ := snap.Doc.Set("clients", "groups", config.StrList([]string{"office 127.0.0.0/8 filter block=social.test"}))
	snap2, err := s.Store.Write(out, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap2); err != nil {
		t.Fatal(err)
	}
	if rcode("y.ads.test") != m.RcodeNXDomain {
		t.Fatal("the group's filtering did not apply")
	}
	if rcode("www2.social.test") != m.RcodeNXDomain {
		t.Fatal("the group's own block rule did not apply")
	}
	if rcode("www.example.test") != m.RcodeNoError {
		t.Fatal("an ordinary name was blocked")
	}
}
