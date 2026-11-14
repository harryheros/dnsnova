package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

func TestNewlyObservedDomains(t *testing.T) {
	s, _, path := start(t, "\n[nod]\nenabled = true\nlearn = \"0s\"\nignore = [\"quiet.test\"]\n[local]\nrecords = [\"nas.lan.test 192.168.1.5\"]\n")
	udp, _, _, _ := s.Addrs()
	for _, name := range []string{"www.fresh.test", "cdn.fresh.test", "nx.test", "nas.lan.test", "x.quiet.test", "other.example.test"} {
		if _, err := udpAsk(t, udp[0], dnstest.Query(1, name, 1, false, false), 2*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	_, recent, on := s.NOD()
	if !on {
		t.Fatal("off")
	}
	var got []string
	for _, d := range recent {
		got = append(got, d.Domain)
	}
	// fresh.test once; not the NXDOMAIN, the local name or the ignored one.
	if len(got) != 2 || got[0] != "example.test" || got[1] != "fresh.test" || recent[1].Name != "www.fresh.test" || recent[1].Client != "127.0.0.x" {
		t.Fatalf("%v %+v", got, recent)
	}

	// Saved (hashes only), then deleted when turned off.
	s.nodTick()
	file := filepath.Join(filepath.Dir(path), nodFile)
	if b, err := os.ReadFile(file); err != nil || len(b) < 1<<20 {
		t.Fatalf("state not saved: %v", err)
	}
	snap, _ := s.Store.Load()
	out, _ := snap.Doc.Set("nod", "enabled", config.Value{Kind: config.Bool, Bool: false})
	snap2, err := s.Store.Write(out, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("state kept after turning it off")
	}
	if _, _, on := s.NOD(); on {
		t.Fatal("still on")
	}
}
