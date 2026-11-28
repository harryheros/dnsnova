package insight

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func testNOD(learn time.Duration) (*NOD, *fakeClock) {
	c := &fakeClock{}
	c.set(time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC))
	n := NewNOD(0)
	n.now = c.get
	n.cur.Load().start, n.prev.Load().start = c.get(), c.get()
	n.learnUntil.Store(c.get().Add(learn).UnixNano())
	return n, c
}

func TestNODReportsOnce(t *testing.T) {
	n, _ := testNOD(0)
	if !n.Observe("fresh-phish.xyz", "login.fresh-phish.xyz", "A", "10.1.0.23") {
		t.Fatal("a new domain was not reported")
	}
	if n.Observe("fresh-phish.xyz", "cdn.fresh-phish.xyz", "A", "10.1.0.40") {
		t.Fatal("reported twice")
	}
	got := n.Recent()
	if len(got) != 1 || got[0].Domain != "fresh-phish.xyz" || got[0].Name != "login.fresh-phish.xyz" || got[0].Client != "10.1.0.23" {
		t.Fatalf("%+v", got)
	}
	if p := n.TakePending(); len(p) != 1 || len(n.TakePending()) != 0 {
		t.Fatal("pending alerts")
	}
	if n.Observe("1.168.192.in-addr.arpa", "", "PTR", "") || n.Observe("in-addr.arpa (reverse lookups)", "", "PTR", "") {
		t.Fatal("reverse lookups are not domains")
	}
}

func TestNODLearnsFirst(t *testing.T) {
	n, c := testNOD(24 * time.Hour)
	if n.Observe("known.example", "www.known.example", "A", "") || !n.State().Learning {
		t.Fatal("reported while learning")
	}
	c.add(25 * time.Hour)
	if n.Observe("known.example", "www.known.example", "A", "") {
		t.Fatal("a domain learned was reported afterwards")
	}
	if !n.Observe("other.example", "other.example", "A", "") || n.State().Learning {
		t.Fatal("not reporting after learning")
	}
}

func TestNODIgnore(t *testing.T) {
	n, _ := testNOD(0)
	n.SetIgnore([]string{"Corp.Example.", "akamaiedge.net"})
	if n.Observe("corp.example", "x.corp.example", "A", "") || n.Observe("e1.akamaiedge.net", "", "A", "") {
		t.Fatal("ignored domain reported")
	}
	if !n.Observe("notcorp.example", "notcorp.example", "A", "") {
		t.Fatal("a domain merely ending like an ignored one was not reported")
	}
}

func TestNODForgetsUnusedDomains(t *testing.T) {
	n, c := testNOD(0)
	n.Observe("used.example", "", "A", "")
	n.Observe("once.example", "", "A", "")
	c.add(NODPeriod + time.Hour) // period 2: both still known
	if n.Observe("used.example", "", "A", "") || n.Observe("once.example", "", "A", "") {
		t.Fatal("forgotten after one period")
	}
	c.add(NODPeriod) // period 3: used.example was asked in period 2, once.example too (just now)
	if n.Observe("used.example", "", "A", "") {
		t.Fatal("a domain in use was forgotten")
	}
	c.add(2 * NODPeriod) // two periods without it
	if !n.Observe("once.example", "", "A", "") {
		t.Fatal("a domain unused for two periods is still known")
	}
}

func TestNODSaveAndLoad(t *testing.T) {
	n, _ := testNOD(time.Hour)
	for i := 0; i < 1000; i++ {
		n.Observe(fmt.Sprintf("d%d.example", i), "", "A", "")
	}
	path := filepath.Join(t.TempDir(), "nod.bin")
	if err := n.SaveFile(path); err != nil {
		t.Fatal(err)
	}
	m, _ := testNOD(0)
	if err := m.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	m.now = n.now
	if !m.State().Learning {
		t.Fatal("the end of learning was not kept")
	}
	m.learnUntil.Store(0)
	for i := 0; i < 1000; i++ {
		if m.Observe(fmt.Sprintf("d%d.example", i), "", "A", "") {
			t.Fatalf("d%d.example new after loading", i)
		}
	}
	if !m.Observe("never.example", "", "A", "") {
		t.Fatal("a domain never seen is not new after loading")
	}
	var buf bytes.Buffer
	buf.WriteString("garbage")
	if err := m.Load(&buf); err == nil {
		t.Fatal("garbage loaded")
	}
	if m.Observe("d1.example", "", "A", "") {
		t.Fatal("a failed load changed the state")
	}
}

func BenchmarkNODObserveKnown(b *testing.B) {
	n := NewNOD(0)
	n.Observe("www.example.com", "", "A", "")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n.Observe("example.com", "www.example.com", "A", "")
		}
	})
}
