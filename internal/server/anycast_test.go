package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// anycastServer runs a server whose anycast commands append a word to a
// file, so the test can read what was run and in which order.
func anycastServer(t *testing.T, announce string) (*Server, string, *atomic.Bool) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "routes")
	extra := fmt.Sprintf(`
[anycast]
enabled = true
announce = ["sh", "-c", %q]
withdraw = ["sh", "-c", "echo withdraw >> %s"]
interval = "100ms"
rise = 2
fall = 3
drain = "300ms"
`, announce, log)
	if announce == "" {
		extra = strings.Replace(extra, `announce = ["sh", "-c", ""]`, fmt.Sprintf(`announce = ["sh", "-c", "echo announce >> %s"]`, log), 1)
	}
	healthy := &atomic.Bool{}
	healthy.Store(true)
	s, _, _ := start(t, extra)
	s.any.mu.Lock()
	s.any.testHealth = healthy.Load
	s.any.mu.Unlock()
	return s, log, healthy
}

func routes(path string) string {
	b, _ := os.ReadFile(path)
	return strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", " ")
}

// Withdrawn at start, announced after rise good checks, withdrawn after
// fall bad ones, announced again when healthy; at shutdown withdrawn first
// and still answering for drain.
func TestAnycastRiseFallDrain(t *testing.T) {
	s, log, healthy := anycastServer(t, "")
	eventually(t, "announced", func() bool { return routes(log) == "withdraw announce" })
	if s.anycastState() != anycastAnnounced || s.nodeReport().Anycast != anycastAnnounced {
		t.Fatalf("state %q", s.anycastState())
	}
	healthy.Store(false)
	eventually(t, "withdrawn", func() bool { return routes(log) == "withdraw announce withdraw" })
	healthy.Store(true)
	eventually(t, "announced again", func() bool { return routes(log) == "withdraw announce withdraw announce" })

	// one failed check is not enough to withdraw (fall = 3)
	healthy.Store(false)
	time.Sleep(150 * time.Millisecond)
	healthy.Store(true)
	time.Sleep(400 * time.Millisecond)
	if routes(log) != "withdraw announce withdraw announce" {
		t.Fatalf("a single failed check changed the route: %s", routes(log))
	}

	udp, _, _, _ := s.Addrs()
	start := time.Now()
	answered := make(chan bool, 1)
	go func() {
		time.Sleep(100 * time.Millisecond) // during the drain
		_, q := probeQuery()
		_, err := udpAsk(t, udp[0], q, time.Second)
		answered <- err == nil
	}()
	s.Shutdown()
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("shutdown took %v: no drain", d)
	}
	if !<-answered {
		t.Fatal("not answering while draining")
	}
	if !strings.HasSuffix(routes(log), "announce withdraw") {
		t.Fatalf("not withdrawn at shutdown: %s", routes(log))
	}
}

// A command that fails is tried again at the next check.
func TestAnycastRetriesFailedCommand(t *testing.T) {
	dir := t.TempDir()
	marker, log := filepath.Join(dir, "tried"), filepath.Join(dir, "ok")
	script := fmt.Sprintf("if [ -e %s ]; then echo announce >> %s; else touch %s; exit 1; fi", marker, log, marker)
	s, _, _ := anycastServer(t, script)
	eventually(t, "announced after one failure", func() bool { return routes(log) == "announce" && s.anycastState() == anycastAnnounced })
}

// The probe goes through the server's own UDP socket: with the listener
// gone the check fails even when everything else is fine.
func TestAnycastProbe(t *testing.T) {
	s, _, _ := start(t, "")
	if !probeUDP(t.Context(), s.probeAddr()) {
		t.Fatal("probe of a running server failed")
	}
	addr := s.probeAddr()
	s.Shutdown()
	if probeUDP(t.Context(), addr) {
		t.Fatal("probe passed with the listener closed")
	}
}

// The probe accepts only an answer to its own question: a reply with the
// same ID that is not a response, has no question or another one fails.
func TestProbeAnsweredChecksTheReply(t *testing.T) {
	_, q := probeQuery()
	good := append([]byte{}, q...)
	good[2] |= 0x80 // QR
	if !probeAnswered(q, good) {
		t.Fatal("a proper answer refused")
	}
	notResp := append([]byte{}, q...)
	noQ := append([]byte{}, good[:m.HeaderLen]...)
	noQ[5] = 0
	other := append([]byte{}, good...)
	other[m.HeaderLen+1] = 'x'
	badID := append([]byte{}, good...)
	badID[1]++
	for name, b := range map[string][]byte{"not a response": notResp, "no question": noQ, "another question": other, "another ID": badID} {
		if probeAnswered(q, b) {
			t.Fatalf("%s accepted", name)
		}
	}
}

// Without a UDP listener, the probe asks over TCP; a closed listener fails
// it.
func TestAnycastProbeOverTCP(t *testing.T) {
	s, _, _ := start(t, "")
	addr := s.probeStreamAddr(false)
	if !addr.IsValid() {
		t.Skip("no TCP listener in the test server")
	}
	if !probeStream(t.Context(), addr, false, false) {
		t.Fatal("TCP probe of a running server failed")
	}
	s.Shutdown()
	if probeStream(t.Context(), addr, false, false) {
		t.Fatal("TCP probe passed with the listener closed")
	}
}
