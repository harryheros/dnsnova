package dnstap

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestInterop sends to a real collector at $DNSTAP_INTEROP (skipped
// without it), such as: dnstap_receiver -u /tmp/rx.sock -v
func TestInterop(t *testing.T) {
	target := os.Getenv("DNSTAP_INTEROP")
	if target == "" {
		t.Skip("set DNSTAP_INTEROP=unix:/path to a collector's socket")
	}
	s := New()
	s.Configure(Settings{Target: target, Queries: true, Responses: true, FullIP: true, Identity: "dnsnova-interop", Version: "DNSNova test"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	waitConnected(t, s)
	s.Add(event("dot", "192.0.2.10:5353"))
	time.Sleep(time.Second)
	cancel()
	<-done
	if st := s.State(); st.Sent != 2 || st.Errors != 0 {
		t.Fatalf("%+v", st)
	}
}
