package server

import (
	"context"
	"strings"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// Forwarding to upstreams, a trace asks each upstream directly.
func TestTraceForwarding(t *testing.T) {
	s, auth, _ := start(t, "")
	tr := s.Trace(context.Background(), string(dnstest.Wire("trace.test")[:len(dnstest.Wire("trace.test"))-1]), m.TypeA)
	if tr.Rcode != "NOERROR" || len(tr.Steps) != 1 || !strings.Contains(tr.Steps[0].Server, auth.Addr) || len(tr.Answers) == 0 {
		t.Fatalf("trace %+v", tr)
	}
	if tr.DNSSEC != "unchecked" || !strings.Contains(tr.Why, "upstreams") {
		t.Fatalf("trace DNSSEC %q %q", tr.DNSSEC, tr.Why)
	}
	d := s.DNSSEC()
	if d.Recursion || d.Failures == nil || d.NTAs == nil {
		t.Fatalf("dnssec %+v", d)
	}
}
