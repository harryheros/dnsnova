package server

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// A panic while answering one query becomes SERVFAIL for that query, not a
// crash of the server. (A Server without a resolver panics on any lookup.)
func TestQueryPanicAnsweredServfail(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	q := dnstest.Query(7, "example.com.", m.TypeA, false, false)
	res := s.resolve(q, netip.Addr{}, true, "udp", false)
	if res.Resp == nil {
		t.Fatal("no answer after a panic")
	}
	if r := dnstest.Parse(t, res.Resp); r.Rcode != m.RcodeServFail || r.ID != 7 {
		t.Fatalf("got rcode %d id %d, want SERVFAIL for id 7", r.Rcode, r.ID)
	}
	res, ok := s.resolveCached(q, netip.Addr{}, true, "udp", false)
	if !ok || res.Resp == nil {
		t.Fatal("cached path: no answer after a panic")
	}
	if res, _ := s.resolveCached([]byte{1, 2}, netip.Addr{}, true, "udp", false); res.Resp != nil {
		t.Fatal("answered a packet that does not parse")
	}
}
