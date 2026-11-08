package upstream

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

func TestParseSpec(t *testing.T) {
	ok := map[string]Spec{
		"1.1.1.1":                             {Scheme: "udp", Host: "1.1.1.1", Port: 53},
		"udp://[2606:4700::1111]:5353":        {Scheme: "udp", Host: "2606:4700::1111", Port: 5353},
		"tcp://9.9.9.9":                       {Scheme: "tcp", Host: "9.9.9.9", Port: 53},
		"tls://dns.google":                    {Scheme: "tls", Host: "dns.google", Port: 853},
		"tls://dns.google#8.8.8.8":            {Scheme: "tls", Host: "dns.google", Port: 853, Pin: netip.MustParseAddr("8.8.8.8")},
		"https://dns.google/dns-query":        {Scheme: "https", Host: "dns.google", Port: 443, URL: "https://dns.google/dns-query"},
		"https://1.1.1.1":                     {Scheme: "https", Host: "1.1.1.1", Port: 443, URL: "https://1.1.1.1/dns-query"},
		"https://doh.example:8443/q#10.0.0.1": {Scheme: "https", Host: "doh.example", Port: 8443, URL: "https://doh.example:8443/q", Pin: netip.MustParseAddr("10.0.0.1")},
		"quic://dns.adguard.example":          {Scheme: "quic", Host: "dns.adguard.example", Port: 853},
		"quic://9.9.9.9:8853":                 {Scheme: "quic", Host: "9.9.9.9", Port: 8853},
	}
	for raw, want := range ok {
		got, err := ParseSpec(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		want.Raw = raw
		if got != want {
			t.Errorf("%s: got %+v, want %+v", raw, got, want)
		}
	}
	for _, raw := range []string{
		"ftp://x", "dns.google", "tcp://dns.google", "tls://1.1.1.1#8.8.8.8", "tls://bad_host",
		"https://user:pw@dns.example/q", "https://dns.example/q?x=1", "quic://dns.example/path", "quic://1.1.1.1#8.8.8.8", "tls://x:99999", "tls://dns.google#nope", "",
	} {
		if _, err := ParseSpec(raw); err == nil {
			t.Errorf("%q should be rejected", raw)
		}
	}
}

// fake is an in-process Upstream with a scripted behaviour.
type fake struct {
	name  string
	delay time.Duration
	err   error
	rcode int
	n     atomic.Int32
}

func (f *fake) String() string { return f.name }
func (f *fake) Close()         {}
func (f *fake) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	f.n.Add(1)
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	r := append([]byte(nil), msg...)
	binary.BigEndian.PutUint16(r[2:], uint16(m.FlagQR|f.rcode))
	return r, nil
}

func group(primary, fallback []*fake, parallel int, delay time.Duration) *Group {
	g := &Group{parallel: parallel, timeout: time.Second, delay: delay}
	for _, f := range primary {
		g.primary = append(g.primary, &Member{U: f})
	}
	for _, f := range fallback {
		g.fallback = append(g.fallback, &Member{U: f, Fallback: true})
	}
	return g
}

func ask(t *testing.T, g *Group, timeout time.Duration) ([]byte, error, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	resp, err := g.Exchange(ctx, m.BuildUpstreamQuery(&m.Query{Name: m.WireName("a", "test"), Type: 1, Class: 1}))
	return resp, err, time.Since(start)
}

func TestGroupFallbackOnlyWhenPrimariesFail(t *testing.T) {
	p := &fake{name: "p", delay: 5 * time.Millisecond}
	fb := &fake{name: "fb"}
	g := group([]*fake{p}, []*fake{fb}, 0, 500*time.Millisecond)
	if _, err, _ := ask(t, g, time.Second); err != nil {
		t.Fatal(err)
	}
	if fb.n.Load() != 0 {
		t.Fatal("fallback used although the primary answered")
	}

	// primary errors at once: fallback starts immediately, not after the delay
	p.err = errors.New("refused")
	resp, err, took := ask(t, g, time.Second)
	if err != nil || resp == nil || took > 200*time.Millisecond || fb.n.Load() != 1 {
		t.Fatalf("immediate fallback: err=%v took=%v fb=%d", err, took, fb.n.Load())
	}

	// primary hangs: fallback starts after fallback_delay
	p.err, p.delay = nil, 10*time.Second
	g = group([]*fake{p}, []*fake{fb}, 0, 100*time.Millisecond)
	_, err, took = ask(t, g, 2*time.Second)
	if err != nil || took < 90*time.Millisecond || took > 600*time.Millisecond {
		t.Fatalf("delayed fallback: err=%v took=%v", err, took)
	}
}

func TestGroupSERVFAILIsPassedOnOnlyWhenAllFail(t *testing.T) {
	bad := &fake{name: "bad", rcode: m.RcodeServFail}
	good := &fake{name: "good", delay: 20 * time.Millisecond}
	g := group([]*fake{bad, good}, nil, 0, time.Second)
	resp, err, _ := ask(t, g, time.Second)
	if err != nil || m.Rcode(resp) != 0 {
		t.Fatalf("a good answer must win over SERVFAIL: %v %d", err, m.Rcode(resp))
	}
	good.rcode = m.RcodeServFail
	resp, err, _ = ask(t, g, time.Second)
	if err != nil || m.Rcode(resp) != m.RcodeServFail {
		t.Fatalf("all SERVFAIL: %v %d", err, m.Rcode(resp))
	}
	if g.primary[0].Errors() == 0 || g.primary[0].Healthy() {
		t.Fatal("a SERVFAIL upstream must count errors and be marked unhealthy")
	}
}

func TestGroupPicksFastest(t *testing.T) {
	slow := &fake{name: "slow", delay: 30 * time.Millisecond}
	fast := &fake{name: "fast", delay: time.Millisecond}
	g := group([]*fake{slow, fast}, nil, 1, time.Second)
	for i := 0; i < 40; i++ {
		ask(t, g, time.Second)
	}
	if fast.n.Load() < 30 {
		t.Fatalf("fast upstream used %d of 40 times", fast.n.Load())
	}
	if slow.n.Load() == 0 {
		t.Fatal("slow upstream never re-tried")
	}
}

func TestRealTransports(t *testing.T) {
	srv := dnstest.Serve(t)
	d := NewDialer(nil)
	q := m.BuildUpstreamQuery(&m.Query{Name: m.WireName("huge", "test"), Type: 16, Class: 1})
	for _, raw := range []string{"udp://" + srv.Addr, "tcp://" + srv.Addr} {
		s, err := ParseSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := New(s, d, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		resp, err := u.Exchange(ctx, q)
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if r := dnstest.Parse(t, resp); r.AN != 60 {
			t.Fatalf("%s: %d answers (TCP fallback after truncation?)", raw, r.AN)
		}
	}
}

func TestDoHAndBootstrap(t *testing.T) {
	auth := dnstest.Serve(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if binary.BigEndian.Uint16(body) != 0 {
			t.Error("DoH queries must use ID 0")
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(auth.Answer(body, false))
	}))
	defer ts.Close()
	conf := ts.Client().Transport.(*http.Transport).TLSClientConfig

	// The test certificate is for example.com; pin it to the server address.
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	s, err := ParseSpec("https://example.com:" + port + "/dns-query#127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := New(s, NewDialer(nil), conf)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := u.Exchange(ctx, m.BuildUpstreamQuery(&m.Query{Name: m.WireName("doh", "test"), Type: 1, Class: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if r := dnstest.Parse(t, resp); r.AN != 1 {
		t.Fatalf("doh: %+v", r)
	}

	// bootstrap resolves a host name through the fake server (which answers
	// 1.2.3.4 for any A query) and caches it
	b, err := NewBootstrap([]string{"udp://" + auth.Addr})
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := b.Lookup(ctx, "Upstream.Example.")
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("bootstrap: %v %v", addrs, err)
	}
	b.Lookup(ctx, "upstream.example")
	if n := auth.Count("upstream.example."); n != 2 { // one A and one AAAA query, then cached
		t.Fatalf("bootstrap queried %d times, want 2", n)
	}
	if _, err := NewBootstrap([]string{"https://dns.google/dns-query"}); err == nil {
		t.Fatal("a bootstrap server must be an IP address")
	}
}
