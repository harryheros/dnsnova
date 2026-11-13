package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

func TestParseH3(t *testing.T) {
	for raw, want := range map[string]Spec{
		"h3://1.1.1.1/dns-query":           {Scheme: "h3", Host: "1.1.1.1", Port: 443, URL: "https://1.1.1.1/dns-query"},
		"h3://dns.google":                  {Scheme: "h3", Host: "dns.google", Port: 443, URL: "https://dns.google/dns-query"},
		"H3://doh.example:8443/q#10.0.0.1": {Scheme: "h3", Host: "doh.example", Port: 8443, URL: "https://doh.example:8443/q", Pin: netip.MustParseAddr("10.0.0.1")},
	} {
		got, err := ParseSpec(raw)
		want.Raw = raw
		if err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", raw, got, err, want)
		}
	}
	for _, bad := range []string{"h3://", "h3://user:pw@dns.example/q", "h3://dns.example/q?x=1", "h3://1.1.1.1#8.8.8.8"} {
		if _, err := ParseSpec(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// TestH3Upstream: an h3:// upstream sends DNS over HTTPS over HTTP/3
// (RFC 8484 over RFC 9114), checks the certificate against the host name
// while connecting to the pinned address, and reuses the connection.
func TestH3Upstream(t *testing.T) {
	auth := dnstest.NewAuth()
	cert, pool := dnstest.SelfSigned(t)
	var h3reqs atomic.Int64
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 3 {
				h3reqs.Add(1)
			}
			body, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || binary.BigEndian.Uint16(body) != 0 {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(auth.Answer(body, false))
		}),
	}
	go srv.Serve(pc)
	t.Cleanup(func() { srv.Close(); pc.Close() })
	port := pc.LocalAddr().(*net.UDPAddr).Port

	s, err := ParseSpec("h3://dns.test:" + strconv.Itoa(port) + "/dns-query#127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	u, err := New(s, NewDialer(nil), &tls.Config{RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for i := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, err := u.Exchange(ctx, m.BuildUpstreamQuery(&m.Query{ID: uint16(100 + i), Name: m.WireName("h3", "test"), Type: 1, Class: 1}, nil))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if r := dnstest.Parse(t, resp); r.AN != 1 {
			t.Fatalf("h3: %+v", r)
		}
	}
	if n := h3reqs.Load(); n != 3 {
		t.Fatalf("%d requests over HTTP/3, want 3", n)
	}

	// the certificate is checked: one for another name is refused
	bad, _ := ParseSpec("h3://other.test:" + strconv.Itoa(port) + "/dns-query#127.0.0.1")
	ub, _ := New(bad, NewDialer(nil), &tls.Config{RootCAs: pool})
	defer ub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := ub.Exchange(ctx, m.BuildUpstreamQuery(&m.Query{Name: m.WireName("h3", "test"), Type: 1, Class: 1}, nil)); err == nil {
		t.Fatal("a certificate for another name was accepted")
	}
}
