package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// doqServer is a minimal RFC 9250 server answering from a fake authority.
type doqServer struct {
	ln    *quic.Listener
	conns atomic.Int32
	last  atomic.Pointer[quic.Conn]
}

func serveDoQ(t *testing.T, auth *dnstest.Auth, cert tls.Certificate) *doqServer {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &doqServer{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			s.conns.Add(1)
			s.last.Store(c)
			go func() {
				for {
					str, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						var lb [2]byte
						io.ReadFull(str, lb[:])
						q := make([]byte, binary.BigEndian.Uint16(lb[:]))
						io.ReadFull(str, q)
						if m.U16(q, 0) != 0 {
							c.CloseWithError(0x2, "message id must be 0")
							return
						}
						if _, err := io.ReadAll(str); err != nil { // the client must send FIN
							t.Errorf("no FIN after the query: %v", err)
						}
						resp := auth.Answer(q, false)
						str.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(resp))), resp...))
						str.Close()
					}()
				}
			}()
		}
	}()
	return s
}

func TestDoQUpstream(t *testing.T) {
	auth := dnstest.NewAuth()
	cert, pool := dnstest.SelfSigned(t)
	srv := serveDoQ(t, auth, cert)
	port := srv.ln.Addr().(*net.UDPAddr).Port

	// a host name pinned to the server: the certificate is checked against dns.test
	s, err := ParseSpec("quic://dns.test:" + strconv.Itoa(port) + "#127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Scheme != "quic" || s.Port != port || s.Host != "dns.test" {
		t.Fatalf("spec: %+v", s)
	}
	if d, _ := ParseSpec("quic://dns.example"); d.Port != 853 {
		t.Fatalf("default DoQ port: %d", d.Port)
	}
	u, err := New(s, NewDialer(nil), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ask := func(name string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		q := m.BuildUpstreamQuery(&m.Query{Name: m.WireName(name, "test"), Type: 1, Class: 1})
		resp, err := u.Exchange(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r := dnstest.Parse(t, resp); r.AN != 1 || r.ID != 0 {
			t.Fatalf("%s: %+v", name, r)
		}
	}
	for _, n := range []string{"a", "b", "c"} {
		ask(n)
	}
	if n := srv.conns.Load(); n != 1 {
		t.Fatalf("%d connections for 3 queries, want 1 (connection reuse)", n)
	}

	// the server goes away: the next query reconnects transparently
	srv.last.Load().CloseWithError(0, "")
	time.Sleep(50 * time.Millisecond)
	ask("d")
	if n := srv.conns.Load(); n != 2 {
		t.Fatalf("%d connections after the server closed one, want 2", n)
	}

	// a server with the wrong certificate is rejected
	bad, err := New(s, NewDialer(nil), &tls.Config{MinVersion: tls.VersionTLS13}) // system roots only
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := bad.Exchange(ctx, m.BuildUpstreamQuery(&m.Query{Name: m.WireName("x", "test"), Type: 1, Class: 1})); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}
