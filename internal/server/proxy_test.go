package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// proxyV2 is a PROXY v2 header for src (dgram or stream).
func proxyV2(src string, dgram bool) []byte {
	ap := netip.MustParseAddrPort(src)
	fam := byte(0x11)
	if dgram {
		fam = 0x12
	}
	a, d := ap.Addr().As4(), [4]byte{127, 0, 0, 1}
	body := append(append(a[:], d[:]...), byte(ap.Port()>>8), byte(ap.Port()), 0, 53)
	h := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, fam, 0, byte(len(body)))
	return append(h, body...)
}

// The server sits behind a load balancer on 127.0.0.1 that sends PROXY
// headers. In private mode only 198.51.100.0/24 may query: an answer shows
// that the client address from the header was used, not the balancer's.
func TestProxyProtocol(t *testing.T) {
	auth := dnstest.Serve(t)
	dir := t.TempDir()
	cert := writeCert(t, dir, "proxy")
	path := filepath.Join(dir, "dnsnova.toml")
	src := fmt.Sprintf(`[server]
mode = "private"
listen = ["127.0.0.1:0"]
data_dir = %q
proxy_protocol = ["127.0.0.0/8"]

[access]
allow = ["198.51.100.0/24"]

[dot]
listen = [%q]

[doh]
https_listen = [%q]
http3 = false

[tls]
certificate = "files"
cert_file = %q
key_file = %q
domains = ["dns.test"]

[upstream]
primary = ["udp://%s"]
bootstrap = []

[limits]
client_qps = 0
prefix_qps = 0
global_qps = 0
rrl_rate = 0
`, dir, freeAddr(t), freeAddr(t), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), auth.Addr)
	os.WriteFile(path, []byte(src), 0o640)
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	udp, tcp, _, _ := s.Addrs()
	dot, https := s.Endpoints()
	q := dnstest.Query(1, "proxied.test", m.TypeA, false, false)

	// UDP: the header gives the client; the answer comes back without one
	resp, err := udpAsk(t, udp[0], append(proxyV2("198.51.100.7:4000", true), q...), 2*time.Second)
	if err != nil {
		t.Fatalf("UDP via the balancer, allowed client: %v", err)
	}
	if p := dnstest.Parse(t, resp); p.ID != 1 || p.AN != 1 {
		t.Fatalf("UDP answer: %+v", p)
	}
	if _, err := udpAsk(t, udp[0], append(proxyV2("203.0.113.9:4000", true), q...), 300*time.Millisecond); err == nil {
		t.Fatal("UDP: a client outside access.allow was answered")
	}
	if _, err := udpAsk(t, udp[0], q, 300*time.Millisecond); err == nil {
		t.Fatal("UDP: a query from the balancer without header was answered")
	}

	// TCP: version 1 and version 2
	tcpAsk := func(header []byte, conn func(net.Conn) net.Conn) error {
		c, err := net.Dial("tcp", tcp[0])
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write(header)
		if conn != nil {
			c = conn(c)
		}
		c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return err
		}
		b := make([]byte, binary.BigEndian.Uint16(lb[:]))
		_, err = io.ReadFull(c, b)
		return err
	}
	if err := tcpAsk([]byte("PROXY TCP4 198.51.100.8 127.0.0.1 4000 53\r\n"), nil); err != nil {
		t.Fatalf("TCP, v1 header: %v", err)
	}
	if err := tcpAsk(proxyV2("198.51.100.9:4000", false), nil); err != nil {
		t.Fatalf("TCP, v2 header: %v", err)
	}
	if err := tcpAsk(nil, nil); err == nil {
		t.Fatal("TCP without header from the balancer was answered")
	}
	if err := tcpAsk([]byte("PROXY TCP4 203.0.113.9 127.0.0.1 4000 53\r\n"), nil); err == nil {
		t.Fatal("TCP: a client outside access.allow was answered")
	}

	// DoT: the header comes before the TLS handshake
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	tcp[0] = dot[0]
	withTLS := func(c net.Conn) net.Conn {
		return tls.Client(c, &tls.Config{ServerName: "dns.test", RootCAs: pool, NextProtos: []string{"dot"}})
	}
	if err := tcpAsk(proxyV2("198.51.100.10:4000", false), withTLS); err != nil {
		t.Fatalf("DoT behind the balancer: %v", err)
	}

	// DoH over HTTPS: the same
	doh := func(header []byte) (int, error) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: "dns.test", RootCAs: pool},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{}).DialContext(ctx, "tcp", https[0])
				if err == nil {
					c.Write(header)
				}
				return c, err
			},
		}
		cl := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		r, err := cl.Get("https://dns.test/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(q))
		if err != nil {
			return 0, err
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode == 200 && dnstest.Parse(t, b).AN != 1 {
			return 0, fmt.Errorf("no answer")
		}
		return r.StatusCode, nil
	}
	if code, err := doh(proxyV2("198.51.100.11:4000", false)); err != nil || code != 200 {
		t.Fatalf("DoH behind the balancer: %d %v", code, err)
	}
	if code, err := doh(proxyV2("203.0.113.9:4000", false)); err == nil && code == 200 {
		t.Fatal("DoH: a client outside access.allow was answered")
	}
	if _, err := doh(nil); err == nil {
		t.Fatal("DoH without header from the balancer was answered")
	}

}
