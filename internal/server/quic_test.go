package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/stats"
)

// quicServer runs dnsnova with DoQ and HTTPS (HTTP/2 and HTTP/3) on fresh
// loopback ports and a certificate for dns.test from files.
type quicServer struct {
	*Server
	auth *dnstest.Server
	dir  string
	path string
	pool *x509.CertPool
}

func startQUIC(t *testing.T, limits string) *quicServer {
	t.Helper()
	auth := dnstest.Serve(t)
	dir := t.TempDir()
	cert := writeCert(t, dir, "first")
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	path := filepath.Join(dir, "dnsnova.toml")
	src := fmt.Sprintf(`[server]
mode = "public"
listen = ["127.0.0.1:0"]
data_dir = %q

[doq]
listen = [%q]

[doh]
https_listen = [%q]

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
%s`, dir, freeUDPAddr(t), freeAddr(t), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), auth.Addr, limits)
	if err := os.WriteFile(path, []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	return &quicServer{Server: s, auth: auth, dir: dir, path: path, pool: pool}
}

// edit rewrites the configuration file with old replaced by new and reloads.
func (q *quicServer) edit(t *testing.T, old, new string) {
	t.Helper()
	src, err := os.ReadFile(q.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), old) {
		t.Fatalf("configuration has no %q", old)
	}
	if err := os.WriteFile(q.path, []byte(strings.Replace(string(src), old, new, 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := q.Reload(); err != nil {
		t.Fatal(err)
	}
}

// freeUDPAddr is freeAddr: DoQ and HTTP/3 listen over UDP on addresses that
// TCP listeners share.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	return freeAddr(t)
}

func clientTLS(pool *x509.CertPool, alpn string) *tls.Config {
	return &tls.Config{ServerName: "dns.test", RootCAs: pool, NextProtos: []string{alpn}}
}

func dialQUIC(addr string, conf *tls.Config) (*quic.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return quic.DialAddr(ctx, addr, conf, &quic.Config{HandshakeIdleTimeout: 700 * time.Millisecond})
}

// doqAsk sends one query on a new stream (RFC 9250) and returns the response.
func doqAsk(c *quic.Conn, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	str, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	str.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := str.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
		return nil, err
	}
	str.Close()
	var lb [2]byte
	if _, err := io.ReadFull(str, lb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(str, resp); err != nil {
		return nil, err
	}
	if _, err := io.ReadAll(str); err != nil {
		return nil, fmt.Errorf("stream not finished after the response: %w", err)
	}
	return resp, nil
}

func TestDNSOverQUIC(t *testing.T) {
	q := startQUIC(t, "")
	doq, _ := q.QUICEndpoints()
	if len(doq) != 1 {
		t.Fatalf("doq endpoints: %v", doq)
	}

	// several queries in parallel on one connection, each on its own stream
	c, err := dialQUIC(doq[0], clientTLS(q.pool, "doq"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseWithError(0, "")
	if st := c.ConnectionState(); st.TLS.NegotiatedProtocol != "doq" || st.Used0RTT {
		t.Fatalf("connection state: %+v", st)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := doqAsk(c, dnstest.Query(0, fmt.Sprintf("doq%d.test", i), 1, false, false))
			if err != nil {
				errs <- err
				return
			}
			if m.U16(resp, 0) != 0 || m.U16(resp, 6) != 1 {
				errs <- fmt.Errorf("doq answer %d: id %d, %d answers", i, m.U16(resp, 0), m.U16(resp, 6))
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// a stream carries up to 64 KB: no truncation
	resp, err := doqAsk(c, dnstest.Query(0, "huge.test", 16, true, false))
	if err != nil {
		t.Fatal(err)
	}
	if p := dnstest.Parse(t, resp); p.AN != 60 || p.TC() {
		t.Fatalf("large answer over DoQ: %+v", p)
	}
	if n := q.Stats.Queries[stats.DoQ].Load(); n != 9 {
		t.Fatalf("doq queries counted: %d", n)
	}

	// a Message ID other than 0 is a protocol error that closes the connection
	if _, err := doqAsk(c, dnstest.Query(42, "bad.test", 1, false, false)); err == nil {
		t.Fatal("query with a non-zero ID was answered")
	}
	select {
	case <-c.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("connection still open after a protocol error")
	}
	var ae *quic.ApplicationError
	if err := context.Cause(c.Context()); !errors.As(err, &ae) || ae.ErrorCode != doqProtocolError {
		t.Fatalf("want DOQ_PROTOCOL_ERROR, got %v", err)
	}

	// only the doq ALPN is offered on the DoQ port
	if c, err := dialQUIC(doq[0], clientTLS(q.pool, "h3")); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("DoQ port accepted ALPN h3")
	}

	// a new certificate is served without a restart
	time.Sleep(20 * time.Millisecond)
	cert2 := writeCert(t, q.dir, "second")
	future := time.Now().Add(time.Second)
	os.Chtimes(filepath.Join(q.dir, "cert.pem"), future, future)
	q.Certs.Configure(tlsSettings(q.state.Load().cfg))
	pool2 := x509.NewCertPool()
	pool2.AddCert(cert2)
	c2, err := dialQUIC(doq[0], clientTLS(pool2, "doq"))
	if err != nil {
		t.Fatalf("new certificate not served over QUIC: %v", err)
	}
	c2.CloseWithError(0, "")
}

func TestDoHOverHTTP3(t *testing.T) {
	q := startQUIC(t, "")
	_, h3 := q.QUICEndpoints()
	_, https := q.Endpoints()
	udp, _, _, _ := q.Addrs()
	if len(h3) != 1 || len(https) != 1 || h3[0] != https[0] {
		t.Fatalf("HTTP/3 must share the HTTPS address and port: udp %v tcp %v", h3, https)
	}

	tr := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: "dns.test", RootCAs: q.pool}}
	defer tr.Close()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	url := "https://" + h3[0] + "/dns-query"

	resp, err := client.Post(url, "application/dns-message", bytes.NewReader(dnstest.Query(0, "h3.test", 1, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 3 || resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/dns-message" {
		t.Fatalf("POST over %s: %d %v", resp.Proto, resp.StatusCode, resp.Header)
	}
	if p := dnstest.Parse(t, body); p.AN != 1 {
		t.Fatalf("doh3 answer: %+v", p)
	}
	get := base64.RawURLEncoding.EncodeToString(dnstest.Query(0, "huge.test", 16, false, false))
	resp, err = client.Get(url + "?dns=" + get)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if p := dnstest.Parse(t, body); resp.ProtoMajor != 3 || p.AN != 60 {
		t.Fatalf("GET over %s: %+v", resp.Proto, p)
	}
	resp, err = client.Get("https://" + h3[0] + "/other")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("other paths: %d", resp.StatusCode)
	}

	// HTTP/2 over TCP advertises HTTP/3 on the same port
	h2 := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "dns.test", RootCAs: q.pool}, ForceAttemptHTTP2: true}}
	resp, err = h2.Post("https://"+https[0]+"/dns-query", "application/dns-message", bytes.NewReader(dnstest.Query(0, "h2.test", 1, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	_, port, _ := net.SplitHostPort(https[0])
	if want := `h3=":` + port + `"; ma=86400`; resp.ProtoMajor != 2 || resp.Header.Get("Alt-Svc") != want {
		t.Fatalf("HTTP/2 Alt-Svc %q over %s, want %q", resp.Header.Get("Alt-Svc"), resp.Proto, want)
	}
	if d3, d := q.Stats.Queries[stats.DoH3].Load(), q.Stats.Queries[stats.DoH].Load(); d3 != 2 || d != 1 {
		t.Fatalf("counted doh3=%d doh=%d, want 2 and 1", d3, d)
	}

	// DDR: DoH with h2 and h3, then DoQ
	ddr, err := udpAsk(t, udp[0], dnstest.Query(3, "_dns.resolver.arpa", m.TypeSVCB, true, false), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if p := dnstest.Parse(t, ddr); p.AN != 2 {
		t.Fatalf("ddr: %d records, want DoH and DoQ", p.AN)
	}
	if !bytes.Contains(ddr, []byte("\x02h2\x02h3")) || !bytes.Contains(ddr, []byte("\x03doq")) {
		t.Fatal("DDR does not advertise h3 and doq")
	}
}

// TestNoZeroRTT resumes a session on both QUIC services and checks that the
// resumption works but early data is never accepted.
func TestNoZeroRTT(t *testing.T) {
	q := startQUIC(t, "")
	doq, h3 := q.QUICEndpoints()
	for _, ep := range []struct{ addr, alpn string }{{doq[0], "doq"}, {h3[0], "h3"}} {
		conf := clientTLS(q.pool, ep.alpn)
		conf.ClientSessionCache = tls.NewLRUClientSessionCache(4)
		c, err := dialQUIC(ep.addr, conf)
		if err != nil {
			t.Fatal(err)
		}
		if ep.alpn == "doq" {
			if _, err := doqAsk(c, dnstest.Query(0, "ticket.test", 1, false, false)); err != nil {
				t.Fatal(err)
			}
		} else {
			time.Sleep(100 * time.Millisecond) // let the session ticket arrive
		}
		c.CloseWithError(0, "")

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		early, err := quic.DialAddrEarly(ctx, ep.addr, conf, nil)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		<-early.HandshakeComplete()
		st := early.ConnectionState()
		early.CloseWithError(0, "")
		if !st.TLS.DidResume {
			t.Fatalf("%s: session was not resumed; the test proves nothing", ep.alpn)
		}
		if st.Used0RTT {
			t.Fatalf("%s: 0-RTT was accepted", ep.alpn)
		}
	}
	if q.quicConfig(q.state.Load()).Allow0RTT {
		t.Fatal("QUIC config allows 0-RTT")
	}
}

func TestQUICAccessLimitsAndReload(t *testing.T) {
	q := startQUIC(t, "\n[access]\nallow = [\"203.0.113.0/24\"]\n")
	doq, h3 := q.QUICEndpoints()
	ask := func() error {
		c, err := dialQUIC(doq[0], clientTLS(q.pool, "doq"))
		if err != nil {
			return err
		}
		defer c.CloseWithError(0, "")
		resp, err := doqAsk(c, dnstest.Query(0, "acl.test", 1, false, false))
		if err != nil {
			return err
		}
		if rc := m.Rcode(resp); rc != 0 {
			return fmt.Errorf("rcode %s", m.RcodeString(rc))
		}
		return nil
	}
	if err := ask(); err != nil {
		t.Fatalf("public mode: %v", err)
	}

	// private mode: refused before the handshake, on DoQ and HTTP/3
	q.edit(t, `mode = "public"`, `mode = "private"`)
	start := time.Now()
	if err := ask(); err == nil {
		t.Fatal("DoQ answered a client outside the allow list")
	} else if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("refusal took %v: the connection should be refused, not left to time out", time.Since(start))
	}
	if c, err := dialQUIC(h3[0], clientTLS(q.pool, "h3")); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("HTTP/3 accepted a client outside the allow list")
	}
	q.edit(t, `allow = ["203.0.113.0/24"]`, `allow = ["127.0.0.1/32"]`)
	if err := ask(); err != nil {
		t.Fatalf("allowed client: %v", err)
	}

	// per-client query limit: REFUSED, as over TCP
	q.edit(t, "client_qps = 0", "client_qps = 0.01\nclient_burst = 1")
	if err := ask(); err != nil {
		t.Fatal(err)
	}
	if err := ask(); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("over the client limit: %v", err)
	}
	q.edit(t, "client_qps = 0.01\nclient_burst = 1", "client_qps = 0\nquic_connections = 1")
	// the connections asked on above are closed, but on a busy machine the
	// server may not have counted them out yet (see below)
	for deadline := time.Now().Add(q.snapIdle() + 3*time.Second); q.quicConns.Load() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("closed connections still counted: %d", q.quicConns.Load())
		}
	}

	// connection cap: a second connection is refused while the first is open
	c1, err := dialQUIC(doq[0], clientTLS(q.pool, "doq"))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := dialQUIC(doq[0], clientTLS(q.pool, "doq")); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("connection over limits.quic_connections accepted")
	}
	c1.CloseWithError(0, "")
	// The client's CONNECTION_CLOSE is a single UDP packet. On a busy
	// machine (CI with -race, small socket buffers) it can be dropped; the
	// server then frees the slot when the idle timeout (limits.
	// tcp_idle_timeout, 10s by default) expires. Either way it must free it.
	deadline := time.Now().Add(q.snapIdle() + 3*time.Second)
	for q.quicConns.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("closed connection still counted: %d", q.quicConns.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := ask(); err != nil {
		t.Fatalf("after the first connection closed: %v", err)
	}

	// removing doq.listen closes the port; turning HTTP/3 off keeps HTTPS on TCP
	q.edit(t, "[doq]\nlisten = ", "[doq]\n# listen = ")
	q.edit(t, "[doh]\n", "[doh]\nhttp3 = false\n")
	if d, h := q.QUICEndpoints(); len(d) != 0 || len(h) != 0 {
		t.Fatalf("QUIC listeners left open: %v %v", d, h)
	}
	if c, err := dialQUIC(doq[0], clientTLS(q.pool, "doq")); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("DoQ still answering after removal")
	}
	_, https := q.Endpoints()
	h2 := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "dns.test", RootCAs: q.pool}, ForceAttemptHTTP2: true}}
	resp, err := h2.Post("https://"+https[0]+"/dns-query", "application/dns-message", bytes.NewReader(dnstest.Query(0, "tcp.test", 1, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Alt-Svc") != "" {
		t.Fatalf("HTTPS without HTTP/3: %d, Alt-Svc %q", resp.StatusCode, resp.Header.Get("Alt-Svc"))
	}
}

// TestDoQUpstreamChain forwards from one dnsnova to another over DoQ.
func TestDoQUpstreamChain(t *testing.T) {
	front := startQUIC(t, "")
	doq, _ := front.QUICEndpoints()
	_, port, _ := net.SplitHostPort(doq[0])

	path := filepath.Join(t.TempDir(), "dnsnova.toml")
	writeConfig(t, path, "unused", "")
	src, _ := os.ReadFile(path)
	src = bytes.Replace(src, []byte(`primary = ["udp://unused"]`), []byte(`primary = ["quic://dns.test:`+port+`#127.0.0.1"]`), 1)
	os.WriteFile(path, src, 0o640)
	back, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	back.TLS = &tls.Config{RootCAs: front.pool, MinVersion: tls.VersionTLS13}
	if err := back.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(back.Shutdown)
	udp, _, _, _ := back.Addrs()
	for i, name := range []string{"chain1.test", "chain2.test"} {
		resp, err := udpAsk(t, udp[0], dnstest.Query(uint16(100+i), name, 1, false, false), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if p := dnstest.Parse(t, resp); p.ID != uint16(100+i) || p.AN != 1 {
			t.Fatalf("through the DoQ upstream: %+v", p)
		}
	}
	if n := front.Stats.Queries[stats.DoQ].Load(); n != 2 {
		t.Fatalf("front end saw %d DoQ queries, want 2", n)
	}
	if n := front.quicConns.Load(); n != 1 {
		t.Fatalf("upstream used %d connections, want 1 reused connection", n)
	}
}

// snapIdle is the QUIC idle timeout the server runs with.
func (q *quicServer) snapIdle() time.Duration {
	return q.state.Load().cfg.Limits.TCPIdleTimeout
}
