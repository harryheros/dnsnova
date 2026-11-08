package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// writeCert writes a self-signed certificate for dns.test and 127.0.0.1.
func writeCert(t *testing.T, dir, cn string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"dns.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestEncryptedProtocolsAndDDR(t *testing.T) {
	auth := dnstest.Serve(t)
	dir := t.TempDir()
	cert := writeCert(t, dir, "first")
	path := filepath.Join(dir, "dnsnova.toml")
	src := fmt.Sprintf(`[server]
mode = "public"
listen = ["127.0.0.1:0"]
data_dir = %q

[dot]
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
	dot, https := s.Endpoints()
	udp, _, _, _ := s.Addrs()

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	// DoT: ALPN "dot", two pipelined queries
	c, err := tls.Dial("tcp", dot[0], &tls.Config{ServerName: "dns.test", RootCAs: pool, NextProtos: []string{"dot"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ConnectionState().NegotiatedProtocol != "dot" {
		t.Fatal("ALPN dot not negotiated")
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	for _, id := range []uint16{1, 2} {
		q := dnstest.Query(id, "dot.test", 1, false, false)
		c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	}
	for i := 0; i < 2; i++ {
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			t.Fatal(err)
		}
		msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
		io.ReadFull(c, msg)
		if p := dnstest.Parse(t, msg); p.AN != 1 {
			t.Fatalf("dot answer: %+v", p)
		}
	}

	// DoH over HTTPS: HTTP/2
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: "dns.test", RootCAs: pool},
		ForceAttemptHTTP2: true,
	}}
	resp, err := client.Post("https://"+https[0]+"/dns-query", "application/dns-message", bytes.NewReader(dnstest.Query(0, "doh.test", 1, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("DoH served over %s, want HTTP/2", resp.Proto)
	}
	if p := dnstest.Parse(t, body); p.AN != 1 {
		t.Fatalf("doh answer: %+v", p)
	}

	// DDR over plain UDP: two SVCB records naming dns.test
	ddr, err := udpAsk(t, udp[0], dnstest.Query(3, "_dns.resolver.arpa", m.TypeSVCB, true, false), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if p := dnstest.Parse(t, ddr); p.AN != 2 || p.Types[0] != m.TypeSVCB {
		t.Fatalf("ddr: %+v", p)
	}
	if !bytes.Contains(ddr, dnstest.Wire("dns.test")) || !bytes.Contains(ddr, []byte{127, 0, 0, 1}) {
		t.Fatal("DDR target name or address hint missing")
	}

	// metrics count DoT separately
	if n := s.Stats.Queries[2].Load(); n != 2 { // stats.DoT
		t.Fatalf("dot queries counted: %d", n)
	}

	// replacing the certificate files takes effect without a restart
	time.Sleep(20 * time.Millisecond)
	cert2 := writeCert(t, dir, "second")
	future := time.Now().Add(time.Second)
	os.Chtimes(filepath.Join(dir, "cert.pem"), future, future)
	s.Certs.Configure(tlsSettings(s.state.Load().cfg)) // what the minute timer does, without waiting
	pool2 := x509.NewCertPool()
	pool2.AddCert(cert2)
	c2, err := tls.Dial("tcp", dot[0], &tls.Config{ServerName: "dns.test", RootCAs: pool2, NextProtos: []string{"dot"}})
	if err != nil {
		t.Fatalf("new certificate not served: %v", err)
	}
	c2.Close()
}

// freeAddr returns a loopback address with a currently free port (DDR needs
// real port numbers in the configuration).
func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}
