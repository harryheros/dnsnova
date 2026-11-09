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
	"strings"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// certFor writes a self-signed certificate for names and returns a pool
// trusting it.
func certFor(t *testing.T, dir string, names ...string) *x509.CertPool {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return pool
}

func rcodeOf(t *testing.T, resp []byte) int { return dnstest.Parse(t, resp).Rcode }

func dotAsk(t *testing.T, addr, sni string, pool *x509.CertPool, q []byte) []byte {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, RootCAs: pool, NextProtos: []string{"dot"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
	io.ReadFull(c, msg)
	return msg
}

func tcpAsk(t *testing.T, addr string, q []byte) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
	io.ReadFull(c, msg)
	return msg
}

func dohAsk(t *testing.T, url string, q []byte) (int, []byte) {
	t.Helper()
	// a new connection each time: a reload may close the one used before
	c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Post(url, "application/dns-message", bytes.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

const filterConfig = `[server]
mode = "public"
listen = [%q]
data_dir = %q

[dot]
listen = [%q]

[doh]
listen = %q

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

[filter]
enabled = %v
lists = [%q]
block = ["own.test"]
allow = ["fine.ads.test"]
names = ["filtered.dns.test"]
listen = [%q]
`

func TestTwoDoors(t *testing.T) {
	auth := dnstest.Serve(t)
	dir := t.TempDir()
	pool := certFor(t, dir, "dns.test", "filtered.dns.test")
	list := filepath.Join(dir, "list.txt")
	os.WriteFile(list, []byte("! test list\n||ads.test^\n"), 0o644)
	plain, filtered, dot, doh := freeAddr(t), freeAddr(t), freeAddr(t), freeAddr(t)
	path := filepath.Join(dir, "dnsnova.toml")
	write := func(on bool) {
		os.WriteFile(path, []byte(fmt.Sprintf(filterConfig, plain, dir, dot, doh,
			filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), auth.Addr, on, list, filtered)), 0o640)
	}
	write(true)
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	deadline := time.Now().Add(3 * time.Second)
	for s.FilterStatus().Rules < 2 { // ads.test from the list, own.test from the configuration
		if time.Now().After(deadline) {
			t.Fatalf("list not loaded: %+v", s.FilterStatus())
		}
		time.Sleep(10 * time.Millisecond)
	}

	ads := func(id uint16) []byte { return dnstest.Query(id, "x.ads.test", 1, true, false) }
	other := dnstest.Query(9, "www.example.test", 1, false, false)

	// plain DNS: the usual address answers, the filtered one blocks
	if r, err := udpAsk(t, plain, ads(1), time.Second); err != nil || rcodeOf(t, r) != m.RcodeNoError {
		t.Fatalf("unfiltered UDP: %v", err)
	}
	r, err := udpAsk(t, filtered, ads(2), time.Second)
	if err != nil || rcodeOf(t, r) != m.RcodeNXDomain {
		t.Fatalf("filtered UDP must block: %v", err)
	}
	if r, _ := udpAsk(t, filtered, other, time.Second); dnstest.Parse(t, r).AN != 1 {
		t.Fatal("filtered UDP blocked an unlisted name")
	}
	if r, _ := udpAsk(t, filtered, dnstest.Query(3, "fine.ads.test", 1, false, false), time.Second); rcodeOf(t, r) != m.RcodeNoError {
		t.Fatal("allow rule ignored")
	}
	if r, _ := udpAsk(t, filtered, dnstest.Query(4, "own.test", 1, false, false), time.Second); rcodeOf(t, r) != m.RcodeNXDomain {
		t.Fatal("own block rule ignored")
	}
	if rcodeOf(t, tcpAsk(t, filtered, ads(5))) != m.RcodeNXDomain || rcodeOf(t, tcpAsk(t, plain, ads(6))) != m.RcodeNoError {
		t.Fatal("TCP doors")
	}

	// DoH behind a reverse proxy: by path
	if code, b := dohAsk(t, "http://"+doh+"/dns-query", ads(0)); code != 200 || rcodeOf(t, b) != m.RcodeNoError {
		t.Fatalf("unfiltered DoH: %d", code)
	}
	if code, b := dohAsk(t, "http://"+doh+"/filtered", ads(0)); code != 200 || rcodeOf(t, b) != m.RcodeNXDomain {
		t.Fatalf("filtered DoH path: %d", code)
	}

	// DoT: by the name the client asks for
	if rcodeOf(t, dotAsk(t, dot, "dns.test", pool, ads(7))) != m.RcodeNoError {
		t.Fatal("unfiltered DoT name blocked")
	}
	if rcodeOf(t, dotAsk(t, dot, "filtered.dns.test", pool, ads(8))) != m.RcodeNXDomain {
		t.Fatal("filtered DoT name did not block")
	}
	if n := s.Stats.Sources[4].Load(); n < 5 { // stats.SourceBlocked
		t.Fatalf("blocked answers counted: %d", n)
	}

	// turned off: the filtered address closes and the path is gone
	write(false)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := udpAsk(t, filtered, ads(10), 300*time.Millisecond); err == nil {
		t.Fatal("filtered address still answers after filtering was turned off")
	}
	if code, _ := dohAsk(t, "http://"+doh+"/filtered", ads(0)); code != http.StatusNotFound {
		t.Fatalf("filtered DoH path after turning off: %d", code)
	}
	if rcodeOf(t, dotAsk(t, dot, "filtered.dns.test", pool, ads(11))) != m.RcodeNoError {
		t.Fatal("DoT still filters after turning off")
	}
	if !strings.Contains(fmt.Sprint(s.FilterStatus()), "false") {
		t.Fatalf("status: %+v", s.FilterStatus())
	}
}
