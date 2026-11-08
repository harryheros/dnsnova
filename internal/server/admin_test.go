package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

type adminClient struct {
	t    *testing.T
	c    *http.Client
	base string
	csrf string
}

func (a *adminClient) do(method, path string, body any) (int, map[string]any, string) {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	r, err := a.c.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	return r.StatusCode, m, string(raw)
}

func TestAdminAPIEndToEnd(t *testing.T) {
	auth := dnstest.Serve(t)
	dir := t.TempDir()
	cert := writeCert(t, dir, "admin")
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	path := filepath.Join(dir, "dnsnova.toml")
	src := fmt.Sprintf(`# test server
[server]
mode = "public"
listen = ["127.0.0.1:0"]
data_dir = %q

[dot]
listen = [%q]

[tls]
certificate = "files"
cert_file = %q
key_file = %q
domains = ["dns.test"]

[upstream]
primary = ["udp://%s"]
bootstrap = []

[admin]
listen = "127.0.0.1:0"

[limits]
client_qps = 0
prefix_qps = 0
global_qps = 0
rrl_rate = 0
`, dir, freeAddr(t), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), auth.Addr)
	os.WriteFile(path, []byte(src), 0o640)
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.BuildVersion = "v1.2.3-test"
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)

	jar, _ := cookiejar.New(nil)
	ac := &adminClient{t: t, c: &http.Client{Jar: jar, Timeout: 10 * time.Second}, base: "http://" + s.AdminAddr()}
	code, m, raw := ac.do("POST", "/api/v1/setup", map[string]string{"code": s.Admin().SetupCode(), "username": "ops", "password": "a long enough password"})
	if code != 201 {
		t.Fatalf("setup: %d %s", code, raw)
	}
	ac.csrf = m["csrf"].(string)

	// traffic shows up in the statistics
	udp, _, _, _ := s.Addrs()
	for i := 0; i < 5; i++ {
		if _, err := udpAsk(t, udp[0], dnstest.Query(uint16(i), fmt.Sprintf("s%d.test", i), 1, false, false), time.Second); err != nil {
			t.Fatal(err)
		}
	}
	code, m, raw = ac.do("GET", "/api/v1/stats?range=1h", nil)
	if code != 200 || m["queries"].(map[string]any)["udp"].(float64) != 5 {
		t.Fatalf("stats: %d %s", code, raw)
	}
	// One network asked, so no domain is listed; the query log is off and
	// records nothing until it is started.
	if l := m["top_domains"].([]any); len(l) != 0 {
		t.Fatalf("domains from a single network listed: %v", l)
	}
	if s.QLog.State(time.Now()).Count != 0 {
		t.Fatal("query log recorded while off")
	}
	if code, _, raw := ac.do("POST", "/api/v1/querylog", map[string]any{"minutes": 15}); code != 200 {
		t.Fatalf("start query log: %d %s", code, raw)
	}
	if _, err := udpAsk(t, udp[0], dnstest.Query(9, "logged.test", 1, false, false), time.Second); err != nil {
		t.Fatal(err)
	}
	code, m, raw = ac.do("GET", "/api/v1/querylog", nil)
	if e := m["entries"].([]any); code != 200 || len(e) != 1 || e[0].(map[string]any)["client"] != "127.0.0.x" ||
		e[0].(map[string]any)["name"] != "logged.test" || e[0].(map[string]any)["proto"] != "udp" {
		t.Fatalf("query log: %d %s", code, raw)
	}
	ac.do("DELETE", "/api/v1/querylog", nil)
	code, m, raw = ac.do("GET", "/api/v1/status", nil)
	lst := m["listeners"].(map[string]any)
	if code != 200 || m["version"] != "v1.2.3-test" || lst["admin"] == nil || lst["dot"] == nil || m["certificate"].(map[string]any)["ready"] != true {
		t.Fatalf("status: %d %s", code, raw)
	}
	code, m, raw = ac.do("GET", "/api/v1/upstreams", nil)
	if ups := m["upstreams"].([]any); code != 200 || len(ups) != 1 || ups[0].(map[string]any)["healthy"] != true || ups[0].(map[string]any)["queries"].(float64) < 5 {
		t.Fatalf("upstreams: %d %s", code, raw)
	}

	// turning DoQ on through the API opens the port at once
	_, m, _ = ac.do("GET", "/api/v1/config", nil)
	hash := m["hash"].(string)
	doqAddr := freeUDPAddr(t)
	code, m, raw = ac.do("PATCH", "/api/v1/config", map[string]any{"hash": hash, "set": map[string]any{"doq.listen": []string{doqAddr}}})
	if code != 200 {
		t.Fatalf("enable DoQ: %d %s", code, raw)
	}
	hash = m["hash"].(string)
	if doq, _ := s.QUICEndpoints(); len(doq) != 1 {
		t.Fatalf("DoQ not listening: %v", doq)
	}
	c, err := dialQUIC(doqAddr, clientTLS(pool, "doq"))
	if err != nil {
		t.Fatalf("DoQ after enabling it: %v", err)
	}
	c.CloseWithError(0, "")

	// a port that is taken: nothing changes, the file is put back
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	before, _ := os.ReadFile(path)
	code, m, raw = ac.do("PATCH", "/api/v1/config", map[string]any{"hash": hash, "set": map[string]any{"dot.listen": []string{busy.Addr().String()}}})
	if code != 422 || m["reverted"] != true || !strings.Contains(raw, "address already in use") {
		t.Fatalf("busy port: %d %s", code, raw)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) || s.Snapshot().Hash != hash {
		t.Fatal("the configuration file was not restored")
	}
	if dot, _ := s.Endpoints(); len(dot) != 1 {
		t.Fatalf("DoT listener lost: %v", dot)
	}

	// the event log shows who changed what
	_, m, raw = ac.do("GET", "/api/v1/events?limit=50", nil)
	for _, want := range []string{"administrator created", "settings changed user=ops keys=doq.listen", "dnsnova started"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("events lack %q: %s", want, raw)
		}
	}

	// HTTPS on the same port once a certificate exists
	tc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "dns.test"}}}
	req, _ := http.NewRequest("GET", "https://"+s.AdminAddr()+"/api/v1/setup", nil)
	req.Host = "dns.test"
	r, err := tc.Do(req)
	if err != nil {
		t.Fatalf("HTTPS on the admin port: %v", err)
	}
	r.Body.Close()
	if r.StatusCode != 200 || r.TLS == nil {
		t.Fatalf("HTTPS: %d", r.StatusCode)
	}

	// moving the admin port from the admin API itself
	oldAddr := s.AdminAddr()
	newAddr := freeAddr(t)
	code, _, raw = ac.do("PATCH", "/api/v1/config", map[string]any{"hash": hash, "set": map[string]any{"admin.listen": newAddr}})
	if code != 200 {
		t.Fatalf("move admin: %d %s", code, raw)
	}
	if s.AdminAddr() != newAddr {
		t.Fatalf("admin on %s, want %s", s.AdminAddr(), newAddr)
	}
	ac.base = "http://" + newAddr
	if code, _, raw := ac.do("GET", "/api/v1/session", nil); code != 200 {
		t.Fatalf("session on the new port: %d %s", code, raw)
	}
	deadline := time.Now().Add(6 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", oldAddr, 200*time.Millisecond); err != nil {
			break
		} else {
			c.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("old admin port still open")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
