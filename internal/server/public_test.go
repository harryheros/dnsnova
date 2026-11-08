package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

func TestStatusPage(t *testing.T) {
	auth := dnstest.Serve(t)
	dir := t.TempDir()
	cert := writeCert(t, dir, "status")
	path := filepath.Join(dir, "dnsnova.toml")
	conf := func(enabled bool) string {
		return fmt.Sprintf(`[server]
mode = "public"
listen = ["127.0.0.1:0"]
data_dir = %q

[doh]
https_listen = ["127.0.0.1:0"]
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

[status]
enabled = %v
`, dir, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), auth.Addr, enabled)
	}
	os.WriteFile(path, []byte(conf(false)), 0o640)
	store := config.NewStore(path)
	s, err := New(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	_, https := s.Endpoints()
	udp, _, _, _ := s.Addrs()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "dns.test", RootCAs: pool}}}
	get := func(p string) (int, http.Header, string) {
		t.Helper()
		resp, err := client.Get("https://" + https[0] + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}
	probe := func(name string) int {
		t.Helper()
		b, err := udpAsk(t, udp[0], dnstest.Query(7, name, 1, false, false), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return dnstest.Parse(t, b).Rcode
	}

	// Off: nothing but DoH, and check names go upstream like any name.
	if code, _, _ := get("/"); code != 404 {
		t.Fatalf("status page while off: %d", code)
	}
	probe("abcdefghij0123456789.check.dns.test")
	if _, ok := s.ProbeSeen("abcdefghij0123456789"); ok {
		t.Fatal("probe recorded while the page is off")
	}

	os.WriteFile(path, []byte(conf(true)), 0o640)
	snap, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap); err != nil {
		t.Fatal(err)
	}
	code, hdr, body := get("/")
	if code != 200 || !strings.Contains(body, "/assets/status.js") {
		t.Fatalf("GET /: %d %.200s", code, body)
	}
	csp := hdr.Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' data: https://*.check.dns.test;") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP: %s", csp)
	}
	for _, p := range []string{"/assets/status.js", "/assets/app.css", "/assets/theme.js"} {
		if code, _, _ := get(p); code != 200 {
			t.Errorf("GET %s: %d", p, code)
		}
	}
	for _, p := range []string{"/assets/app.js", "/assets/index.html", "/api/v1/status", "/assets/"} {
		if code, _, _ := get(p); code == 200 {
			t.Errorf("GET %s should not be served", p)
		}
	}
	var info map[string]any
	_, _, body = get("/status.json")
	json.Unmarshal([]byte(body), &info)
	if info["domain"] != "dns.test" || info["check"] != true || info["encrypted"] != true || info["query_log"] != false ||
		!strings.HasPrefix(info["doh"].(string), "https://dns.test:") {
		t.Fatalf("status.json: %s", body)
	}

	// The check: over UDP, then over DoH; only the token and protocol are kept.
	if rc := probe("udptoken0123456789ab.check.dns.test"); rc != 3 {
		t.Fatalf("probe rcode %d, want NXDOMAIN", rc)
	}
	if _, _, body := get("/check/udptoken0123456789ab"); !strings.Contains(body, `"proto": "udp"`) || !strings.Contains(body, `"seen": true`) {
		t.Fatalf("check: %s", body)
	}
	resp, err := client.Post("https://"+https[0]+"/dns-query", "application/dns-message", bytes.NewReader(dnstest.Query(0, "dohtoken0123456789ab.check.dns.test", 1, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, _, body := get("/check/dohtoken0123456789ab"); !strings.Contains(body, `"proto": "doh"`) {
		t.Fatalf("doh check: %s", body)
	}
	if _, _, body := get("/check/nevermadeanyquery0000"); !strings.Contains(body, `"seen": false`) {
		t.Fatalf("unknown token: %s", body)
	}
	// Names deeper under the check zone, or short tokens, are not probes.
	probe("a.b0123456789abcdefgh.check.dns.test")
	probe("short.check.dns.test")
	if _, ok := s.ProbeSeen("short"); ok {
		t.Fatal("short token accepted")
	}

	// The Apple profile carries the DoH address.
	code, hdr, body = get("/dnsnova.mobileconfig?p=doh")
	if code != 200 || hdr.Get("Content-Type") != "application/x-apple-aspen-config" ||
		!strings.Contains(body, "<string>"+info["doh"].(string)+"</string>") || !strings.Contains(body, "com.apple.dnsSettings.managed") {
		t.Fatalf("profile: %d %s", code, body)
	}
	if code, _, _ := get("/dnsnova.mobileconfig?p=dot"); code != 404 { // no DoT listener
		t.Fatalf("dot profile without DoT: %d", code)
	}

	// A running query log shows on the page.
	s.QLog.Start(time.Hour, false, time.Now())
	if _, _, body := get("/status.json"); !strings.Contains(body, `"query_log": true`) {
		t.Fatalf("query log not shown: %s", body)
	}
}

// A fresh install runs only the admin interface; DNS starts once setup sets
// addresses and upstreams.
func TestSetupPendingServesNoDNS(t *testing.T) {
	auth := dnstest.Serve(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	os.WriteFile(path, []byte(fmt.Sprintf(`[server]
mode = "public"
listen = []
data_dir = %q

[upstream]
primary = []
bootstrap = []

[admin]
listen = "127.0.0.1:0"
`, dir)), 0o640)
	store := config.NewStore(path)
	s, err := New(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	if udp, _, _, _ := s.Addrs(); len(udp) != 0 || s.AdminAddr() == "" {
		t.Fatalf("udp %v admin %q", udp, s.AdminAddr())
	}
	if len(s.Upstreams()) != 0 {
		t.Fatal("upstreams before setup")
	}
	snap, _ := store.Load()
	out, _ := snap.Doc.Set("server", "listen", config.StrList([]string{"127.0.0.1:0"}))
	doc, err := config.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	out2, _ := doc.Set("upstream", "primary", config.StrList([]string{"udp://" + auth.Addr}))
	snap3, err := store.Write(out2, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap3); err != nil {
		t.Fatal(err)
	}
	udp, _, _, _ := s.Addrs()
	if len(udp) != 1 {
		t.Fatalf("udp after setup: %v", udp)
	}
	b, err := udpAsk(t, udp[0], dnstest.Query(3, "after.test", 1, false, false), 2*time.Second)
	if err != nil || dnstest.Parse(t, b).AN != 1 {
		t.Fatalf("query after setup: %v", err)
	}
}

func TestLocalNamesAndDenyList(t *testing.T) {
	s, auth, _ := start(t, "\n[local]\nrecords = [\"nas.home 192.168.1.5\", \"*.lab.home 10.0.0.9\"]\n")
	udp, _, _, _ := s.Addrs()
	b, err := udpAsk(t, udp[0], dnstest.Query(1, "nas.home", 1, false, false), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if p := dnstest.Parse(t, b); p.AN != 1 || !bytes.Contains(b, []byte{192, 168, 1, 5}) {
		t.Fatalf("nas.home: %+v", p)
	}
	b, _ = udpAsk(t, udp[0], dnstest.Query(2, "x.lab.home", 1, false, false), 2*time.Second)
	if !bytes.Contains(b, []byte{10, 0, 0, 9}) {
		t.Fatal("wildcard not answered")
	}
	if auth.Count("nas.home.") != 0 || auth.Count("x.lab.home.") != 0 {
		t.Fatal("a local name was sent upstream")
	}
	// Blocking the test client's own address: no answer at all.
	snap, _ := s.Store.Load()
	out, _ := snap.Doc.Set("access", "deny", config.StrList([]string{"127.0.0.0/8"}))
	snap2, err := s.Store.Write(out, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap2); err != nil {
		t.Fatal(err)
	}
	if _, err := udpAsk(t, udp[0], dnstest.Query(3, "nas.home", 1, false, false), 500*time.Millisecond); err == nil {
		t.Fatal("a blocked client got an answer")
	}
}
