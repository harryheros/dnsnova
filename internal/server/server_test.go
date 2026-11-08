package server

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

func writeConfig(t *testing.T, path, upstream, extra string) {
	t.Helper()
	src := fmt.Sprintf(`[server]
mode = "public"
listen = ["127.0.0.1:0"]
data_dir = %q

[doh]
listen = "127.0.0.1:0"

[metrics]
listen = "127.0.0.1:0"

[upstream]
primary = ["udp://%s"]
bootstrap = []
timeout = "2s"

[limits]
client_qps = 0
prefix_qps = 0
global_qps = 0
rrl_rate = 0
%s`, filepath.Dir(path), upstream, extra)
	if err := os.WriteFile(path, []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
}

// start runs a server; extra is appended to the [limits] table, so further
// tables can follow it.
func start(t *testing.T, extra string) (*Server, *dnstest.Server, string) {
	t.Helper()
	auth := dnstest.Serve(t)
	path := filepath.Join(t.TempDir(), "dnsnova.toml")
	writeConfig(t, path, auth.Addr, extra)
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	return s, auth, path
}

func udpAsk(t *testing.T, addr string, q []byte, wait time.Duration) ([]byte, error) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(wait))
	c.Write(q)
	b := make([]byte, 65535)
	n, err := c.Read(b)
	return b[:n], err
}

func TestEndToEnd(t *testing.T) {
	s, _, _ := start(t, "")
	udp, tcp, doh, metrics := s.Addrs()

	resp, err := udpAsk(t, udp[0], dnstest.Query(7, "e2e.test", 1, true, false), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if p := dnstest.Parse(t, resp); p.ID != 7 || p.AN != 1 {
		t.Fatalf("udp: %+v", p)
	}

	// TCP: two pipelined queries on one connection
	c, err := net.Dial("tcp", tcp[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	for _, id := range []uint16{8, 9} {
		q := dnstest.Query(id, "huge.test", 16, false, false)
		c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	}
	seen := map[uint16]bool{}
	for i := 0; i < 2; i++ {
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			t.Fatal(err)
		}
		msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
		io.ReadFull(c, msg)
		p := dnstest.Parse(t, msg)
		if p.AN != 60 {
			t.Fatalf("tcp answers %d", p.AN)
		}
		seen[p.ID] = true
	}
	if !seen[8] || !seen[9] {
		t.Fatal("pipelined responses missing")
	}

	// DoH GET and POST
	base := "http://" + doh + "/dns-query"
	q := base64.RawURLEncoding.EncodeToString(dnstest.Query(0, "e2e.test", 1, false, false))
	hr, err := http.Get(base + "?dns=" + q)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(hr.Body)
	hr.Body.Close()
	if hr.StatusCode != 200 || hr.Header.Get("Content-Type") != "application/dns-message" || hr.Header.Get("Cache-Control") == "max-age=0" {
		t.Fatalf("doh get: %d %v", hr.StatusCode, hr.Header)
	}
	if p := dnstest.Parse(t, body); p.AN != 1 {
		t.Fatalf("doh get: %+v", p)
	}
	hr, err = http.Post(base, "application/dns-message", bytes.NewReader(dnstest.Query(0, "huge.test", 16, true, false)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(hr.Body)
	hr.Body.Close()
	if p := dnstest.Parse(t, body); p.AN != 60 || p.TC() {
		t.Fatalf("doh post: %+v", p)
	}

	// metrics and health
	hr, _ = http.Get("http://" + metrics + "/metrics")
	body, _ = io.ReadAll(hr.Body)
	hr.Body.Close()
	for _, want := range []string{`dnsnova_queries_total{proto="doh"} 2`, `dnsnova_answers_total{source="cache"}`, `dnsnova_upstream_healthy{upstream=`, `dnsnova_response_seconds_bucket{source="upstream",le="+Inf"}`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	hr, _ = http.Get("http://" + metrics + "/healthz")
	var h map[string]any
	json.NewDecoder(hr.Body).Decode(&h)
	hr.Body.Close()
	if hr.StatusCode != 200 || h["status"] != "ok" {
		t.Fatalf("health: %d %v", hr.StatusCode, h)
	}
}

func TestPrivateMode(t *testing.T) {
	s, _, _ := start(t, "\n[access]\nallow = [\"203.0.113.0/24\"]\n")
	// switch to private mode through the store, as the admin API will
	snap, _ := s.Store.Load()
	out, _ := snap.Doc.Set("server", "mode", config.Str("private"))
	snap2, err := s.Store.Write(out, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap2); err != nil {
		t.Fatal(err)
	}
	udp, tcp, doh, _ := s.Addrs()
	if _, err := udpAsk(t, udp[0], dnstest.Query(1, "a.test", 1, false, false), 300*time.Millisecond); err == nil {
		t.Fatal("a client outside the allow list got a UDP answer")
	}
	c, err := net.Dial("tcp", tcp[0])
	if err == nil {
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("TCP connection from a denied client stayed open")
		}
		c.Close()
	}
	get := func(realIP string) int {
		q := base64.RawURLEncoding.EncodeToString(dnstest.Query(0, "a.test", 1, false, false))
		req, _ := http.NewRequest("GET", "http://"+doh+"/dns-query?dns="+q, nil)
		req.Header.Set("X-Real-IP", realIP)
		hr, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		hr.Body.Close()
		return hr.StatusCode
	}
	if code := get("198.51.100.1"); code != 403 {
		t.Fatalf("doh outside allow list: %d", code)
	}
	if code := get("203.0.113.9"); code != 200 {
		t.Fatalf("doh inside allow list: %d", code)
	}
}

func TestRateLimitAndRRL(t *testing.T) {
	s, _, path := start(t, "")
	udp, _, _, _ := s.Addrs()
	cfg, _ := os.ReadFile(path)
	limited := strings.Replace(string(cfg), "client_qps = 0", "client_qps = 0.01\nclient_burst = 3", 1)
	os.WriteFile(path, []byte(limited), 0o640)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	got := 0
	for i := 0; i < 5; i++ {
		if _, err := udpAsk(t, udp[0], dnstest.Query(uint16(i), "rl.test", 1, false, false), 200*time.Millisecond); err == nil {
			got++
		}
	}
	if got != 3 {
		t.Fatalf("client limit: %d answers, want 3", got)
	}

	rrl := strings.Replace(string(cfg), "rrl_rate = 0", "rrl_rate = 0.01\nrrl_slip = 2", 1)
	os.WriteFile(path, []byte(rrl), 0o640)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for i := 0; i < 5; i++ {
		resp, err := udpAsk(t, udp[0], dnstest.Query(uint16(i), "same.test", 1, false, false), 200*time.Millisecond)
		switch {
		case err != nil:
			kinds = append(kinds, "drop")
		case dnstest.Parse(t, resp).TC():
			kinds = append(kinds, "slip")
		default:
			kinds = append(kinds, "send")
		}
	}
	// burst = rate rounded up to 1: one answer, then alternating drop/slip
	if strings.Join(kinds, ",") != "send,drop,slip,drop,slip" {
		t.Fatalf("rrl sequence: %v", kinds)
	}
}

func TestHotReload(t *testing.T) {
	s, auth, path := start(t, "")
	udp, _, _, _ := s.Addrs()
	if _, err := udpAsk(t, udp[0], dnstest.Query(1, "warm.test", 1, false, false), time.Second); err != nil {
		t.Fatal(err)
	}

	// point at a different upstream: cached answers survive the reload
	other := dnstest.Serve(t)
	other.ServFail.Store(true)
	writeConfig(t, path, other.Addr, "")
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	resp, _ := udpAsk(t, udp[0], dnstest.Query(2, "warm.test", 1, false, false), time.Second)
	if p := dnstest.Parse(t, resp); p.Rcode != 0 || p.AN != 1 {
		t.Fatal("cache lost on reload")
	}
	resp, _ = udpAsk(t, udp[0], dnstest.Query(3, "new.test", 1, false, false), time.Second)
	if p := dnstest.Parse(t, resp); p.Rcode != m.RcodeServFail || auth.Count("new.test.") != 0 {
		t.Fatal("new upstream not used after reload")
	}

	// a broken file is rejected and the running configuration stays
	os.WriteFile(path, []byte("[server]\nmode = \"oops\"\n"), 0o640)
	if err := s.Reload(); err == nil {
		t.Fatal("invalid configuration applied")
	}
	if _, err := udpAsk(t, udp[0], dnstest.Query(4, "warm.test", 1, false, false), time.Second); err != nil {
		t.Fatal("server stopped answering after a failed reload")
	}

	// the file watcher picks up a valid change by itself
	writeConfig(t, path, auth.Addr, "\n[log]\nqueries = true\n")
	go s.WatchConfig(50 * time.Millisecond)
	deadline := time.Now().Add(3 * time.Second)
	for !s.state.Load().cfg.Log.Queries {
		if time.Now().After(deadline) {
			t.Fatal("file change not picked up")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
