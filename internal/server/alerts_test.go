package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/alert"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/filter"
	"github.com/harryheros/dnsnova/internal/recursor"
	"github.com/harryheros/dnsnova/internal/stats"
	"github.com/harryheros/dnsnova/internal/tlsmgr"
)

func keys(cs []alert.Condition) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Key+"="+string(c.Severity))
	}
	slices.Sort(out)
	return out
}

func latencies(n uint64, bucket int) (c [16]uint64) {
	c[bucket] = n
	return c
}

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	base := alertInput{cfg: config.DefaultAlerts, node: "n1", now: now, span: 5 * time.Minute}
	cases := []struct {
		name string
		mod  func(*alertInput)
		want []string
	}{
		{"all fine", func(in *alertInput) {
			in.counts = stats.Counts{Answers: 10000, ServFail: 100, Upstream: latencies(5000, 8)}
			in.upstreams = []upstreamWindow{{addr: "a", healthy: true, queries: 100, errors: 3}}
		}, nil},
		{"every upstream down", func(in *alertInput) {
			in.upstreams = []upstreamWindow{{addr: "a", queries: 50, errors: 50}, {addr: "b", queries: 40, errors: 40}}
		}, []string{"upstreams_down=critical"}},
		{"down but nothing asked: unknown, not down", func(in *alertInput) {
			in.upstreams = []upstreamWindow{{addr: "a"}}
		}, nil},
		{"recursion: upstreams are not the answer path", func(in *alertInput) {
			in.recursion = true
			in.upstreams = []upstreamWindow{{addr: "a", queries: 50, errors: 50}}
		}, nil},
		{"recursion: name servers unreachable", func(in *alertInput) {
			in.recursion, in.recState = true, "unreachable"
		}, []string{"recursion_down=critical"}},
		{"recursion: port 53 intercepted", func(in *alertInput) {
			in.recursion, in.recState, in.fallback = true, "intercepted", true
		}, []string{"recursion_intercepted=critical"}},
		{"recursion healthy", func(in *alertInput) {
			in.recursion = true
		}, nil},
		{"one upstream failing", func(in *alertInput) {
			in.upstreams = []upstreamWindow{{addr: "a", healthy: true, queries: 100, errors: 60}, {addr: "b", healthy: true, queries: 100},
				{addr: "c", queries: 10, errors: 10}} // too few queries to say
		}, []string{"upstream_failing:a=warning"}},
		{"SERVFAIL ratio", func(in *alertInput) {
			in.counts = stats.Counts{Answers: 1000, ServFail: 80}
		}, []string{"servfail_rate=warning"}},
		{"SERVFAIL ratio high", func(in *alertInput) {
			in.counts = stats.Counts{Answers: 1000, ServFail: 600}
		}, []string{"servfail_rate=critical"}},
		{"SERVFAIL from DNSSEC is not counted twice", func(in *alertInput) {
			in.cfg.DNSSECFailures = 0
			in.counts, in.bogus = stats.Counts{Answers: 1000, ServFail: 80}, 60
		}, nil},
		{"too few queries to judge", func(in *alertInput) {
			in.counts = stats.Counts{Answers: 100, ServFail: 90, Upstream: latencies(50, 14)}
		}, nil},
		{"slow", func(in *alertInput) {
			in.counts = stats.Counts{Answers: 1000, Upstream: latencies(500, 12)} // 0.5..1s
		}, []string{"latency_p95=warning"}},
		{"slow check off", func(in *alertInput) {
			in.cfg.LatencyP95 = 0
			in.counts = stats.Counts{Answers: 1000, Upstream: latencies(500, 12)}
		}, nil},
		{"DNSSEC failures", func(in *alertInput) {
			in.bogus = 150
			in.failures = []recursor.Failure{{Name: "broken.example.", Type: "A", EDE: "DNSSEC Bogus", Count: 150, Last: now}}
		}, []string{"dnssec_failures=warning"}},
		{"certificate in 10 days", func(in *alertInput) {
			in.certMode, in.cert = "acme", tlsmgr.Status{Ready: true, NotAfter: now.Add(10 * 24 * time.Hour)}
		}, []string{"cert_expiry=warning"}},
		{"certificate in 2 days, renewal failing", func(in *alertInput) {
			in.certMode, in.cert = "acme", tlsmgr.Status{Ready: true, NotAfter: now.Add(2 * 24 * time.Hour), LastError: "rate limited"}
		}, []string{"cert_expiry=critical", "cert_renewal=warning"}},
		{"no certificate", func(in *alertInput) {
			in.certMode, in.cert = "acme", tlsmgr.Status{LastError: "challenge failed"}
		}, []string{"cert_renewal=critical"}},
		{"certificate off", func(in *alertInput) {
			in.certMode, in.cert = "off", tlsmgr.Status{LastError: "x"}
		}, nil},
		{"reload, lists, cluster, anycast", func(in *alertInput) {
			in.reloadErr = "line 3: unknown key"
			in.lists = []filter.ListStatus{{Source: "https://lists.example/ads.txt", Error: "HTTP 404"}, {Source: "ok"}}
			in.configErr = "upstream.primary: required"
			in.anycast = anycastWithdrawn
		}, []string{"anycast_withdrawn=critical", "config_refused=warning", "config_reload=warning", "filter_update:https://lists.example/ads.txt=warning"}},
	}
	for _, c := range cases {
		in := base
		c.mod(&in)
		got := evaluate(in)
		if strings.Join(keys(got), " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: %v, want %v", c.name, keys(got), c.want)
		}
		for _, g := range got {
			if g.Node != "n1" || g.Summary == "" || g.Kind == "" {
				t.Errorf("%s: %+v", c.name, g)
			}
		}
	}
	// what the reason was is kept
	in := base
	in.reloadErr = "line 3: unknown key"
	if d := evaluate(in)[0].Details; len(d) != 1 || d[0] != in.reloadErr {
		t.Fatalf("details %v", d)
	}
}

type hook struct {
	mu  sync.Mutex
	got []alert.Notification
	srv *httptest.Server
}

func newHook(t *testing.T) *hook {
	h := &hook{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var n alert.Notification
		json.Unmarshal(b, &n)
		if alert.Sign("k", r.Header.Get("X-DNSNova-Timestamp"), b) != strings.TrimPrefix(r.Header.Get("X-DNSNova-Signature"), "sha256=") {
			w.WriteHeader(401)
			return
		}
		h.mu.Lock()
		h.got = append(h.got, n)
		h.mu.Unlock()
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hook) has(status, key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, n := range h.got {
		if n.Status == status && n.Key == key {
			return true
		}
	}
	return false
}

// Every upstream down: the webhook hears of it, the admin page shows it,
// and the destination is kept 0600 in secrets.
func TestAlertsUpstreamsDown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	writeConfig(t, path, "127.0.0.1:1", "\n[alerts]\nenabled = true\nupstream_down_for = \"0s\"\n")
	s := newServer(t, path)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	h := newHook(t)
	if err := s.SetAlertDestination("webhook", map[string]string{"url": h.srv.URL, "secret": "k"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "secrets", "alerts.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("secrets file: %v %v", fi, err)
	}
	udp, _, _, _ := s.Addrs()
	udpAsk(t, udp[0], dnstest.Query(1, "down.test", 1, true, false), 3*time.Second)
	s.alertTick(time.Now())
	eventually(t, "webhook notified", func() bool { return h.has(alert.Firing, "upstreams_down") })
	a := s.Alerts()
	if !a.Enabled || len(a.Active) != 1 || !a.Active[0].Firing || !a.Destinations["webhook"].Set || len(a.Channels) != 1 {
		t.Fatalf("%+v", a)
	}
	res, err := s.TestAlerts(t.Context())
	if err != nil || res["webhook"] != "ok" || !h.has(alert.Test, "test") {
		t.Fatalf("test: %v %v", res, err)
	}

	// turned off: nothing more, and nothing resolved by being off
	src, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(src), "enabled = true", "enabled = false", 1)), 0o640)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if a := s.Alerts(); a.Enabled || len(a.Active) != 0 || len(a.Channels) != 0 {
		t.Fatalf("off: %+v", a)
	}
	if _, err := s.TestAlerts(t.Context()); err == nil {
		t.Fatal("test sent with alerts off")
	}
}

// A failed automatic reload is an alert until a configuration is applied.
func TestAlertsConfigReload(t *testing.T) {
	s, _, _ := start(t, "\n[alerts]\nenabled = true\n")
	s.noteReload(errors.New("line 9: unknown key"))
	s.alertTick(time.Now())
	if f := s.al.engine.Firing(); len(f) != 1 || f[0].Key != "config_reload" || f[0].Details[0] != "line 9: unknown key" {
		t.Fatalf("%+v", f)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.al.reloadErr != "" {
		t.Fatal("still noted after a good reload")
	}
}

// A follower notifies nothing itself: its alerts go to the primary with its
// report, and the primary sends them under the follower's name; when the
// follower stops reporting, that is an alert too, and its last alerts are
// kept rather than resolved.
func TestAlertsCluster(t *testing.T) {
	auth := dnstest.Serve(t)
	p, pdir := startPrimary(t, auth.Addr)
	ppath := filepath.Join(pdir, "dnsnova.toml")
	src, _ := os.ReadFile(ppath)
	os.WriteFile(ppath, append(src, []byte("\n[alerts]\nenabled = true\n")...), 0o640)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	h := newHook(t)
	if err := p.SetAlertDestination("webhook", map[string]string{"url": h.srv.URL, "secret": "k"}); err != nil {
		t.Fatal(err)
	}
	fdir := followerDir(t, pdir, p.ClusterAddr(), true)
	f := newServer(t, filepath.Join(fdir, "dnsnova.toml"))
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Shutdown)
	if !f.Alerts().Enabled || len(f.Alerts().Channels) != 0 {
		t.Fatalf("follower: %+v", f.Alerts())
	}
	if _, err := f.TestAlerts(t.Context()); err == nil {
		t.Fatal("follower sent a test")
	}
	f.noteReload(errors.New("bad file on fra-1"))
	f.alertTick(time.Now())
	eventually(t, "reported to the primary", func() bool {
		p.alertTick(time.Now())
		return h.has(alert.Firing, "fra-1/config_reload")
	})
	h.mu.Lock()
	for _, n := range h.got {
		if n.Key == "fra-1/config_reload" && (n.Node != "fra-1" || n.Server != "primary-1") {
			t.Errorf("%+v", n)
		}
	}
	h.mu.Unlock()

	p.cl.mu.Lock()
	p.cl.nodes["fra-1"].LastSeen = time.Now().Add(-time.Hour)
	p.cl.mu.Unlock()
	got := keys(p.nodeConditions())
	if strings.Join(got, " ") != "fra-1/config_reload=warning fra-1/node_offline=critical" {
		t.Fatalf("offline: %v", got)
	}
	// alerts.nodes = false: the primary says nothing about the followers
	os.WriteFile(ppath, append(src, []byte("\n[alerts]\nenabled = true\nnodes = false\n")...), 0o640)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	p.noteNodeAlerts("fra-1", []alert.Condition{{Key: "latency_p95", Severity: alert.Warning, Summary: "slow"}})
	p.alertTick(time.Now())
	time.Sleep(100 * time.Millisecond)
	if h.has(alert.Firing, "fra-1/latency_p95") || h.has(alert.Firing, "fra-1/node_offline") {
		t.Fatal("notified about a follower with alerts.nodes = false")
	}
}
