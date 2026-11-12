package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

func newServer(t *testing.T, path string) *Server {
	t.Helper()
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// startPrimary runs a primary whose shared settings include cache.size.
func startPrimary(t *testing.T, upstream string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	src := fmt.Sprintf(`# fleet settings
[server]
mode = "public"
listen = ["127.0.0.1:0"]
data_dir = %q

[upstream]
primary = ["udp://%s"]
bootstrap = []

[cache]
size = 1234

[limits]
client_qps = 0
prefix_qps = 0
global_qps = 0
rrl_rate = 0

[cluster]
role = "primary"
name = "primary-1"
listen = "127.0.0.1:0"

[anycast]
announce = ["echo", "primary-only"]
withdraw = ["echo", "primary-only"]
`, dir, upstream)
	os.WriteFile(path, []byte(src), 0o640)
	s := newServer(t, path)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	return s, dir
}

// followerDir prepares a follower's own file and, with key, the cluster
// key copied from the primary.
func followerDir(t *testing.T, primaryDir, primaryAddr string, key bool) string {
	t.Helper()
	dir := t.TempDir()
	if key {
		b, err := os.ReadFile(filepath.Join(primaryDir, "secrets", keyFile))
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)
		os.WriteFile(filepath.Join(dir, "secrets", keyFile), b, 0o600)
	}
	src := fmt.Sprintf(`# this node only
[server]
listen = ["127.0.0.1:0"]
data_dir = %q

[cluster]
role = "follower"
name = "fra-1"
region = "Frankfurt"
primary = %q
interval = "1s"
`, dir, primaryAddr)
	os.WriteFile(filepath.Join(dir, "dnsnova.toml"), []byte(src), 0o640)
	return dir
}

func TestClusterSync(t *testing.T) {
	auth := dnstest.Serve(t)
	p, pdir := startPrimary(t, auth.Addr)
	fdir := followerDir(t, pdir, p.ClusterAddr(), true)
	f := newServer(t, filepath.Join(fdir, "dnsnova.toml"))
	if err := f.Start(); err != nil {
		t.Fatalf("follower start: %v", err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			f.Shutdown()
		}
	})

	// the primary's settings, the follower's own on top, none of the
	// primary's node-local ones
	c := f.snap.Load().Config
	if c.Cache.Size != 1234 || c.Server.Mode != "public" || len(c.Upstream.Primary) != 1 {
		t.Fatalf("shared settings missing: cache %d mode %q", c.Cache.Size, c.Server.Mode)
	}
	if c.Server.DataDir != fdir || c.Cluster.Name != "fra-1" || c.Cluster.Listen != "" || len(c.Anycast.Announce) != 0 {
		t.Fatalf("node-local settings wrong: data_dir %q cluster %+v anycast %+v", c.Server.DataDir, c.Cluster, c.Anycast)
	}
	udp, _, _, _ := f.Addrs()
	if resp, err := udpAsk(t, udp[0], dnstest.Query(1, "fleet.test", m.TypeA, false, false), 2*time.Second); err != nil || dnstest.Parse(t, resp).AN != 1 {
		t.Fatalf("follower does not answer: %v", err)
	}

	// settings are changed on the primary, not here
	if _, err := f.ApplyConfig([]byte("x"), f.snap.Load().Hash); !errors.Is(err, config.ErrFollower) {
		t.Fatalf("follower accepted a change: %v", err)
	}

	// the primary sees the node
	eventually(t, "the primary lists fra-1 in sync", func() bool {
		for _, n := range p.Cluster().Nodes {
			if n.Name == "fra-1" && n.Online && n.InSync && n.Region == "Frankfurt" && n.Status == "ok" {
				return true
			}
		}
		return false
	})
	if nodes := p.Cluster().Nodes; len(nodes) != 2 || !nodes[0].Self || nodes[0].Name != "primary-1" {
		t.Fatalf("nodes: %+v", nodes)
	}

	// a change on the primary reaches the follower
	snap := p.snap.Load()
	src, _ := snap.Doc.Set("cache", "size", config.IntV(4321))
	if _, err := p.ApplyConfig(src, snap.Hash); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the follower applies the new cache size", func() bool { return f.snap.Load().Config.Cache.Size == 4321 })
	eventually(t, "the primary sees the follower in sync again", func() bool {
		for _, n := range p.Cluster().Nodes {
			if n.Name == "fra-1" && n.InSync {
				return true
			}
		}
		return false
	})
	if fc := f.Cluster(); fc.Role != "follower" || fc.PrimaryName != "primary-1" || fc.SyncError != "" || len(fc.Overrides) == 0 {
		t.Fatalf("follower view: %+v", fc)
	}

	// the primary goes away: the follower keeps answering, says so, and
	// starts again from its copy
	p.Shutdown()
	eventually(t, "the follower notices the primary is gone", func() bool { return f.Cluster().SyncError != "" })
	if resp, err := udpAsk(t, udp[0], dnstest.Query(2, "fleet.test", m.TypeA, false, false), 2*time.Second); err != nil || dnstest.Parse(t, resp).AN != 1 {
		t.Fatalf("follower stopped answering without its primary: %v", err)
	}
	f.Shutdown()
	stopped = true
	f2 := newServer(t, filepath.Join(fdir, "dnsnova.toml"))
	if err := f2.Start(); err != nil {
		t.Fatalf("restart without the primary: %v", err)
	}
	t.Cleanup(f2.Shutdown)
	if f2.snap.Load().Config.Cache.Size != 4321 {
		t.Fatal("restarted without the last configuration")
	}
}

// Without the cluster key, or with another one, a follower gets nothing.
func TestClusterKeyRequired(t *testing.T) {
	auth := dnstest.Serve(t)
	p, pdir := startPrimary(t, auth.Addr)
	fdir := followerDir(t, pdir, p.ClusterAddr(), false)
	if err := newServer(t, filepath.Join(fdir, "dnsnova.toml")).Start(); err == nil || !strings.Contains(err.Error(), keyFile) {
		t.Fatalf("start without the key: %v", err)
	}
	os.MkdirAll(filepath.Join(fdir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(fdir, "secrets", keyFile), []byte(strings.Repeat("ab", 32)+"\n"), 0o600)
	if err := newServer(t, filepath.Join(fdir, "dnsnova.toml")).Start(); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("start with another key: %v", err)
	}
	for _, n := range p.Cluster().Nodes {
		if !n.Self {
			t.Fatalf("a node without the key was listed: %+v", n)
		}
	}
}

// A server without [cluster] has no cluster listener and no follower loop.
func TestNoClusterByDefault(t *testing.T) {
	s, _, _ := start(t, "")
	if s.ClusterAddr() != "" || s.cl.follower != nil {
		t.Fatal("cluster parts running without a role")
	}
	if c := s.Cluster(); c.Role != "" || len(c.Nodes) != 0 {
		t.Fatalf("standalone: %+v", c)
	}
}

// A shared configuration that does not work on a follower (with its own
// settings on top) is not applied: it keeps the last good one and reports
// the error, here and to the primary.
func TestClusterRefusesBadConfig(t *testing.T) {
	auth := dnstest.Serve(t)
	p, pdir := startPrimary(t, auth.Addr)
	fdir := followerDir(t, pdir, p.ClusterAddr(), true)
	f := newServer(t, filepath.Join(fdir, "dnsnova.toml"))
	if err := f.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Shutdown)
	before := f.snap.Load().Hash
	f.applyShared([]byte("[server]\nmode = \"bogus\"\n"))
	if f.snap.Load().Hash != before {
		t.Fatal("a configuration that does not load was applied")
	}
	if c := f.Cluster(); !strings.Contains(c.SyncError, "server.mode") {
		t.Fatalf("error not reported: %+v", c)
	}
	if r := f.nodeReport(); !strings.Contains(r.ConfigError, "server.mode") {
		t.Fatalf("error not reported to the primary: %+v", r)
	}
	// the next good configuration clears it
	shared, _ := p.sharedOut()
	f.applyShared(shared)
	if c := f.Cluster(); c.SyncError != "" {
		t.Fatalf("error kept after a good configuration: %q", c.SyncError)
	}
}
