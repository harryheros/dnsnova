package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// With cache.persist on, answers saved at shutdown are served after a
// restart without asking the upstream again.
func TestCachePersistAcrossRestart(t *testing.T) {
	s, auth, path := start(t, "\n[cache]\npersist = true\n")
	udp, _, _, _ := s.Addrs()
	if _, err := udpAsk(t, udp[0], dnstest.Query(1, "keep.test", m.TypeA, false, false), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	s.Shutdown()
	file := filepath.Join(filepath.Dir(path), cacheFile)
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatalf("no cache file after shutdown: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode %04o, want 0600", fi.Mode().Perm())
	}

	s2, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s2.Shutdown)
	udp, _, _, _ = s2.Addrs()
	resp, err := udpAsk(t, udp[0], dnstest.Query(2, "keep.test", m.TypeA, false, false), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if p := dnstest.Parse(t, resp); p.AN != 1 || p.ID != 2 {
		t.Fatalf("after restart: %+v", p)
	}
	if n := auth.Count("keep.test."); n != 1 {
		t.Fatalf("upstream asked %d times, want once (before the restart)", n)
	}

	// clearing the cache removes the file too
	s2.ClearCache()
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("cache file left after clearing the cache")
	}
}

// Turning cache.persist off removes the saved file, at once and at start:
// looked-up names are not left on disk.
func TestCachePersistOffRemovesFile(t *testing.T) {
	s, _, path := start(t, "\n[cache]\npersist = true\n")
	if err := s.saveCache(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(filepath.Dir(path), cacheFile)
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(path)
	os.WriteFile(path, regexp.MustCompile(`persist = true`).ReplaceAll(src, []byte("persist = false")), 0o640)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("cache file kept after persist was turned off")
	}
	s.Shutdown()
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("cache saved at shutdown with persist off")
	}

	// a file from before is removed at start when persist is off
	os.WriteFile(file, []byte("old"), 0o600)
	s2, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s2.Shutdown)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("old cache file kept at start with persist off")
	}
}

// A damaged file is logged and ignored: the server starts with an empty
// cache.
func TestCachePersistDamagedFile(t *testing.T) {
	dir := t.TempDir()
	auth := dnstest.Serve(t)
	path := filepath.Join(dir, "dnsnova.toml")
	writeConfig(t, path, auth.Addr, "\n[cache]\npersist = true\n")
	os.WriteFile(filepath.Join(dir, cacheFile), []byte("DNCACHE1 not really"), 0o600)
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start with a damaged cache file: %v", err)
	}
	t.Cleanup(s.Shutdown)
	found := false
	for _, e := range s.EventLog.Recent(50) {
		if e.Level == "warn" && regexp.MustCompile(`cache file not loaded`).MatchString(e.Msg) {
			found = true
		}
	}
	if !found {
		t.Fatal("damaged cache file not reported")
	}
}

// Without cache.persist ("auto"), a public server keeps its cache across
// restarts and a home or office one (private mode) does not.
func TestCachePersistAutoFollowsMode(t *testing.T) {
	s, _, path := start(t, "")
	file := filepath.Join(filepath.Dir(path), cacheFile)
	s.Shutdown()
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("public mode: no cache file by default: %v", err)
	}

	src, _ := os.ReadFile(path)
	priv := regexp.MustCompile(`mode = "public"`).ReplaceAllString(string(src), `mode = "private"`) + "\n[access]\nallow = [\"192.168.0.0/16\"]\n"
	os.WriteFile(path, []byte(priv), 0o640)
	s2, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("private mode: the public server's cache file was kept")
	}
	s2.Shutdown()
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("private mode: cache saved by default")
	}
}
