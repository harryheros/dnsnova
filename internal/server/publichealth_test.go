package server

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/harryheros/dnsnova/internal/config"
)

// With recursion only (no upstreams), the public page must follow the
// resolver's health, as /healthz does, not report the server as down.
func TestPublicStatusRecursionOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	src := "[server]\nmode=\"public\"\nlisten=[\"127.0.0.1:0\"]\ndata_dir=\"" + dir + "\"\n[upstream]\nprimary=[]\nbootstrap=[]\n[recursion]\nenabled=true\nfallback=false\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
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
	if !s.Rec.Healthy() {
		t.Fatal("precondition: a fresh resolver counts as healthy")
	}
	if !s.PublicStatus().Healthy {
		t.Fatal("public status unhealthy although the resolver is healthy")
	}
}
