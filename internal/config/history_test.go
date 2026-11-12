package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Saves within one millisecond must each keep their own version, in order.
func TestHistoryKeepsRapidSaves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	if err := os.WriteFile(path, minimal(), 0o640); err != nil {
		t.Fatal(err)
	}
	s := NewStore(path)
	snap, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	const n = HistoryLimit + 5
	for i := 1; i <= n; i++ {
		out, err := snap.Doc.Set("upstream", "parallel", IntV(int64(i%3+1)))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, []byte("# save "+string(rune('a'+i))+"\n")...)
		if snap, err = s.Write(out, snap.Hash); err != nil {
			t.Fatal(err)
		}
	}
	hist, err := s.History()
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != HistoryLimit {
		t.Fatalf("history has %d versions, want %d", len(hist), HistoryLimit)
	}
	// newest first: the newest saved version is the one before the last write
	for i, h := range hist {
		b, err := os.ReadFile(filepath.Join(s.HistoryDir, h.Name))
		if err != nil {
			t.Fatal(err)
		}
		want := "# save " + string(rune('a'+n-1-i)) + "\n"
		if len(b) < len(want) || string(b[len(b)-len(want):]) != want {
			t.Errorf("history[%d] = %s: does not end with %q", i, h.Name, want)
		}
	}
}
