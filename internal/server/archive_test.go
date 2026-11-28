package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/insight"
)

func TestQueryArchive(t *testing.T) {
	s, _, path := start(t, "\n[log]\nquery_days = 3\n")
	udp, _, _, _ := s.Addrs()
	if _, err := udpAsk(t, udp[0], dnstest.Query(1, "kept.test", 1, false, false), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(path), insight.ArchiveDir)
	var b []byte
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		b, _ = os.ReadFile(filepath.Join(dir, time.Now().UTC().Format(time.DateOnly)+".tsv"))
		if strings.Contains(string(b), "kept.test") {
			break
		}
	}
	if !strings.Contains(string(b), "\t127.0.0.x\tudp\tkept.test\tA\tNOERROR\t") {
		t.Fatalf("archive file: %q", b)
	}
	if info := s.PublicStatus(); !info.QueryLog || info.QueryLogDays != 3 || info.QueryLogFullIP || info.ArchiveFullIP {
		t.Fatalf("status page: log %v days %d full %v", info.QueryLog, info.QueryLogDays, info.QueryLogFullIP)
	}
	// a live capture with full addresses, held in memory, is not on disk
	s.QLog.Start(15*time.Minute, true, time.Now())
	if info := s.PublicStatus(); !info.QueryLogFullIP || info.ArchiveFullIP {
		t.Fatalf("live capture read as on disk: full %v archive full %v", info.QueryLogFullIP, info.ArchiveFullIP)
	}
	s.QLog.Stop(time.Now())

	// Turned off: the files go, and the status page says so.
	snap, _ := s.Store.Load()
	out, _ := snap.Doc.Set("log", "query_days", config.Value{Kind: config.Int, Int: 0})
	snap2, err := s.Store.Write(out, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(snap2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("archive kept after it was turned off")
	}
	if info := s.PublicStatus(); info.QueryLog || info.QueryLogDays != 0 {
		t.Fatal("status page still says queries are kept")
	}
}

// The guides say where filtering applies: every endpoint, the filtered ones
// listed, or none yet (filtering on without a filtered endpoint must not
// read as "every address filters").
func TestFilteredInfo(t *testing.T) {
	s, _, _ := start(t, "")
	c := *s.Snapshot().Config
	if f := s.filteredInfo(&c, "dns.test"); f != nil {
		t.Fatalf("filtering off: %+v", f)
	}
	c.Filter.Enabled, c.Filter.All = true, true
	if f := s.filteredInfo(&c, "dns.test"); f == nil || !f.All {
		t.Fatalf("all endpoints: %+v", f)
	}
	c.Filter.All = false
	if f := s.filteredInfo(&c, ""); f == nil || f.All || f.DoH != "" || f.DoT != "" || f.DoQ != "" || len(f.Plain) != 0 {
		t.Fatalf("no filtered endpoint: %+v", f)
	}
}
