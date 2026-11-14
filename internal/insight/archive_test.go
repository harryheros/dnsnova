package insight

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a time safe to change while the archive reads it.
type fakeClock struct{ ns atomic.Int64 }

func (c *fakeClock) get() time.Time      { return time.Unix(0, c.ns.Load()).UTC() }
func (c *fakeClock) set(t time.Time)     { c.ns.Store(t.UnixNano()) }
func (c *fakeClock) add(d time.Duration) { c.ns.Add(int64(d)) }

func testArchive(t *testing.T, days int, full bool) (*Archive, string, *fakeClock, func()) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ArchiveDir)
	now := &fakeClock{}
	now.set(time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC))
	a := NewArchive()
	a.now = now.get
	a.Configure(ArchiveSettings{Dir: dir, Days: days, FullIP: full})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	return a, dir, now, stop
}

func q(at time.Time, name, rcode, source string) Query {
	return Query{Time: at, Proto: "udp", Name: name, Type: "A", Rcode: rcode, Source: source, MS: 1.25}
}

var (
	alice = netip.MustParseAddr("192.168.1.23")
	bob   = netip.MustParseAddr("192.168.1.40")
)

func search(t *testing.T, a *Archive, sq ArchiveQuery) []Query {
	t.Helper()
	if sq.Limit == 0 {
		sq.Limit = 100
	}
	got, err := a.Search(context.Background(), sq)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func names(qs []Query) string {
	var s []string
	for _, q := range qs {
		s = append(s, q.Name)
	}
	return strings.Join(s, " ")
}

func TestArchiveWritesAndSearches(t *testing.T) {
	a, dir, now, _ := testArchive(t, 7, true)
	a.Add(q(now.get(), "mail.example", "NOERROR", "cache"), alice)
	a.Add(q(now.get().Add(time.Second), "ads.tracker.test", "NXDOMAIN", "blocked"), bob)
	a.Add(q(now.get().Add(2*time.Second), "www.example", "SERVFAIL", "upstream"), alice)

	if got := names(search(t, a, ArchiveQuery{})); got != "www.example ads.tracker.test mail.example" {
		t.Fatalf("newest first: %s", got)
	}
	if got := names(search(t, a, ArchiveQuery{Name: "EXAMPLE"})); got != "www.example mail.example" {
		t.Fatalf("by name: %s", got)
	}
	if got := search(t, a, ArchiveQuery{Client: "192.168.1.40"}); len(got) != 1 || got[0].Client != "192.168.1.40" {
		t.Fatalf("by client: %+v", got)
	}
	if got := names(search(t, a, ArchiveQuery{Result: "blocked"})); got != "ads.tracker.test" {
		t.Fatalf("blocked: %s", got)
	}
	if got := names(search(t, a, ArchiveQuery{Result: "error"})); got != "www.example ads.tracker.test" {
		t.Fatalf("errors: %s", got)
	}
	if got := names(search(t, a, ArchiveQuery{Limit: 1})); got != "www.example" {
		t.Fatalf("limit: %s", got)
	}
	got := search(t, a, ArchiveQuery{Name: "mail"})[0]
	if !got.Time.Equal(now.get()) || got.MS != 1.2 && got.MS != 1.3 || got.Type != "A" || got.Proto != "udp" {
		t.Fatalf("round trip: %+v", got)
	}
	// Plain text on disk, private to the service.
	b, err := os.ReadFile(filepath.Join(dir, "2026-11-14.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	// Lines may be a little out of order (the search sorts by time).
	if !strings.Contains(string(b), "2026-11-14T10:00:00.000Z\t192.168.1.23\tudp\tmail.example\tA\tNOERROR\tcache\t1.2\t0\t\n") || strings.Count(string(b), "\n") != 3 {
		t.Fatalf("file:\n%s", b)
	}
	if info, _ := os.Stat(filepath.Join(dir, "2026-11-14.tsv")); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
}

func TestArchiveShortensAddresses(t *testing.T) {
	a, _, now, _ := testArchive(t, 7, false)
	a.Add(q(now.get(), "a.example", "NOERROR", "cache"), alice)
	if got := search(t, a, ArchiveQuery{}); got[0].Client != "192.168.1.x" {
		t.Fatalf("client %q", got[0].Client)
	}
}

func TestArchiveDaysRotateCompressAndExpire(t *testing.T) {
	a, dir, now, _ := testArchive(t, 2, true)
	day1 := now.get()
	a.Add(q(day1, "one.example", "NOERROR", "cache"), alice)
	a.drain() // a day passes before the next query
	a.Add(q(day1.Add(24*time.Hour), "two.example", "NOERROR", "cache"), alice)
	now.set(day1.Add(24 * time.Hour))
	a.drain()
	waitFile(t, filepath.Join(dir, "2026-11-14.tsv.gz"))
	if _, err := os.Stat(filepath.Join(dir, "2026-11-14.tsv")); !os.IsNotExist(err) {
		t.Fatal("the plain file of a finished day was kept")
	}
	if got := names(search(t, a, ArchiveQuery{})); got != "two.example one.example" {
		t.Fatalf("across days: %s", got)
	}
	if got := names(search(t, a, ArchiveQuery{Day: "2026-11-14"})); got != "one.example" {
		t.Fatalf("one day: %s", got)
	}
	// The gzip file is ordinary gzip.
	f, _ := os.Open(filepath.Join(dir, "2026-11-14.tsv.gz"))
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(zr); !strings.Contains(string(b), "one.example") {
		t.Fatal("gzip content")
	}
	f.Close()

	// Two days kept: on the third day the first goes.
	now.set(day1.Add(48 * time.Hour))
	a.Sweep()
	if fs := a.Files(); len(fs) != 1 || fs[0].Day != "2026-11-15" {
		t.Fatalf("after expiry: %+v", fs)
	}
}

func TestArchiveCompressesLeftoverDays(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ArchiveDir)
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "2026-11-13.tsv"), []byte(formatLine(q(time.Date(2026, 11, 13, 23, 0, 0, 0, time.UTC), "crash.example", "NOERROR", "cache"))), 0o600)
	os.WriteFile(filepath.Join(dir, "2026-11-13.tsv.gz.tmp123"), []byte("half"), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600)
	a := NewArchive()
	a.now = func() time.Time { return time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC) }
	a.Configure(ArchiveSettings{Dir: dir, Days: 7})
	if fs := a.Files(); len(fs) != 1 || fs[0].Name != "2026-11-13.tsv.gz" {
		t.Fatalf("%+v", fs)
	}
	if _, err := os.Stat(filepath.Join(dir, "2026-11-13.tsv.gz.tmp123")); !os.IsNotExist(err) {
		t.Fatal("a half-written file was left")
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal("a file that is not the archive's was removed")
	}
}

func TestArchiveOffDeletesFiles(t *testing.T) {
	a, dir, now, _ := testArchive(t, 7, true)
	a.Add(q(now.get(), "a.example", "NOERROR", "cache"), alice)
	a.drain()
	a.Configure(ArchiveSettings{Dir: dir, Days: 0})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("the archive was kept after it was turned off")
	}
	a.Add(q(now.get(), "b.example", "NOERROR", "cache"), alice)
	a.drain()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("written while off")
	}
}

func TestArchiveNeverBlocks(t *testing.T) {
	a := NewArchive() // no writer running
	a.Configure(ArchiveSettings{Dir: t.TempDir(), Days: 1})
	start := time.Now()
	for i := 0; i < archiveQueue+10; i++ {
		a.Add(q(time.Now(), "a.example", "NOERROR", "cache"), alice)
	}
	if time.Since(start) > 2*time.Second || a.State().Dropped != 10 {
		t.Fatalf("dropped %d in %v", a.State().Dropped, time.Since(start))
	}
}

func TestArchiveEscapesNames(t *testing.T) {
	a, _, now, _ := testArchive(t, 7, true)
	a.Add(q(now.get(), "evil\tname\n.example", "NOERROR", "cache"), alice)
	a.Add(q(now.get().Add(time.Second), `back\slash.example`, "NOERROR", "cache"), alice)
	got := search(t, a, ArchiveQuery{})
	if len(got) != 2 || got[1].Name != `evil\009name\010.example` || got[0].Name != `back\092slash.example` {
		t.Fatalf("%q", names(got))
	}
}

func TestArchiveOpenFile(t *testing.T) {
	a, _, now, _ := testArchive(t, 7, true)
	a.Add(q(now.get(), "a.example", "NOERROR", "cache"), alice)
	f, err := a.OpenFile("2026-11-14.tsv")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if !strings.Contains(string(b), "a.example") {
		t.Fatal("queued queries missing from the download")
	}
	for _, bad := range []string{"../secrets/admin.json", "2026-11-14.tsv/../../x", "notes.txt", ""} {
		if _, err := a.OpenFile(bad); err == nil {
			t.Fatalf("%q opened", bad)
		}
	}
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestArchiveLateQueryNeverReopensADay(t *testing.T) {
	a, dir, now, _ := testArchive(t, 7, true)
	day1 := now.get()
	a.Add(q(day1, "before.example", "NOERROR", "cache"), alice)
	a.drain()
	a.Add(q(day1.Add(24*time.Hour), "after.example", "NOERROR", "cache"), alice)
	a.drain()
	a.Add(q(day1.Add(time.Minute), "late.example", "NOERROR", "cache"), alice) // reached the writer after midnight
	a.drain()
	waitFile(t, filepath.Join(dir, "2026-11-14.tsv.gz"))
	if _, err := os.Stat(filepath.Join(dir, "2026-11-14.tsv")); !os.IsNotExist(err) {
		t.Fatal("a compressed day was opened again")
	}
	if got := names(search(t, a, ArchiveQuery{})); got != "after.example late.example before.example" {
		t.Fatalf("%s", got)
	}
}

func TestArchiveRecompressKeepsEarlierLines(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ArchiveDir)
	os.MkdirAll(dir, 0o700)
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	a := NewArchive()
	a.now = func() time.Time { return time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC) }
	// Day 13 compressed, then more lines for it after a restart.
	os.WriteFile(filepath.Join(dir, "2026-11-13.tsv"), []byte(formatLine(q(at, "first.example", "NOERROR", "cache"))), 0o600)
	a.Configure(ArchiveSettings{Dir: dir, Days: 7})
	os.WriteFile(filepath.Join(dir, "2026-11-13.tsv"), []byte(formatLine(q(at.Add(time.Hour), "second.example", "NOERROR", "cache"))), 0o600)
	a.Sweep()
	if got := names(search(t, a, ArchiveQuery{})); got != "second.example first.example" {
		t.Fatalf("after compressing twice: %q", got)
	}
}

func TestArchiveLimitKeepsNewest(t *testing.T) {
	a, _, now, _ := testArchive(t, 7, true)
	base := now.get()
	// Written out of order: the newest is not the last line.
	for _, s := range []int{1, 5, 3, 4, 2} {
		a.Add(q(base.Add(time.Duration(s)*time.Second), fmt.Sprintf("n%d.example", s), "NOERROR", "cache"), alice)
	}
	if got := names(search(t, a, ArchiveQuery{Limit: 2})); got != "n5.example n4.example" {
		t.Fatalf("%s", got)
	}
}
