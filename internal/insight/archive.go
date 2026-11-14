package insight

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The archive keeps every query on disk for a number of days, for networks
// that must be able to tell later which device looked up what (an office's
// security team, an audit). It is off unless the administrator turns it on.
//
// One file per day (UTC), named 2006-01-02.tsv while it is written and
// gzipped once the day is over. Each line is one query, tab-separated:
//
//	time (RFC 3339, ms)  client  protocol  name  type  result  from  ms  filtered  group
//
// Names are written as in a zone file: bytes that are not printable, and
// backslashes, as \DDD. The files are plain text, so grep, zgrep and log
// shippers read them as they are.

// ArchiveDir is the directory under data_dir.
const ArchiveDir = "querylog"

// archiveQueue is how many queries may wait for the writer; beyond it,
// queries are dropped from the archive (and counted), never delayed.
const archiveQueue = 1 << 16

// ArchiveSettings configure the archive.
type ArchiveSettings struct {
	Dir    string // data_dir/querylog
	Days   int    // 0: off, and the files are deleted
	FullIP bool   // keep whole client addresses
}

// Archive writes queries to disk. Safe for concurrent use.
type Archive struct {
	mu      sync.Mutex // set, w, f, day
	set     ArchiveSettings
	ch      chan Query
	w       *bufio.Writer
	f       *os.File
	day     string
	on      atomic.Bool
	full    atomic.Bool  // set.FullIP, read on every query
	cmu     sync.Mutex   // one compression at a time
	pending atomic.Int64 // queued and not yet written
	dropped atomic.Uint64
	written atomic.Uint64
	errs    atomic.Uint64
	lastErr atomic.Pointer[string]
	now     func() time.Time
}

// NewArchive returns a stopped archive; Configure turns it on.
func NewArchive() *Archive {
	return &Archive{ch: make(chan Query, archiveQueue), now: time.Now}
}

// Run writes queued queries until ctx is done, flushing every second and
// removing old files every hour.
func (a *Archive) Run(ctx context.Context) {
	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	sweep := time.NewTicker(time.Hour)
	defer sweep.Stop()
	a.Sweep()
	for {
		select {
		case <-ctx.Done():
			a.drain()
			a.mu.Lock()
			a.closeLocked()
			a.mu.Unlock()
			return
		case q := <-a.ch:
			a.mu.Lock()
			a.writeLocked(q)
			a.pending.Add(-1)
			a.mu.Unlock()
		case <-flush.C:
			a.mu.Lock()
			a.flushLocked()
			a.mu.Unlock()
		case <-sweep.C:
			a.Sweep()
		}
	}
}

// drain writes everything queued so far, including a record the writer
// has taken but not yet written (for at most a second).
func (a *Archive) drain() {
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		for empty := false; !empty; {
			select {
			case q := <-a.ch:
				a.writeLocked(q)
				a.pending.Add(-1)
			default:
				empty = true
			}
		}
		a.flushLocked()
		a.mu.Unlock()
		if a.pending.Load() <= 0 || time.Now().After(deadline) {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// Configure applies new settings. Turning the archive off deletes its
// files; fewer days delete the files past them.
func (a *Archive) Configure(s ArchiveSettings) {
	a.mu.Lock()
	if s.Dir != a.set.Dir || s.Days <= 0 {
		a.closeLocked()
	}
	a.set = s
	a.full.Store(s.FullIP)
	a.on.Store(s.Days > 0 && s.Dir != "")
	a.mu.Unlock()
	a.Sweep()
}

// On reports whether queries are being archived.
func (a *Archive) On() bool { return a.on.Load() }

// Add queues one query. ip is the client's address; it is shortened
// unless whole addresses are kept.
func (a *Archive) Add(q Query, ip netip.Addr) {
	if !a.on.Load() {
		return
	}
	if a.full.Load() {
		q.Client = ip.Unmap().String()
	} else {
		q.Client = Mask(ip)
	}
	a.pending.Add(1)
	select {
	case a.ch <- q:
	default:
		a.pending.Add(-1)
		a.dropped.Add(1)
	}
}

// writeLocked appends q to the file of its day, opening (and finishing
// the previous day's file) as the day changes.
func (a *Archive) writeLocked(q Query) {
	if !a.on.Load() {
		return
	}
	day := q.Time.UTC().Format(time.DateOnly)
	if a.w != nil && day < a.day {
		// A query from just before midnight that reached the writer late:
		// it goes in the open file (its line has its own time), never
		// reopening a day that may be compressed already.
		day = a.day
	}
	if day != a.day || a.w == nil {
		prev := a.day
		a.closeLocked()
		if err := os.MkdirAll(a.set.Dir, 0o700); err != nil {
			a.fail(err)
			return
		}
		f, err := os.OpenFile(filepath.Join(a.set.Dir, day+".tsv"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			a.fail(err)
			return
		}
		a.f, a.w, a.day = f, bufio.NewWriterSize(f, 64<<10), day
		if prev != "" && prev < day {
			go a.compress(prev)
		}
	}
	a.w.WriteString(formatLine(q))
	a.written.Add(1)
}

func (a *Archive) flushLocked() {
	if a.w != nil {
		if err := a.w.Flush(); err != nil {
			a.fail(err)
		}
	}
}

func (a *Archive) closeLocked() {
	a.flushLocked()
	if a.f != nil {
		a.f.Close()
	}
	a.f, a.w, a.day = nil, nil, ""
}

func (a *Archive) fail(err error) {
	a.errs.Add(1)
	s := err.Error()
	a.lastErr.Store(&s)
}

// compress gzips the finished file of day and removes the plain one.
func (a *Archive) compress(day string) {
	a.cmu.Lock()
	defer a.cmu.Unlock()
	a.mu.Lock()
	dir := a.set.Dir
	a.mu.Unlock()
	if dir == "" {
		return
	}
	src := filepath.Join(dir, day+".tsv")
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.CreateTemp(dir, day+".tsv.gz.tmp*")
	if err != nil {
		a.fail(err)
		return
	}
	tmp := out.Name()
	zw := gzip.NewWriter(out)
	_, err = io.Copy(zw, in)
	if err == nil {
		err = zw.Close()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		a.fail(err)
		return
	}
	dst := filepath.Join(dir, day+".tsv.gz")
	if _, err := os.Stat(dst); err == nil {
		// The day was compressed already (lines written to it after a
		// restart): add them as another gzip member, which readers join.
		err := appendFile(dst, tmp)
		os.Remove(tmp)
		if err != nil {
			a.fail(err)
			return
		}
	} else if err := os.Rename(tmp, dst); err != nil {
		a.fail(err)
		return
	}
	os.Remove(src)
}

// appendFile adds the contents of src to the end of dst.
func appendFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Sweep deletes files older than the days kept (all of them when off) and
// compresses finished days left plain, as after a crash.
func (a *Archive) Sweep() {
	a.mu.Lock()
	s, today := a.set, a.now().UTC().Format(time.DateOnly)
	on := a.on.Load()
	a.mu.Unlock()
	if s.Dir == "" {
		return
	}
	a.cmu.Lock() // no compression is writing its temporary file now
	if ents, err := os.ReadDir(s.Dir); err == nil {
		for _, e := range ents {
			if day, _, ok := strings.Cut(e.Name(), ".tsv.gz.tmp"); ok && len(day) == len(time.DateOnly) {
				os.Remove(filepath.Join(s.Dir, e.Name())) // left by a crash
			}
		}
	}
	a.cmu.Unlock()
	files, _ := a.files(s.Dir)
	first := a.now().UTC().AddDate(0, 0, -(s.Days - 1)).Format(time.DateOnly)
	for _, f := range files {
		switch {
		case !on || f.Day < first:
			os.Remove(filepath.Join(s.Dir, f.Name))
		case !f.Gzip && f.Day < today && !a.writing(f.Day):
			a.compress(f.Day)
		}
	}
	if !on {
		os.Remove(s.Dir) // only if empty
	}
}

func (a *Archive) writing(day string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.day == day
}

// ArchiveFile is one day's file.
type ArchiveFile struct {
	Name string `json:"name"`
	Day  string `json:"day"`
	Size int64  `json:"size"`
	Gzip bool   `json:"gzip"`
}

// Files lists the archive's files, newest first.
func (a *Archive) Files() []ArchiveFile {
	a.mu.Lock()
	dir := a.set.Dir
	a.mu.Unlock()
	files, _ := a.files(dir)
	return files
}

func (a *Archive) files(dir string) ([]ArchiveFile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return []ArchiveFile{}, err
	}
	out := []ArchiveFile{}
	for _, e := range ents {
		day, gz, ok := archiveName(e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, ArchiveFile{Name: e.Name(), Day: day, Size: info.Size(), Gzip: gz})
	}
	slices.SortFunc(out, func(x, y ArchiveFile) int { return strings.Compare(y.Name, x.Name) })
	return out, nil
}

// archiveName parses "2006-01-02.tsv" and "2006-01-02.tsv.gz".
func archiveName(n string) (day string, gz bool, ok bool) {
	base, gz := strings.CutSuffix(n, ".gz")
	day, ok = strings.CutSuffix(base, ".tsv")
	if !ok {
		return "", false, false
	}
	if _, err := time.Parse(time.DateOnly, day); err != nil {
		return "", false, false
	}
	return day, gz, true
}

// OpenFile opens one of the archive's files by name, for download.
func (a *Archive) OpenFile(name string) (*os.File, error) {
	if _, _, ok := archiveName(name); !ok {
		return nil, os.ErrNotExist
	}
	a.drain() // what is queued belongs in today's file
	a.mu.Lock()
	dir := a.set.Dir
	a.mu.Unlock()
	if dir == "" {
		return nil, os.ErrNotExist
	}
	return os.Open(filepath.Join(dir, name))
}

// ArchiveState describes the archive.
type ArchiveState struct {
	On      bool   `json:"on"`
	Days    int    `json:"days"`
	FullIP  bool   `json:"full_ip"`
	Written uint64 `json:"written"` // since the start
	Dropped uint64 `json:"dropped"` // the writer could not keep up
	Errors  uint64 `json:"errors"`
	LastErr string `json:"last_error,omitempty"`
	Bytes   int64  `json:"bytes"` // on disk
	Files   int    `json:"files"`
}

// State describes the archive now.
func (a *Archive) State() ArchiveState {
	a.mu.Lock()
	s := a.set
	a.mu.Unlock()
	st := ArchiveState{On: a.on.Load(), Days: s.Days, FullIP: s.FullIP && a.on.Load(),
		Written: a.written.Load(), Dropped: a.dropped.Load(), Errors: a.errs.Load()}
	if p := a.lastErr.Load(); p != nil {
		st.LastErr = *p
	}
	for _, f := range a.Files() {
		st.Bytes += f.Size
		st.Files++
	}
	return st
}

// ---- search ----

// ArchiveQuery selects queries from the archive.
type ArchiveQuery struct {
	Day    string // one day (2006-01-02), or "" for every day
	Name   string // the name contains this
	Client string // the client starts with this
	Group  string // the client's group is this
	Result string // "", "blocked" or "error" (anything but NOERROR)
	Limit  int
}

// ErrSearchTimeout ends a search that took too long; what was found is
// returned with it.
var ErrSearchTimeout = errors.New("the search took too long; narrow it to one day or a longer part of the name")

// Search returns up to q.Limit matching queries, newest first.
func (a *Archive) Search(ctx context.Context, q ArchiveQuery) ([]Query, error) {
	q.Name = strings.ToLower(strings.TrimSpace(q.Name))
	q.Client = strings.TrimSpace(q.Client)
	a.drain()
	// No compression meanwhile: while one runs, a day is in two files.
	a.cmu.Lock()
	defer a.cmu.Unlock()
	a.mu.Lock()
	dir := a.set.Dir
	a.mu.Unlock()
	files, _ := a.files(dir)
	out := []Query{}
	for _, f := range files {
		if q.Day != "" && f.Day != q.Day {
			continue
		}
		found, err := searchFile(ctx, filepath.Join(dir, f.Name), f.Gzip, q, q.Limit-len(out))
		out = append(out, found...)
		if err != nil {
			if ctx.Err() != nil {
				return out, ErrSearchTimeout
			}
			return out, err
		}
		if len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}

// searchFile returns the last limit matching lines of one file, newest
// first.
func searchFile(ctx context.Context, path string, gz bool, q ArchiveQuery, limit int) ([]Query, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // compressed or removed meanwhile
		}
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	}
	var newest newestN
	newest.n = limit
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for n := 0; sc.Scan(); n++ {
		if n%4096 == 0 && ctx.Err() != nil {
			return newest.sorted(), ctx.Err()
		}
		line := sc.Text()
		if q.Name != "" && !strings.Contains(strings.ToLower(line), q.Name) {
			continue // cheap test first; checked on the field below
		}
		rec, ok := parseLine(line)
		if !ok || !q.match(rec) {
			continue
		}
		newest.add(rec)
	}
	return newest.sorted(), sc.Err()
}

// newestN keeps the n newest queries seen (a min-heap on time): lines can
// be a little out of order, so the last lines are not always the newest.
type newestN struct {
	n int
	h []Query
}

func (k *newestN) add(q Query) {
	if k.n <= 0 {
		return
	}
	if len(k.h) < k.n {
		k.h = append(k.h, q)
		for i := len(k.h) - 1; i > 0; {
			p := (i - 1) / 2
			if !k.h[i].Time.Before(k.h[p].Time) {
				break
			}
			k.h[i], k.h[p] = k.h[p], k.h[i]
			i = p
		}
		return
	}
	if !q.Time.After(k.h[0].Time) {
		return // older than every one kept
	}
	k.h[0] = q
	for i := 0; ; {
		l, small := 2*i+1, i
		if l < len(k.h) && k.h[l].Time.Before(k.h[small].Time) {
			small = l
		}
		if r := l + 1; r < len(k.h) && k.h[r].Time.Before(k.h[small].Time) {
			small = r
		}
		if small == i {
			break
		}
		k.h[i], k.h[small] = k.h[small], k.h[i]
		i = small
	}
}

// sorted returns what was kept, newest first.
func (k *newestN) sorted() []Query {
	out := slices.Clone(k.h)
	slices.SortStableFunc(out, func(x, y Query) int { return y.Time.Compare(x.Time) })
	return out
}

func (q ArchiveQuery) match(r Query) bool {
	switch {
	case q.Name != "" && !strings.Contains(r.Name, q.Name):
		return false
	case q.Client != "" && !strings.HasPrefix(r.Client, q.Client):
		return false
	case q.Group != "" && r.Group != q.Group:
		return false
	case q.Result == "blocked" && !strings.HasPrefix(r.Source, "blocked"):
		return false
	case q.Result == "error" && r.Rcode == "NOERROR":
		return false
	}
	return true
}

// ---- lines ----

func formatLine(q Query) string {
	var b strings.Builder
	b.Grow(96)
	b.WriteString(q.Time.UTC().Format("2006-01-02T15:04:05.000Z"))
	for _, s := range []string{q.Client, q.Proto, escapeName(q.Name), q.Type, q.Rcode, q.Source,
		strconv.FormatFloat(q.MS, 'f', 1, 64)} {
		b.WriteByte('\t')
		b.WriteString(s)
	}
	b.WriteByte('\t')
	if q.Filtered {
		b.WriteByte('1')
	} else {
		b.WriteByte('0')
	}
	b.WriteByte('\t')
	b.WriteString(q.Group)
	b.WriteByte('\n')
	return b.String()
}

func parseLine(line string) (Query, bool) {
	f := strings.Split(line, "\t")
	if len(f) != 10 {
		return Query{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, f[0])
	if err != nil {
		return Query{}, false
	}
	ms, _ := strconv.ParseFloat(f[7], 64)
	return Query{Time: t, Client: f[1], Proto: f[2], Name: f[3], Type: f[4], Rcode: f[5], Source: f[6], MS: ms, Filtered: f[8] == "1", Group: f[9]}, true
}

// escapeName writes bytes that are not printable ASCII, and backslashes,
// as \DDD, so a name can never break a line or a field.
func escapeName(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			fmt.Fprintf(&b, "\\%03d", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
