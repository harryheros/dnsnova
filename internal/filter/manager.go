package filter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Settings configure a Manager; they can change at run time.
type Settings struct {
	Enabled  bool
	Lists    []string // http(s) URLs or absolute file paths
	Block    []string // the operator's own rules
	Allow    []string
	Interval time.Duration // how often lists are downloaded again
}

// ListStatus describes one list for the admin interface.
type ListStatus struct {
	Source  string    `json:"source"`
	Rules   int       `json:"rules"`
	Skipped int       `json:"skipped"`
	Updated time.Time `json:"updated,omitzero"` // when the copy in use was fetched
	Checked time.Time `json:"checked,omitzero"` // last attempt
	Error   string    `json:"error,omitempty"`  // last attempt failed; the previous copy stays in use
}

// Status is the state of filtering.
type Status struct {
	Enabled bool         `json:"enabled"`
	Rules   int          `json:"rules"` // block rules in force, lists and own rules together
	Lists   []ListStatus `json:"lists"`
}

const (
	maxListSize = 64 << 20 // bytes
	// A list that suddenly loses more than half of its rules is probably a
	// broken download or a mistake upstream: the previous copy is kept.
	shrinkKeep = 0.5
	shrinkMin  = 100 // ...for lists of at least this many rules
)

// Manager keeps the lists up to date and publishes the combined Set. Copies
// of the lists are kept under dir, so filtering works at once after a
// restart and while a list cannot be downloaded.
type Manager struct {
	dir     string
	log     *slog.Logger
	publish func(*Set) // called with every new Set (nil when filtering is off)
	HTTP    *http.Client
	whyMu   sync.Mutex // one Why at a time: each parses every list
	Now     func() time.Time

	mu sync.Mutex
	// rebuildMu: one rebuild at a time, each reading the settings when it
	// starts. Otherwise a slow rebuild for old settings could publish its
	// rules after a quicker one for the new settings.
	rebuildMu sync.Mutex
	set       Settings
	lists     map[string]*ListStatus
	wake      chan struct{}
	rules     atomic.Int64
}

// NewManager returns a manager storing copies in dir; publish receives the
// combined rules whenever they change.
func NewManager(dir string, log *slog.Logger, publish func(*Set)) *Manager {
	return &Manager{
		dir: dir, log: log, publish: publish,
		HTTP:  newHTTPClient(),
		Now:   time.Now,
		lists: map[string]*ListStatus{},
		wake:  make(chan struct{}, 1),
	}
}

// Configure applies new settings: the rules are rebuilt at once from the
// stored copies, and lists that are new or due are downloaded by Run.
func (m *Manager) Configure(s Settings) {
	m.mu.Lock()
	m.set = s
	keep := map[string]*ListStatus{}
	for _, src := range s.Lists {
		if st, ok := m.lists[src]; ok {
			keep[src] = st
		} else {
			keep[src] = &ListStatus{Source: src}
		}
	}
	m.lists = keep
	m.mu.Unlock()
	m.rebuild()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Status reports the lists and the rules in force.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Enabled: m.set.Enabled, Rules: int(m.rules.Load())}
	for _, src := range m.set.Lists {
		if l := m.lists[src]; l != nil {
			st.Lists = append(st.Lists, *l)
		}
	}
	return st
}

// Run downloads lists when they are due, until ctx is done. It checks every
// few minutes and right after Configure.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		m.UpdateDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.wake:
		}
	}
}

// UpdateNow downloads every list at once, whatever its age (the "Update
// now" button), then rebuilds the rules.
func (m *Manager) UpdateNow(ctx context.Context) {
	m.mu.Lock()
	s := m.set
	m.mu.Unlock()
	if !s.Enabled {
		return
	}
	for _, src := range s.Lists {
		m.fetch(ctx, src)
	}
	m.rebuild()
}

// UpdateDue downloads every list whose copy is missing or older than the
// interval, then rebuilds the rules if anything changed.
func (m *Manager) UpdateDue(ctx context.Context) {
	m.mu.Lock()
	s := m.set
	m.mu.Unlock()
	if !s.Enabled {
		return
	}
	changed := false
	for _, src := range s.Lists {
		updated, checked := m.stamps(src)
		now := m.Now()
		due := updated.IsZero() || now.Sub(updated) >= s.Interval
		// After a failure, try again within the hour rather than waiting a
		// whole interval, but not on every tick.
		if !due || (!checked.IsZero() && now.Sub(checked) < retryAfter(s.Interval) && checked.After(updated)) {
			continue
		}
		if m.fetch(ctx, src) {
			changed = true
		}
	}
	if changed {
		m.rebuild()
	}
}

func retryAfter(interval time.Duration) time.Duration { return min(interval, 30*time.Minute) }

func (m *Manager) stamps(src string) (updated, checked time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l := m.lists[src]; l != nil {
		updated, checked = l.Updated, l.Checked
	}
	if updated.IsZero() { // after a restart: the age of the stored copy
		if fi, err := os.Stat(m.path(src)); err == nil {
			updated = fi.ModTime()
		}
	}
	return
}

// checkRedirect limits where a list server can send the download: a few
// redirects at most, never from HTTPS to plain HTTP, and never to an
// address on this machine or a private network (where it could reach
// services that are not meant to be asked, such as a cloud's metadata
// address).
//
// A name in a redirect can resolve to such an address too, so the address
// is checked again where it cannot be dodged: when the connection is made
// (guardDial), for every connection opened after a redirect.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("redirected from HTTPS to " + req.URL.Scheme)
	}
	if ip, err := netip.ParseAddr(strings.Trim(req.URL.Hostname(), "[]")); err == nil && localAddr(ip) {
		return errLocalRedirect
	}
	if f, ok := req.Context().Value(redirectedKey{}).(*atomic.Bool); ok {
		f.Store(true)
	}
	return nil
}

var errLocalRedirect = errors.New("redirected to a local address")

// redirectedKey marks, in a download's context, that it has been redirected.
type redirectedKey struct{}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func localAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() ||
		ip.IsMulticast() || cgnat.Contains(ip)
}

// guardDial refuses to connect to a local address once the download has
// been redirected. The list's own address, which the administrator typed,
// may be anywhere.
func guardDial(ctx context.Context, _, address string, _ syscall.RawConn) error {
	if f, ok := ctx.Value(redirectedKey{}).(*atomic.Bool); !ok || !f.Load() {
		return nil
	}
	if ap, err := netip.ParseAddrPort(address); err != nil || localAddr(ap.Addr()) {
		return errLocalRedirect
	}
	return nil
}

func newHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, ControlContext: guardDial}).DialContext
	// one connection per request: a connection opened before a redirect
	// is never reused for the address after it
	tr.DisableKeepAlives = true
	return &http.Client{Timeout: 60 * time.Second, Transport: tr, CheckRedirect: checkRedirect}
}

// path is where the copy of src is kept.
func (m *Manager) path(src string) string {
	sum := sha256.Sum256([]byte(src))
	return filepath.Join(m.dir, hex.EncodeToString(sum[:8])+".txt")
}

// fetch downloads src and stores it if it looks sound; it reports whether
// the stored copy changed.
func (m *Manager) fetch(ctx context.Context, src string) bool {
	now := m.Now()
	data, meta, err := m.download(ctx, src)
	if err == errNotModified || (err == nil && m.sameAsStored(src, data)) {
		// the copy in use is still current: nothing to parse or rebuild
		os.Chtimes(m.path(src), now, now) // its age after a restart
		if err == nil {
			m.storeMeta(src, meta)
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if l := m.lists[src]; l != nil {
			l.Checked, l.Updated, l.Error = now, now, ""
		}
		return false
	}
	var c Counts
	if err == nil {
		c, err = Parse(bytes.NewReader(data), NewBuilder())
	}
	if err == nil {
		prev := m.previousRules(src)
		if prev >= shrinkMin && float64(c.Block) < float64(prev)*shrinkKeep {
			err = fmt.Errorf("the new copy has %d rules, the one in use %d; kept the one in use", c.Block, prev)
		}
	}
	if err == nil && c.Block == 0 && c.Allow == 0 {
		err = errors.New("no usable rules in the download")
	}
	if err == nil {
		if err = m.store(src, data); err == nil {
			m.storeMeta(src, meta)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.lists[src]
	if l == nil { // removed while downloading
		return false
	}
	l.Checked = now
	if err != nil {
		l.Error = err.Error()
		m.log.Warn("filter list not updated", "list", src, "err", err)
		return false
	}
	l.Error, l.Updated = "", now
	m.log.Info("filter list updated", "list", src, "rules", c.Block)
	return true
}

func (m *Manager) previousRules(src string) int {
	data, err := os.ReadFile(m.path(src))
	if err != nil {
		return 0
	}
	c, _ := Parse(bytes.NewReader(data), NewBuilder())
	return c.Block
}

// errNotModified: the server says the copy in use is current (HTTP 304).
var errNotModified = errors.New("not modified")

// listMeta is what the server said about the copy in use, to ask next
// time only for a newer one (RFC 9110 13.1: If-None-Match and
// If-Modified-Since).
type listMeta struct{ etag, modified string }

func (m *Manager) metaPath(src string) string {
	return strings.TrimSuffix(m.path(src), ".txt") + ".meta"
}

func (m *Manager) readMeta(src string) listMeta {
	if _, err := os.Stat(m.path(src)); err != nil {
		return listMeta{} // no copy: ask for the whole list
	}
	b, err := os.ReadFile(m.metaPath(src))
	if err != nil {
		return listMeta{}
	}
	etag, modified, _ := strings.Cut(string(b), "\n")
	return listMeta{etag: strings.TrimSpace(etag), modified: strings.TrimSpace(modified)}
}

func (m *Manager) storeMeta(src string, meta listMeta) {
	if meta == (listMeta{}) {
		os.Remove(m.metaPath(src))
		return
	}
	os.WriteFile(m.metaPath(src), []byte(meta.etag+"\n"+meta.modified+"\n"), 0o640)
}

// sameAsStored reports whether data is the copy in use, byte for byte
// (servers that do not support conditional requests).
func (m *Manager) sameAsStored(src string, data []byte) bool {
	old, err := os.ReadFile(m.path(src))
	return err == nil && bytes.Equal(old, data)
}

func (m *Manager) download(ctx context.Context, src string) ([]byte, listMeta, error) {
	if strings.HasPrefix(src, "/") {
		f, err := os.Open(src)
		if err != nil {
			return nil, listMeta{}, err
		}
		defer f.Close()
		data, err := readLimited(f)
		return data, listMeta{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx = context.WithValue(ctx, redirectedKey{}, new(atomic.Bool))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, listMeta{}, err
	}
	req.Header.Set("User-Agent", "dnsnova")
	if old := m.readMeta(src); old.etag != "" {
		req.Header.Set("If-None-Match", old.etag)
	} else if old.modified != "" {
		req.Header.Set("If-Modified-Since", old.modified)
	}
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, listMeta{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, listMeta{}, errNotModified
	}
	if resp.StatusCode != http.StatusOK {
		return nil, listMeta{}, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	data, err := readLimited(resp.Body)
	return data, listMeta{etag: resp.Header.Get("ETag"), modified: resp.Header.Get("Last-Modified")}, err
}

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxListSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxListSize {
		return nil, fmt.Errorf("larger than %d MB", maxListSize>>20)
	}
	return data, nil
}

func (m *Manager) store(src string, data []byte) error {
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.dir, ".list-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), m.path(src))
}

// rebuild combines the stored copies and the operator's rules into a new
// Set and publishes it.
func (m *Manager) rebuild() {
	m.rebuildMu.Lock()
	defer m.rebuildMu.Unlock()
	m.mu.Lock()
	s := m.set
	m.mu.Unlock()
	if !s.Enabled {
		m.rules.Store(0)
		m.publish(nil)
		return
	}
	b := NewBuilder()
	counts := map[string]Counts{}
	for _, src := range s.Lists {
		data, err := os.ReadFile(m.path(src))
		if err != nil {
			continue // not downloaded yet
		}
		c, _ := Parse(bytes.NewReader(data), b)
		counts[src] = c
	}
	for _, d := range s.Block {
		b.Block(d)
	}
	for _, d := range s.Allow {
		b.Allow(d)
	}
	set := b.Set()
	m.mu.Lock()
	for src, c := range counts {
		if l := m.lists[src]; l != nil && slices.Contains(s.Lists, src) {
			l.Rules, l.Skipped = c.Block, c.Skipped
			if l.Updated.IsZero() {
				if fi, err := os.Stat(m.path(src)); err == nil {
					l.Updated = fi.ModTime()
				}
			}
		}
	}
	m.mu.Unlock()
	m.rules.Store(int64(set.Rules()))
	m.publish(set)
}
