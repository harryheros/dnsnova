package filter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// listServer serves a list whose content and status the test controls.
type listServer struct {
	mu     sync.Mutex
	body   string
	status int
	hits   int
}

func (l *listServer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits++
	if l.status != 0 && l.status != 200 {
		w.WriteHeader(l.status)
		return
	}
	io.WriteString(w, l.body)
}

func (l *listServer) set(body string, status int) {
	l.mu.Lock()
	l.body, l.status = body, status
	l.mu.Unlock()
}

func rules(n int, prefix string) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "||%s%d.example.com^\n", prefix, i)
	}
	return b.String()
}

type harness struct {
	m    *Manager
	srv  *httptest.Server
	ls   *listServer
	now  time.Time
	mu   sync.Mutex
	last *Set
	n    int
}

func newHarness(t *testing.T, dir string) *harness {
	h := &harness{ls: &listServer{}, now: time.Unix(1_900_000_000, 0)}
	h.srv = httptest.NewServer(h.ls)
	t.Cleanup(h.srv.Close)
	h.m = NewManager(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), func(s *Set) {
		h.mu.Lock()
		h.last, h.n = s, h.n+1
		h.mu.Unlock()
	})
	h.m.Now = func() time.Time { return h.now }
	return h
}

func (h *harness) blocked(t *testing.T, name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last.Blocked(wireOf(t, name))
}

func (h *harness) settings() Settings {
	return Settings{Enabled: true, Lists: []string{h.srv.URL + "/list.txt"}, Interval: 24 * time.Hour,
		Block: []string{"mine.example"}, Allow: []string{"ok0.example.com"}}
}

func TestManagerUpdatesAndProtects(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	h.ls.set(rules(500, "ad"), 200)
	h.m.Configure(h.settings())
	// own rules work before any download
	if !h.blocked(t, "mine.example") || h.blocked(t, "ad1.example.com") {
		t.Fatal("own rules must apply at once; lists only after download")
	}
	h.m.UpdateDue(context.Background())
	if !h.blocked(t, "ad1.example.com") || !h.blocked(t, "x.ad499.example.com") {
		t.Fatal("list not applied after download")
	}
	if h.blocked(t, "ok0.example.com") {
		t.Fatal("own allow rule must win over the list")
	}
	if st := h.m.Status(); st.Rules != 501 || len(st.Lists) != 1 || st.Lists[0].Rules != 500 || st.Lists[0].Error != "" {
		t.Fatalf("status %+v", st)
	}

	// not due yet: no download
	hits := h.ls.hits
	h.m.UpdateDue(context.Background())
	if h.ls.hits != hits {
		t.Fatal("downloaded again before the interval")
	}

	// due, but the server fails: the copy in use stays
	h.now = h.now.Add(25 * time.Hour)
	h.ls.set("", 503)
	h.m.UpdateDue(context.Background())
	if !h.blocked(t, "ad1.example.com") {
		t.Fatal("a failed download dropped the rules")
	}
	if st := h.m.Status(); !strings.Contains(st.Lists[0].Error, "503") {
		t.Fatalf("error not reported: %+v", st.Lists[0])
	}
	// no retry storm: not again within the retry window
	hits = h.ls.hits
	h.m.UpdateDue(context.Background())
	if h.ls.hits != hits {
		t.Fatal("retried at once after a failure")
	}

	// the list suddenly loses most rules: kept
	h.now = h.now.Add(time.Hour)
	h.ls.set(rules(10, "ad"), 200)
	h.m.UpdateDue(context.Background())
	if !h.blocked(t, "ad300.example.com") {
		t.Fatal("a list that shrank to 2% replaced the one in use")
	}
	if st := h.m.Status(); !strings.Contains(st.Lists[0].Error, "kept the one in use") {
		t.Fatalf("shrink not reported: %+v", st.Lists[0])
	}

	// a normal update replaces it
	h.now = h.now.Add(time.Hour)
	h.ls.set(rules(450, "new"), 200)
	h.m.UpdateDue(context.Background())
	if !h.blocked(t, "new1.example.com") || h.blocked(t, "ad1.example.com") {
		t.Fatal("normal update not applied")
	}

	// a restart without network: the stored copy is used at once
	h2 := newHarness(t, dir)
	h2.ls.set("", 500)
	s := h.settings()
	h2.m.Configure(s)
	if !h2.blocked(t, "new1.example.com") {
		t.Fatal("stored copy not used after a restart")
	}

	// turned off: nothing blocked, nothing downloaded
	s.Enabled = false
	h2.m.Configure(s)
	hits = h2.ls.hits
	h2.m.UpdateDue(context.Background())
	if h2.blocked(t, "new1.example.com") || h2.blocked(t, "mine.example") || h2.ls.hits != hits {
		t.Fatal("filtering off still blocks or downloads")
	}
}

func TestManagerLocalFileAndRemovedList(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, dir)
	path := dir + "/own-list.txt"
	writeFile(t, path, "0.0.0.0 local.example\n")
	s := Settings{Enabled: true, Lists: []string{path}, Interval: time.Hour}
	h.m.Configure(s)
	h.m.UpdateDue(context.Background())
	if !h.blocked(t, "local.example") {
		t.Fatal("local file list not applied")
	}
	s.Lists = nil
	h.m.Configure(s)
	if h.blocked(t, "local.example") || len(h.m.Status().Lists) != 0 {
		t.Fatal("a removed list still applies")
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRedirect(t *testing.T) {
	req := func(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }
	from := []*http.Request{req("https://lists.example/a.txt")}
	for u, ok := range map[string]bool{
		"https://cdn.example/a.txt":                true,
		"http://cdn.example/a.txt":                 false, // HTTPS to HTTP
		"https://127.0.0.1/a.txt":                  false,
		"https://169.254.169.254/latest/meta-data": false, // cloud metadata
		"https://10.0.0.5/a.txt":                   false,
		"https://[::1]/a.txt":                      false,
	} {
		if err := checkRedirect(req(u), from); (err == nil) != ok {
			t.Errorf("%s: %v", u, err)
		}
	}
	many := []*http.Request{from[0], from[0], from[0], from[0], from[0]}
	if checkRedirect(req("https://cdn.example/a.txt"), many) == nil {
		t.Error("no limit on redirects")
	}
}

// TestRebuildsKeepOrder: rebuilds for older settings never publish after
// the newest.
func TestRebuildsKeepOrder(t *testing.T) {
	h := newHarness(t, t.TempDir())
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			h.m.Configure(Settings{Enabled: true, Interval: time.Hour, Block: []string{fmt.Sprintf("n%d.example", i)}})
		})
	}
	wg.Wait()
	h.m.Configure(Settings{Enabled: true, Interval: time.Hour, Block: []string{"last.example"}})
	if !h.blocked(t, "last.example") || h.blocked(t, "n1.example") {
		t.Fatal("the rules published are not those of the newest settings")
	}
}

// TestRedirectToLocalName: a list server cannot send the download to a
// name that resolves to this machine. The address is checked when the
// connection is made, so it does not matter what the name looks like.
func TestRedirectToLocalName(t *testing.T) {
	var reached atomic.Int32
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		io.WriteString(w, rules(50, "secret"))
	}))
	defer inner.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(inner.URL, "http://"))
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+port+"/list.txt", http.StatusFound)
	}))
	defer outer.Close()

	m := NewManager(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(*Set) {})
	if _, err := m.download(context.Background(), outer.URL+"/list.txt"); err == nil || !strings.Contains(err.Error(), "local address") {
		t.Fatalf("redirect to localhost: err = %v", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the local server was reached %d times", n)
	}
	// the address the administrator typed may be local
	if _, err := m.download(context.Background(), inner.URL+"/list.txt"); err != nil {
		t.Fatalf("direct download from a local address: %v", err)
	}
}
