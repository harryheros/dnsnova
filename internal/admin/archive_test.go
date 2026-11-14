package admin

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/insight"
)

func TestArchiveAPI(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ar := e.b.archive
	ar.Configure(insight.ArchiveSettings{Dir: filepath.Join(e.dir, insight.ArchiveDir), Days: 30, FullIP: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { ar.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	day := time.Now().UTC()
	for i, n := range []string{"mail.example", "ads.tracker.test", "www.example"} {
		src := "cache"
		if strings.HasPrefix(n, "ads") {
			src = "blocked"
		}
		ar.Add(insight.Query{Time: day.Add(time.Duration(i) * time.Second), Proto: "udp", Name: n, Type: "A", Rcode: "NOERROR", Source: src},
			netip.MustParseAddr("192.168.1."+string(rune('1'+i))))
	}

	r := e.do(e.c, "GET", "/api/v1/querylog/archive?name=example", nil)
	if r.code != 200 || len(r.body["entries"].([]any)) != 2 {
		t.Fatalf("search: %d %s", r.code, r.raw)
	}
	r = e.do(e.c, "GET", "/api/v1/querylog/archive?result=blocked&client=192.168.1.2", nil)
	if es := r.body["entries"].([]any); len(es) != 1 || es[0].(map[string]any)["name"] != "ads.tracker.test" {
		t.Fatalf("blocked: %s", r.raw)
	}
	for _, bad := range []string{"day=yesterday", "result=all", "limit=5000", "limit=0"} {
		if r := e.do(e.c, "GET", "/api/v1/querylog/archive?"+bad, nil); r.code != 400 {
			t.Errorf("%s: %d", bad, r.code)
		}
	}

	r = e.do(e.c, "GET", "/api/v1/querylog", nil)
	arch := r.body["archive"].(map[string]any)
	files := r.body["files"].([]any)
	if arch["on"] != true || arch["days"] != 30.0 || len(files) != 1 {
		t.Fatalf("state: %s", r.raw)
	}
	name := files[0].(map[string]any)["name"].(string)
	r = e.do(e.c, "GET", "/api/v1/querylog/files/"+name, nil)
	if r.code != 200 || !strings.Contains(r.raw, "\tads.tracker.test\t") || !strings.Contains(r.hdr.Get("Content-Disposition"), "attachment") {
		t.Fatalf("download: %d %q %s", r.code, r.hdr.Get("Content-Disposition"), r.raw)
	}
	for _, bad := range []string{"..%2Fdnsnova.toml", "x.tsv", "%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"} {
		if r := e.do(e.c, "GET", "/api/v1/querylog/files/"+bad, nil); r.code != 404 {
			t.Errorf("%s: %d %s", bad, r.code, r.raw)
		}
	}
	// Signed in only.
	for _, p := range []string{"/api/v1/querylog/archive", "/api/v1/querylog/files/" + name} {
		if r := e.do(e.client(), "GET", p, nil); r.code != 401 {
			t.Errorf("%s without a session: %d", p, r.code)
		}
	}
	// The overview's privacy summary says it.
	r = e.do(e.c, "GET", "/api/v1/status", nil)
	pv := r.body["privacy"].(map[string]any)
	if pv["query_log"] != true || pv["query_log_days"] != 30.0 || pv["query_log_full_ip"] != true {
		t.Fatalf("privacy: %v", pv)
	}
}
