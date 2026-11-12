package cluster

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testPrimary(t *testing.T, key Key) (*Primary, *httptest.Server, *[]Report) {
	t.Helper()
	p := NewPrimary(key, "primary-1")
	p.Shared = func() ([]byte, string) { return []byte("[cache]\nsize = 1\n"), "h1" }
	var mu sync.Mutex
	var got []Report
	p.OnReport = func(r Report, _ netip.Addr) { mu.Lock(); got = append(got, r); mu.Unlock() }
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return p, srv, &got
}

func addr(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "http://") }

func TestSync(t *testing.T) {
	key := Key{1, 2, 3}
	_, srv, got := testPrimary(t, key)
	f := NewFollower(key, addr(srv))
	reply, err := f.Sync(context.Background(), Report{Node: "fra-1", Version: "v1", Status: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Primary != "primary-1" || reply.Hash != "h1" || reply.Config != "[cache]\nsize = 1\n" {
		t.Fatalf("reply %+v", reply)
	}
	if len(*got) != 1 || (*got)[0].Node != "fra-1" || (*got)[0].Status != "ok" {
		t.Fatalf("reports %+v", *got)
	}
	// a node that has the configuration gets only its hash
	reply, err = f.Sync(context.Background(), Report{Node: "fra-1", Have: "h1"})
	if err != nil || reply.Config != "" || reply.Hash != "h1" {
		t.Fatalf("up to date: %+v %v", reply, err)
	}
}

func TestSyncWrongKey(t *testing.T) {
	_, srv, got := testPrimary(t, Key{1})
	if _, err := NewFollower(Key{2}, addr(srv)).Sync(context.Background(), Report{Node: "x"}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("other key: %v", err)
	}
	if len(*got) != 0 {
		t.Fatal("a report sealed with another key was accepted")
	}
	// a request without any sealing, or tampered with
	for _, body := range [][]byte{nil, []byte("{\"node\":\"x\"}"), bytes.Repeat([]byte{7}, 200)} {
		r, err := http.Post(srv.URL+Path, "application/octet-stream", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("unsealed body: %d", r.StatusCode)
		}
	}
	key := Key{1}
	sealed, _ := seal(newBox(key).req, Report{Node: "x", Time: time.Now().Unix(), Challenge: make([]byte, 16)})
	sealed[len(sealed)-1] ^= 1
	if r, _ := http.Post(srv.URL+Path, "", bytes.NewReader(sealed)); r.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered: %d", r.StatusCode)
	}
	// a sealed answer is not a request (separate keys)
	asReq, _ := seal(newBox(key).resp, Report{Node: "x", Time: time.Now().Unix(), Challenge: make([]byte, 16)})
	if r, _ := http.Post(srv.URL+Path, "", bytes.NewReader(asReq)); r.StatusCode != http.StatusForbidden {
		t.Fatalf("answer passed as request: %d", r.StatusCode)
	}
}

// An answer recorded earlier cannot be played back to a follower: it was
// for another challenge.
func TestReplayedReplyRejected(t *testing.T) {
	key := Key{9}
	_, real, _ := testPrimary(t, key)
	var recorded []byte
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if recorded != nil {
			w.Write(recorded) // play the old answer back
			return
		}
		resp, err := http.Post(real.URL+Path, "", r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		recorded, _ = io.ReadAll(resp.Body)
		w.Write(recorded)
	}))
	defer proxy.Close()
	f := NewFollower(key, addr(proxy))
	if _, err := f.Sync(context.Background(), Report{Node: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Sync(context.Background(), Report{Node: "a"}); err == nil || !strings.Contains(err.Error(), "not for this request") {
		t.Fatalf("replayed answer accepted: %v", err)
	}
}

func TestClockSkew(t *testing.T) {
	key := Key{4}
	p, srv, _ := testPrimary(t, key)
	f := NewFollower(key, addr(srv))
	f.Now = func() time.Time { return time.Now().Add(-MaxSkew - time.Minute) }
	if _, err := f.Sync(context.Background(), Report{Node: "a"}); err == nil {
		t.Fatal("request from a clock far behind accepted")
	}
	f.Now = time.Now
	p.Now = func() time.Time { return time.Now().Add(MaxSkew + time.Minute) }
	if _, err := f.Sync(context.Background(), Report{Node: "a"}); err == nil {
		t.Fatal("follower accepted an answer from a clock far ahead")
	}
}

func TestLoadKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "cluster-key")
	if _, _, err := LoadKey(path, false); err == nil {
		t.Fatal("a missing key was not reported")
	}
	k, created, err := LoadKey(path, true)
	if err != nil || !created || k == (Key{}) {
		t.Fatalf("create: %v %v", created, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	k2, created, err := LoadKey(path, true)
	if err != nil || created || k2 != k {
		t.Fatal("key changed on reload")
	}
	os.WriteFile(path, []byte("abc\n"), 0o600)
	if _, _, err := LoadKey(path, true); err == nil {
		t.Fatal("broken key accepted")
	}
}
