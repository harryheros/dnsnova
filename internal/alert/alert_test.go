package alert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeChan records what it is sent; fail makes the next sends fail.
type fakeChan struct {
	name string
	mu   sync.Mutex
	got  []Notification
	fail []error
	hold chan struct{} // if set, Send waits on it
}

func (f *fakeChan) Name() string { return f.name }
func (f *fakeChan) ID() string   { return f.name }
func (f *fakeChan) Send(ctx context.Context, n Notification) error {
	if f.hold != nil {
		select {
		case <-f.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, n)
	if len(f.fail) > 0 {
		err := f.fail[0]
		f.fail = f.fail[1:]
		return err
	}
	return nil
}

func (f *fakeChan) statuses() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var s []string
	for _, n := range f.got {
		s = append(s, n.Status+":"+n.Key)
	}
	return s
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 200 {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newTestEngine() (*Engine, *clock, *fakeChan) {
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e := NewEngine(quiet, "node-a")
	e.Now = c.now
	f := &fakeChan{name: "fake"}
	e.SetChannels([]Channel{f})
	return e, c, f
}

func TestEngineLifecycle(t *testing.T) {
	e, c, f := newTestEngine()
	defer e.Close()
	e.SetRepeat(time.Hour)
	cond := Condition{Key: "upstreams_down", Kind: "upstreams_down", Severity: Critical, Summary: "all down", For: 30 * time.Second}

	e.Update([]Condition{cond}) // pending
	if a := e.Active(); len(a) != 1 || a[0].Firing {
		t.Fatalf("active %+v", a)
	}
	c.add(20 * time.Second)
	e.Update([]Condition{cond})
	c.add(10 * time.Second)
	e.Update([]Condition{cond}) // held 30s: fires
	waitFor(t, "firing", func() bool { return len(f.statuses()) == 1 })
	if len(e.Firing()) != 1 {
		t.Fatal("not firing")
	}
	c.add(30 * time.Minute)
	e.Update([]Condition{cond}) // no reminder yet
	c.add(31 * time.Minute)
	e.Update([]Condition{cond}) // an hour since: reminder
	waitFor(t, "reminder", func() bool { return len(f.statuses()) == 2 })

	e.Update(nil) // gone: not resolved at once
	c.add(30 * time.Second)
	e.Update([]Condition{cond}) // back: still the same alert, nothing sent
	e.Update(nil)
	c.add(time.Minute)
	e.Update(nil) // gone a minute: resolved
	waitFor(t, "resolved", func() bool { return len(f.statuses()) == 3 })
	want := []string{"firing:upstreams_down", "reminder:upstreams_down", "resolved:upstreams_down"}
	if got := f.statuses(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sent %v, want %v", got, want)
	}
	if len(e.Active()) != 0 {
		t.Fatal("still active")
	}
	waitFor(t, "history", func() bool { return len(e.History()) == 3 })
	if h := e.History(); h[0].Status != Resolved || h[0].Results["fake"] != "ok" || h[0].Server != "node-a" {
		t.Fatalf("history %+v", h[0])
	}
}

// A condition that comes and goes faster than its For never fires, and
// leaves nothing to resolve.
func TestEnginePendingForgotten(t *testing.T) {
	e, c, f := newTestEngine()
	defer e.Close()
	cond := Condition{Key: "k", Severity: Warning, For: 5 * time.Minute}
	for range 5 {
		e.Update([]Condition{cond})
		c.add(time.Minute)
		e.Update(nil)
		c.add(2 * time.Minute)
		e.Update(nil)
	}
	time.Sleep(50 * time.Millisecond)
	if len(f.statuses()) != 0 || len(e.Active()) != 0 {
		t.Fatalf("sent %v, active %v", f.statuses(), e.Active())
	}
}

// Warning becoming critical is said at once; the reverse is not.
func TestEngineEscalation(t *testing.T) {
	e, c, f := newTestEngine()
	defer e.Close()
	w := Condition{Key: "cert_expiry", Severity: Warning, Summary: "14 days"}
	e.Update([]Condition{w})
	c.add(time.Hour)
	crit := w
	crit.Severity, crit.Summary = Critical, "3 days"
	e.Update([]Condition{crit})
	waitFor(t, "escalation", func() bool { return len(f.statuses()) == 2 })
	e.Update([]Condition{w})
	time.Sleep(50 * time.Millisecond)
	if len(f.statuses()) != 2 {
		t.Fatalf("sent %v", f.statuses())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.got[1].Severity != Critical || f.got[1].Summary != "3 days" {
		t.Fatalf("escalation sent %+v", f.got[1])
	}
}

func TestDeliveryRetries(t *testing.T) {
	old := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { retryDelays = old }()

	e, _, f := newTestEngine()
	defer e.Close()
	f.fail = []error{errors.New("connection refused"), &httpError{code: 503}}
	e.Update([]Condition{{Key: "a", Severity: Critical}})
	waitFor(t, "delivered after retries", func() bool { return len(e.History()) == 1 && e.History()[0].Results["fake"] == "ok" })
	if len(f.statuses()) != 3 {
		t.Fatalf("%d attempts", len(f.statuses()))
	}

	// a 4xx is not retried: the channel is set up wrong
	f.fail = []error{&httpError{code: 404, body: "no such hook"}}
	e.Update([]Condition{{Key: "a", Severity: Critical}, {Key: "b", Severity: Critical}})
	waitFor(t, "given up", func() bool {
		for _, h := range e.History() {
			if h.Key == "b" && h.Results["fake"] != "" {
				return true
			}
		}
		return false
	})
	if len(f.statuses()) != 4 || e.History()[0].Results["fake"] != "HTTP 404: no such hook" {
		t.Fatalf("attempts %v, history %+v", f.statuses(), e.History()[0])
	}
}

// A channel that hangs holds up neither Update nor the other channels;
// beyond its queue, notifications are dropped.
func TestSlowChannelDoesNotBlock(t *testing.T) {
	e, _, fast := newTestEngine()
	defer e.Close()
	slow := &fakeChan{name: "slow", hold: make(chan struct{})}
	e.SetChannels([]Channel{fast, slow})
	done := make(chan struct{})
	go func() {
		for i := range queueSize + 10 {
			e.Update([]Condition{{Key: string(rune('a'+i%26)) + strings.Repeat("x", i), Severity: Warning}})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Update blocked on a slow channel")
	}
	// the fast channel delivers on its own, at least a queue's worth of
	// the burst; the slow one takes one and drops what its queue cannot hold
	waitFor(t, "fast channel", func() bool { return len(fast.statuses()) >= queueSize })
	// the slow one holds one notification, its queue is full, the rest
	// were dropped rather than waited for
	e.mu.Lock()
	sw := e.chans["slow\x00slow"]
	e.mu.Unlock()
	if len(sw.q) < queueSize-1 { // less the one it may have taken since
		t.Fatalf("slow queue %d, want full (%d)", len(sw.q), queueSize)
	}
	if n := len(slow.statuses()); n != 0 {
		t.Fatalf("slow channel delivered %d while held", n)
	}
	close(slow.hold)
}

func TestSetChannelsKeepsQueues(t *testing.T) {
	e, _, f := newTestEngine()
	defer e.Close()
	w := e.chans["fake\x00fake"]
	e.SetChannels([]Channel{f, &fakeChan{name: "other"}})
	if e.chans["fake\x00fake"] != w || len(e.Channels()) != 2 {
		t.Fatal("unchanged channel replaced")
	}
	e.SetChannels(nil)
	if len(e.Channels()) != 0 || w.ctx.Err() == nil {
		t.Fatal("removed channel not stopped")
	}
}

// ---- channels ----

type capture struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
	code int
}

func (c *capture) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs, c.body = append(c.reqs, r), append(c.body, b)
		code := c.code
		c.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			w.Write([]byte("bad request"))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

var sample = Notification{Version: 1, Status: Firing, Key: "upstream_failing:udp://9.9.9.9:53", Kind: "upstream_failing",
	Severity: Critical, Node: "fra-1", Summary: "Upstream <udp://9.9.9.9:53> failing @everyone",
	Details: []string{"timeouts: 120 of 400"}, Since: time.Unix(1700000000, 0), Time: time.Unix(1700000300, 0), Server: "fra-1"}

func TestWebhookSigned(t *testing.T) {
	var c capture
	s := c.server(t)
	if err := (Webhook{URL: s.URL + "/hook", Secret: "s3cret"}).Send(context.Background(), sample); err != nil {
		t.Fatal(err)
	}
	r, body := c.reqs[0], c.body[0]
	var n Notification
	if err := json.Unmarshal(body, &n); err != nil || n.Key != sample.Key || n.Version != 1 || n.Status != Firing {
		t.Fatalf("body %s: %v", body, err)
	}
	ts := r.Header.Get("X-DNSNova-Timestamp")
	if want := "sha256=" + Sign("s3cret", ts, body); ts == "" || r.Header.Get("X-DNSNova-Signature") != want {
		t.Fatalf("signature %q, want %q", r.Header.Get("X-DNSNova-Signature"), want)
	}
	// no secret: no signature
	(Webhook{URL: s.URL}).Send(context.Background(), sample)
	if c.reqs[1].Header.Get("X-DNSNova-Signature") != "" {
		t.Fatal("signed without a secret")
	}
}

func TestSlackDiscordTelegram(t *testing.T) {
	var c capture
	s := c.server(t)
	ctx := context.Background()
	if err := (Slack{URL: s.URL}).Send(ctx, sample); err != nil {
		t.Fatal(err)
	}
	var sl map[string]string
	json.Unmarshal(c.body[0], &sl)
	if !strings.HasPrefix(sl["text"], "*[CRITICAL] fra-1: Upstream &lt;udp://9.9.9.9:53&gt;") || !strings.Contains(sl["text"], "timeouts: 120 of 400") {
		t.Fatalf("slack %q", sl["text"])
	}

	if err := (Discord{URL: s.URL}).Send(ctx, sample); err != nil {
		t.Fatal(err)
	}
	var dc struct {
		Embeds []struct {
			Title string
			Color int
		}
		AllowedMentions struct{ Parse []string } `json:"allowed_mentions"`
	}
	json.Unmarshal(c.body[1], &dc)
	if len(dc.Embeds) != 1 || dc.Embeds[0].Color != 0xE5534B || !strings.Contains(dc.Embeds[0].Title, "fra-1") ||
		dc.AllowedMentions.Parse == nil || len(dc.AllowedMentions.Parse) != 0 {
		t.Fatalf("discord %s", c.body[1])
	}

	tg := Telegram{Token: "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ", ChatID: "-100123", API: s.URL}
	res := sample
	res.Status = Resolved
	if err := tg.Send(ctx, res); err != nil {
		t.Fatal(err)
	}
	var tm map[string]any
	json.Unmarshal(c.body[2], &tm)
	if c.reqs[2].URL.Path != "/bot"+tg.Token+"/sendMessage" || tm["chat_id"] != "-100123" ||
		!strings.HasPrefix(tm["text"].(string), "[RESOLVED]") || !strings.Contains(tm["text"].(string), "Lasted 5m0s") {
		t.Fatalf("telegram %s %s", c.reqs[2].URL.Path, c.body[2])
	}

	// refusals: the error says why, and never contains the token
	c.code = 400
	err := tg.Send(ctx, sample)
	if err == nil || retryable(err) || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("err %v", err)
	}
	dead := Telegram{Token: tg.Token, ChatID: "1", API: "http://127.0.0.1:1"}
	if err := dead.Send(ctx, sample); err == nil || strings.Contains(err.Error(), tg.Token) || !retryable(err) {
		t.Fatalf("err %v", err)
	}
	if err := (Slack{URL: "http://127.0.0.1:1/services/SECRET"}).Send(ctx, sample); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err %v", err)
	}
}

func TestSendTest(t *testing.T) {
	var c capture
	s := c.server(t)
	e := NewEngine(quiet, "n1")
	defer e.Close()
	e.SetChannels([]Channel{Slack{URL: s.URL}, Discord{URL: s.URL + "/x"}})
	res := e.SendTest(context.Background())
	if res["slack"] != "ok" || res["discord"] != "ok" || len(c.body) != 2 {
		t.Fatalf("%v", res)
	}
	if h := e.History(); len(h) != 1 || h[0].Status != Test || len(h[0].Results) != 2 {
		t.Fatalf("history %+v", h)
	}
}

// ---- secrets ----

func TestSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "alerts.json")
	s, err := LoadSecrets(path)
	if err != nil || len(s.Channels()) != 0 {
		t.Fatal(s, err)
	}
	bad := []struct {
		name string
		f    map[string]string
	}{
		{"slack", map[string]string{"url": "http://hooks.slack.com/x"}}, // https only
		{"discord", map[string]string{"url": "not a url"}},
		{"telegram", map[string]string{"token": "nope", "chat_id": "1"}},
		{"telegram", map[string]string{"token": "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ", "chat_id": "chat; rm"}},
		{"email", map[string]string{"url": "https://x"}},
	}
	for _, b := range bad {
		if err := s.Set(b.name, b.f); err == nil {
			t.Errorf("%s %v accepted", b.name, b.f)
		}
	}
	must := func(name string, f map[string]string) {
		t.Helper()
		if err := s.Set(name, f); err != nil {
			t.Fatal(err)
		}
	}
	must("webhook", map[string]string{"url": "http://10.0.0.5:8080/hook", "secret": "k"})
	must("slack", map[string]string{"url": "https://hooks.slack.com/services/T/B/SECRET"})
	must("discord", map[string]string{"url": "https://discord.com/api/webhooks/1/SECRET"})
	must("telegram", map[string]string{"token": "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ", "chat_id": "-100123"})
	must("heartbeat", map[string]string{"url": "https://hc-ping.com/uuid"})
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	s2, err := LoadSecrets(path)
	if err != nil || len(s2.Channels()) != 4 || s2.Heartbeat.URL == "" {
		t.Fatal(s2, err)
	}
	shown, _ := json.Marshal(s2.Show())
	if strings.Contains(string(shown), "SECRET") || strings.Contains(string(shown), "ABCDEFG") {
		t.Fatalf("secret shown: %s", shown)
	}
	if !s2.Show()["slack"].Set || s2.Show()["slack"].Hint != "https://hooks.slack.com/…" {
		t.Fatalf("%+v", s2.Show())
	}
	must("slack", map[string]string{"url": ""}) // removed
	if s.Show()["slack"].Set {
		t.Fatal("not removed")
	}
}

func TestHeartbeat(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Heartbeat(ctx, func() string { return s.URL }, 5*time.Millisecond, quiet); close(done) }()
	waitFor(t, "heartbeats", func() bool { mu.Lock(); defer mu.Unlock(); return hits >= 3 })
	cancel()
	<-done
}
