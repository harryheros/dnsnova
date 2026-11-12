// Package alert sends notifications when something is wrong with the
// server, and when it is fine again, to a JSON webhook, Slack, Discord or
// Telegram. It is off unless configured.
//
// It thinks in conditions, not events: every evaluation hands the engine
// what is wrong right now. A condition fires once it has held for its
// For; it is resolved once it has been gone for a minute (so a value
// hovering at its threshold does not flap); while it lasts, a reminder
// goes out every Repeat. Each notification goes to every channel through
// its own queue, in the background, with a timeout and a few retries:
// nothing here ever holds up a DNS query.
package alert

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"
)

// Severity of a condition.
type Severity string

const (
	Critical Severity = "critical"
	Warning  Severity = "warning"
)

// Condition is one thing that is wrong.
type Condition struct {
	// Key identifies it across evaluations: "upstreams_down",
	// "upstream_failing:udp://9.9.9.9", "fra-1/cert_expiry".
	Key      string   `json:"key"`
	Kind     string   `json:"kind"` // upstreams_down, upstream_failing, ...
	Severity Severity `json:"severity"`
	Node     string   `json:"node"`
	Summary  string   `json:"summary"`
	Details  []string `json:"details,omitempty"`
	// For is how long it must hold before it fires (0: at once).
	For time.Duration `json:"-"`
}

// Status of a notification.
const (
	Firing   = "firing"
	Resolved = "resolved"
	Reminder = "reminder" // still firing, Repeat later
	Test     = "test"
)

// Notification is what a channel sends. Version is the schema of the JSON
// webhook body: fields are only ever added.
type Notification struct {
	Version  int       `json:"version"`
	Status   string    `json:"status"`
	Key      string    `json:"key"`
	Kind     string    `json:"kind"`
	Severity Severity  `json:"severity"`
	Node     string    `json:"node"`
	Summary  string    `json:"summary"`
	Details  []string  `json:"details,omitempty"`
	Since    time.Time `json:"since"` // when the condition was first seen
	Time     time.Time `json:"time"`
	Server   string    `json:"server"` // the node that sent it
}

// Active is a condition being watched, for the admin page.
type Active struct {
	Condition
	Since  time.Time `json:"since"`
	Firing bool      `json:"firing"` // false: pending, not held for For yet
}

// Sent is one notification and how each channel took it.
type Sent struct {
	Notification
	Results map[string]string `json:"results"` // channel -> "ok" or the error
}

// clearAfter: a condition is resolved once it has been gone this long.
const clearAfter = time.Minute

type state struct {
	c        Condition
	since    time.Time
	firing   bool
	lastSent time.Time
	missing  time.Time // first evaluation without it (zero: present)
}

// Engine keeps the conditions and sends notifications.
type Engine struct {
	Log *slog.Logger
	Now func() time.Time
	// Server is this node's name, put in every notification.
	Server string // (under mu once the engine is in use: SetServer)

	mu      sync.Mutex
	repeat  time.Duration
	states  map[string]*state
	chans   map[string]*worker
	history []Sent
}

// NewEngine returns an engine with no channels.
func NewEngine(log *slog.Logger, server string) *Engine {
	return &Engine{Log: log, Now: time.Now, Server: server, states: map[string]*state{}, chans: map[string]*worker{}}
}

// SetServer sets this node's name, put in every notification.
func (e *Engine) SetServer(name string) {
	e.mu.Lock()
	e.Server = name
	e.mu.Unlock()
}

// SetRepeat sets how often a lasting condition is notified again (0: never).
func (e *Engine) SetRepeat(d time.Duration) {
	e.mu.Lock()
	e.repeat = d
	e.mu.Unlock()
}

// Update hands the engine what is wrong now. It returns at once; the
// notifications go out in the background.
func (e *Engine) Update(conds []Condition) {
	now := e.Now()
	e.mu.Lock()
	var out []Notification
	seen := map[string]bool{}
	for _, c := range conds {
		seen[c.Key] = true
		st := e.states[c.Key]
		if st == nil {
			st = &state{c: c, since: now}
			e.states[c.Key] = st
		}
		escalated := st.firing && c.Severity == Critical && st.c.Severity != Critical
		st.c, st.missing = c, time.Time{}
		switch {
		case !st.firing && now.Sub(st.since) >= c.For:
			st.firing, st.lastSent = true, now
			out = append(out, e.note(st, Firing, now))
		case escalated: // worse than when it fired: say so now
			st.lastSent = now
			out = append(out, e.note(st, Firing, now))
		case st.firing && e.repeat > 0 && now.Sub(st.lastSent) >= e.repeat:
			st.lastSent = now
			out = append(out, e.note(st, Reminder, now))
		}
	}
	for k, st := range e.states {
		if seen[k] {
			continue
		}
		if !st.firing { // never fired: forget quietly
			delete(e.states, k)
			continue
		}
		if st.missing.IsZero() {
			st.missing = now
		}
		if now.Sub(st.missing) >= clearAfter {
			out = append(out, e.note(st, Resolved, now))
			delete(e.states, k)
		}
	}
	e.mu.Unlock()
	for _, n := range out {
		e.dispatch(n)
	}
}

func (e *Engine) note(st *state, status string, now time.Time) Notification {
	return Notification{Version: 1, Status: status, Key: st.c.Key, Kind: st.c.Kind, Severity: st.c.Severity, Node: st.c.Node,
		Summary: st.c.Summary, Details: slices.Clone(st.c.Details), Since: st.since.UTC(), Time: now.UTC(), Server: e.Server}
}

// Reset forgets every condition without notifying (alerts turned off).
func (e *Engine) Reset() {
	e.mu.Lock()
	clear(e.states)
	e.mu.Unlock()
}

// Firing returns the conditions that have fired and not been resolved
// (what a cluster follower reports to its primary).
func (e *Engine) Firing() []Condition {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Condition
	for _, st := range e.states {
		if st.firing {
			c := st.c
			c.For = 0 // it has held already
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Condition) int { return compare(a.Key, b.Key) })
	return out
}

// Active returns every condition being watched, firing first.
func (e *Engine) Active() []Active {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Active, 0, len(e.states))
	for _, st := range e.states {
		out = append(out, Active{Condition: st.c, Since: st.since, Firing: st.firing})
	}
	slices.SortFunc(out, func(a, b Active) int {
		if a.Firing != b.Firing {
			if a.Firing {
				return -1
			}
			return 1
		}
		return compare(a.Key, b.Key)
	})
	return out
}

// History returns the last notifications sent, newest first.
func (e *Engine) History() []Sent {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := slices.Clone(e.history)
	for i := range out { // the maps change as deliveries finish
		out[i].Results = maps.Clone(out[i].Results)
		out[i].Details = slices.Clone(out[i].Details)
	}
	slices.Reverse(out)
	return out
}

const maxHistory = 50

func (e *Engine) record(n Notification, channel, result string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.history) - 1; i >= 0 && i >= len(e.history)-maxHistory; i-- {
		h := &e.history[i]
		if h.Key == n.Key && h.Time.Equal(n.Time) && h.Status == n.Status {
			h.Results[channel] = result
			return
		}
	}
	e.history = append(e.history, Sent{Notification: n, Results: map[string]string{channel: result}})
	if len(e.history) > maxHistory {
		e.history = slices.Delete(e.history, 0, len(e.history)-maxHistory)
	}
}

// SetChannels replaces the channels. Channels that are the same as before
// keep their queue.
func (e *Engine) SetChannels(chs []Channel) {
	e.mu.Lock()
	defer e.mu.Unlock()
	keep := map[string]bool{}
	for _, c := range chs {
		id := c.Name() + "\x00" + c.ID()
		keep[id] = true
		if e.chans[id] == nil {
			w := newWorker(e, c)
			e.chans[id] = w
		}
	}
	for id, w := range e.chans {
		if !keep[id] {
			w.stop()
			delete(e.chans, id)
		}
	}
}

// Channels returns the names of the channels in use.
func (e *Engine) Channels() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, w := range e.chans {
		out = append(out, w.ch.Name())
	}
	slices.Sort(out)
	return out
}

// Close stops every channel; queued notifications are dropped.
func (e *Engine) Close() { e.SetChannels(nil) }

func (e *Engine) dispatch(n Notification) {
	e.mu.Lock()
	ws := make([]*worker, 0, len(e.chans))
	for _, w := range e.chans {
		ws = append(ws, w)
	}
	e.mu.Unlock()
	lvl := slog.LevelWarn
	if n.Status == Resolved {
		lvl = slog.LevelInfo
	}
	e.Log.Log(context.Background(), lvl, "alert "+n.Status+": "+n.Summary, "key", n.Key, "node", n.Node)
	for _, w := range ws {
		w.enqueue(n)
	}
}

// SendTest sends a test notification to every channel now and returns how
// each took it.
func (e *Engine) SendTest(ctx context.Context) map[string]string {
	e.mu.Lock()
	n := Notification{Version: 1, Status: Test, Key: "test", Kind: "test", Severity: Warning, Node: e.Server, Server: e.Server,
		Summary: "Test notification from DNSNova: alerts reach this channel.", Time: e.Now().UTC(), Since: e.Now().UTC()}
	ws := make([]*worker, 0, len(e.chans))
	for _, w := range e.chans {
		ws = append(ws, w)
	}
	e.mu.Unlock()
	out := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, w := range ws {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, sendTimeout)
			defer cancel()
			res := "ok"
			if err := w.ch.Send(c, n); err != nil {
				res = err.Error()
			}
			mu.Lock()
			out[w.ch.Name()] = res
			mu.Unlock()
			e.record(n, w.ch.Name(), res)
		}()
	}
	wg.Wait()
	return out
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ---- delivery ----

const (
	sendTimeout = 10 * time.Second
	queueSize   = 64
)

// retryDelays: a failed send is tried again after each of these, then
// given up (and logged).
var retryDelays = []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second}

// worker delivers to one channel, in order, from its own queue: a slow or
// failing channel holds up no other.
type worker struct {
	e      *Engine
	ch     Channel
	q      chan Notification
	ctx    context.Context
	cancel context.CancelFunc
}

func newWorker(e *Engine, ch Channel) *worker {
	ctx, cancel := context.WithCancel(context.Background())
	w := &worker{e: e, ch: ch, q: make(chan Notification, queueSize), ctx: ctx, cancel: cancel}
	go w.run()
	return w
}

func (w *worker) stop() { w.cancel() }

func (w *worker) enqueue(n Notification) {
	select {
	case w.q <- n:
	default:
		w.e.Log.Warn("alert: queue full, notification dropped", "channel", w.ch.Name(), "key", n.Key)
		w.e.record(n, w.ch.Name(), "dropped: queue full")
	}
}

func (w *worker) run() {
	for {
		select {
		case <-w.ctx.Done():
			return
		case n := <-w.q:
			w.deliver(n)
		}
	}
}

func (w *worker) deliver(n Notification) {
	var err error
	for attempt := 0; ; attempt++ {
		c, cancel := context.WithTimeout(w.ctx, sendTimeout)
		err = w.ch.Send(c, n)
		cancel()
		if err == nil || attempt == len(retryDelays) || !retryable(err) {
			break
		}
		select {
		case <-w.ctx.Done():
			return
		case <-time.After(retryDelays[attempt]):
		}
	}
	if err != nil {
		w.e.Log.Error("alert: not delivered", "channel", w.ch.Name(), "key", n.Key, "err", err)
		w.e.record(n, w.ch.Name(), err.Error())
		return
	}
	w.e.record(n, w.ch.Name(), "ok")
}
