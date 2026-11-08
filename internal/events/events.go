// Package events keeps the most recent log records in memory, so the admin
// interface can show what happened (starts, errors, setting changes,
// certificates) without reading the system journal. Queries are never
// logged, so they never appear here.
package events

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Size is how many events are kept.
const Size = 200

// Event is one log record.
type Event struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"` // info, warn, error
	Msg   string    `json:"message"`
}

// Log is a ring of recent events. It is safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	ring [Size]Event
	next int
	n    int
}

// Add records an event.
func (l *Log) Add(e Event) {
	l.mu.Lock()
	l.ring[l.next] = e
	l.next = (l.next + 1) % Size
	if l.n < Size {
		l.n++
	}
	l.mu.Unlock()
}

// Recent returns up to limit events, newest first.
func (l *Log) Recent(limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > l.n {
		limit = l.n
	}
	out := make([]Event, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, l.ring[(l.next-i+Size)%Size])
	}
	return out
}

// Tee returns a handler that passes every record to next and also keeps
// records at Info and above in l. Routine "listening" lines are left out.
func Tee(next slog.Handler, l *Log) slog.Handler { return &tee{next: next, log: l} }

type tee struct {
	next   slog.Handler
	log    *Log
	attrs  []slog.Attr
	groups string
}

func (t *tee) Enabled(ctx context.Context, lv slog.Level) bool {
	return lv >= slog.LevelInfo || t.next.Enabled(ctx, lv)
}

func (t *tee) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelInfo && r.Message != "listening" {
		var b strings.Builder
		b.WriteString(r.Message)
		add := func(a slog.Attr) {
			if a.Equal(slog.Attr{}) {
				return
			}
			fmt.Fprintf(&b, " %s%s=%v", t.groups, a.Key, a.Value.Resolve())
		}
		for _, a := range t.attrs {
			add(a)
		}
		r.Attrs(func(a slog.Attr) bool { add(a); return true })
		t.log.Add(Event{Time: r.Time, Level: level(r.Level), Msg: b.String()})
	}
	if t.next.Enabled(ctx, r.Level) {
		return t.next.Handle(ctx, r)
	}
	return nil
}

func level(lv slog.Level) string {
	switch {
	case lv >= slog.LevelError:
		return "error"
	case lv >= slog.LevelWarn:
		return "warn"
	}
	return "info"
}

func (t *tee) WithAttrs(as []slog.Attr) slog.Handler {
	c := *t
	c.next = t.next.WithAttrs(as)
	for _, a := range as {
		a.Key = t.groups + a.Key
		c.attrs = append(append([]slog.Attr(nil), c.attrs...), a)
	}
	return &c
}

func (t *tee) WithGroup(name string) slog.Handler {
	c := *t
	c.next = t.next.WithGroup(name)
	c.groups = t.groups + name + "."
	return &c
}
