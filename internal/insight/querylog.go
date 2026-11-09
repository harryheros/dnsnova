package insight

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// QueryLogSize is how many queries the query log keeps.
const QueryLogSize = 10000

// QueryLogKeep is how long records stay after the query log stops.
const QueryLogKeep = time.Hour

// Query is one record of the query log.
type Query struct {
	Time   time.Time `json:"time"`
	Client string    `json:"client"` // masked unless the log was started with full addresses
	Proto  string    `json:"proto"`
	Name   string    `json:"name"`
	Type   string    `json:"type"`
	Rcode  string    `json:"rcode"`
	Source string    `json:"source"` // cache, stale, upstream, local, blocked
	MS     float64   `json:"ms"`
	// Filtered: the query came in through the filtered service.
	Filtered bool `json:"filtered,omitempty"`
}

// QueryLogState says whether the query log is running.
type QueryLogState struct {
	On      bool      `json:"on"`
	Until   time.Time `json:"until,omitzero"`   // when it stops by itself
	FullIP  bool      `json:"full_ip"`          // whether addresses are kept whole
	Stopped time.Time `json:"stopped,omitzero"` // when it last stopped
	Count   int       `json:"count"`            // records held
}

// QueryLog is a ring of recent queries that runs only for a limited time
// and only when an administrator starts it.
type QueryLog struct {
	mu      sync.Mutex
	buf     []Query
	head, n int
	until   time.Time
	fullIP  bool
	stopped time.Time
	on      bool
	active  atomic.Bool // mirrors on, for a lock-free check on every query
}

// NewQueryLog returns a stopped query log.
func NewQueryLog() *QueryLog { return &QueryLog{} }

// On reports whether the log is recording. It is cheap enough to call for
// every query; the time limit is checked when a record is added.
func (l *QueryLog) On() bool { return l.active.Load() }

// expire stops the log once its time is up and drops records an hour after
// it stopped. It reports whether the log is running. l.mu must be held.
func (l *QueryLog) expire(now time.Time) bool {
	if l.on && !now.Before(l.until) {
		l.on = false
		l.active.Store(false)
		l.stopped = l.until
	}
	if !l.on && l.n > 0 && now.Sub(l.stopped) >= QueryLogKeep {
		l.clear()
	}
	return l.on
}

func (l *QueryLog) clear() {
	l.buf, l.head, l.n = nil, 0, 0
}

// Start records queries for d. Records from an earlier run are dropped.
func (l *QueryLog) Start(d time.Duration, fullIP bool, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clear()
	l.buf = make([]Query, QueryLogSize)
	l.on, l.until, l.fullIP = true, now.Add(d), fullIP
	l.active.Store(true)
}

// Stop stops recording and drops every record.
func (l *QueryLog) Stop(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.on {
		l.stopped = now
	}
	l.on = false
	l.active.Store(false)
	l.clear()
}

// Add records one query if the log is running.
func (l *QueryLog) Add(q Query, ip netip.Addr) {
	if !l.active.Load() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.expire(q.Time) {
		return
	}
	if l.fullIP {
		q.Client = ip.Unmap().String()
	} else {
		q.Client = Mask(ip)
	}
	l.buf[l.head] = q
	l.head = (l.head + 1) % len(l.buf)
	if l.n < len(l.buf) {
		l.n++
	}
}

// State describes the log at now.
func (l *QueryLog) State(now time.Time) QueryLogState {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expire(now)
	st := QueryLogState{On: l.on, FullIP: l.fullIP && (l.on || l.n > 0), Stopped: l.stopped, Count: l.n}
	if l.on {
		st.Until = l.until
	}
	return st
}

// Recent returns up to limit records, newest first, whose name or client
// contains filter (if set).
func (l *QueryLog) Recent(limit int, filter string, now time.Time) []Query {
	filter = strings.ToLower(strings.TrimSpace(filter))
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expire(now)
	out := []Query{}
	for i := 0; i < l.n && len(out) < limit; i++ {
		q := l.buf[(l.head-1-i+2*len(l.buf))%len(l.buf)]
		if filter == "" || strings.Contains(q.Name, filter) || strings.Contains(q.Client, filter) {
			out = append(out, q)
		}
	}
	return out
}

// Mask hides the host part of an address: 203.0.113.x for IPv4 and the
// first 48 bits for IPv6 (2001:db8:1::/48).
func Mask(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.x", b[0], b[1], b[2])
	}
	return NetworkOf(ip).String()
}
