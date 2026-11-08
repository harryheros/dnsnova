// Package stats keeps dnsnova's counters in memory and renders them in the
// Prometheus text format. Nothing here is ever written to disk.
package stats

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// Protocols.
const (
	UDP = iota
	TCP
	DoT
	DoH
	numProto
)

var protoNames = [numProto]string{"udp", "tcp", "dot", "doh"}

// Rejection reasons.
const (
	RejectACL = iota
	RejectClientLimit
	RejectNetworkLimit
	RejectGlobalLimit
	RejectRRLDrop
	RejectRRLSlip
	RejectOverload
	RejectUpstreamBusy
	RejectZoneBusy
	RejectMalformed
	numReject
)

var rejectNames = [numReject]string{
	"acl", "client_limit", "network_limit", "global_limit", "rrl_drop", "rrl_slip",
	"overload", "upstream_busy", "zone_busy", "malformed",
}

// Answer sources.
const (
	SourceCache = iota
	SourceStale
	SourceUpstream
	SourceLocal
	numSource
)

var sourceNames = [numSource]string{"cache", "stale", "upstream", "local"}

// Stats is the set of counters for one server.
type Stats struct {
	Queries   [numProto]atomic.Uint64
	Rejected  [numReject]atomic.Uint64
	Sources   [numSource]atomic.Uint64
	Rcodes    [7]atomic.Uint64 // NOERROR..REFUSED, then other
	Refreshes atomic.Uint64
	Truncated atomic.Uint64

	LatencyCache    *Histogram
	LatencyUpstream *Histogram
	Started         time.Time
}

// New returns empty counters.
func New() *Stats {
	return &Stats{
		LatencyCache:    NewHistogram(),
		LatencyUpstream: NewHistogram(),
		Started:         time.Now(),
	}
}

// Rcode counts one response code.
func (s *Stats) Rcode(rc int) {
	if rc >= 0 && rc < 6 {
		s.Rcodes[rc].Add(1)
	} else {
		s.Rcodes[6].Add(1)
	}
}

// Histogram counts durations in fixed buckets.
type Histogram struct {
	bounds []float64 // upper bounds in seconds
	counts []atomic.Uint64
	sumNs  atomic.Uint64
	count  atomic.Uint64
}

// DefaultBounds suit DNS: from 0.1 ms (cache) to 5 s (slow upstream).
var DefaultBounds = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

// NewHistogram returns a histogram with DefaultBounds.
func NewHistogram() *Histogram {
	return &Histogram{bounds: DefaultBounds, counts: make([]atomic.Uint64, len(DefaultBounds)+1)}
}

// Observe records one duration.
func (h *Histogram) Observe(d time.Duration) {
	s := d.Seconds()
	i := 0
	for i < len(h.bounds) && s > h.bounds[i] {
		i++
	}
	h.counts[i].Add(1)
	h.sumNs.Add(uint64(d))
	h.count.Add(1)
}

// Quantile estimates quantile q (0..1) by linear interpolation in buckets.
func (h *Histogram) Quantile(q float64) time.Duration {
	total := h.count.Load()
	if total == 0 {
		return 0
	}
	rank := q * float64(total)
	var cum float64
	lower := 0.0
	for i := range h.counts {
		c := float64(h.counts[i].Load())
		upper := lower * 2
		if i < len(h.bounds) {
			upper = h.bounds[i]
		}
		if cum+c >= rank && c > 0 {
			frac := (rank - cum) / c
			return time.Duration((lower + frac*(upper-lower)) * float64(time.Second))
		}
		cum += c
		lower = upper
	}
	return time.Duration(lower * float64(time.Second))
}

func (h *Histogram) write(w io.Writer, name, labels string) {
	var cum uint64
	sep := ""
	if labels != "" {
		sep = ","
	}
	for i, b := range h.bounds {
		cum += h.counts[i].Load()
		fmt.Fprintf(w, "%s_bucket{%s%sle=\"%g\"} %d\n", name, labels, sep, b, cum)
	}
	cum += h.counts[len(h.bounds)].Load()
	fmt.Fprintf(w, "%s_bucket{%s%sle=\"+Inf\"} %d\n", name, labels, sep, cum)
	fmt.Fprintf(w, "%s_sum{%s} %g\n", name, labels, float64(h.sumNs.Load())/1e9)
	fmt.Fprintf(w, "%s_count{%s} %d\n", name, labels, h.count.Load())
}

// WritePrometheus renders the counters.
func (s *Stats) WritePrometheus(w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("# HELP dnsnova_queries_total Queries received, by protocol.")
	p("# TYPE dnsnova_queries_total counter")
	for i, n := range protoNames {
		p(`dnsnova_queries_total{proto=%q} %d`, n, s.Queries[i].Load())
	}
	p("# HELP dnsnova_rejected_total Queries or responses refused or dropped, by reason.")
	p("# TYPE dnsnova_rejected_total counter")
	for i, n := range rejectNames {
		p(`dnsnova_rejected_total{reason=%q} %d`, n, s.Rejected[i].Load())
	}
	p("# HELP dnsnova_answers_total Answers sent, by where they came from.")
	p("# TYPE dnsnova_answers_total counter")
	for i, n := range sourceNames {
		p(`dnsnova_answers_total{source=%q} %d`, n, s.Sources[i].Load())
	}
	p("# HELP dnsnova_responses_total Responses sent, by response code.")
	p("# TYPE dnsnova_responses_total counter")
	for i, n := range []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "other"} {
		p(`dnsnova_responses_total{rcode=%q} %d`, n, s.Rcodes[i].Load())
	}
	p("# TYPE dnsnova_cache_refreshes_total counter")
	p("dnsnova_cache_refreshes_total %d", s.Refreshes.Load())
	p("# TYPE dnsnova_truncated_total counter")
	p("dnsnova_truncated_total %d", s.Truncated.Load())
	p("# HELP dnsnova_response_seconds Time to answer, by answer source.")
	p("# TYPE dnsnova_response_seconds histogram")
	s.LatencyCache.write(w, "dnsnova_response_seconds", `source="cache"`)
	s.LatencyUpstream.write(w, "dnsnova_response_seconds", `source="upstream"`)
	p("# TYPE dnsnova_uptime_seconds gauge")
	p("dnsnova_uptime_seconds %d", int(time.Since(s.Started).Seconds()))
}
