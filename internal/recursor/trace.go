package recursor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// ---- tracing one lookup ----
//
// Trace resolves a name from scratch, as dig +trace does, and records each
// step: every server asked and what it said, every CNAME followed, and the
// DNSSEC verdict on each zone's keys and each answer. It ignores what the
// cache holds (what it learns is stored as usual), so it shows how the name
// resolves now. An ordinary query has no trace: one nil check per step.

// TraceStep is one step of a trace.
type TraceStep struct {
	MS     float64 `json:"ms"`    // since the trace started
	Depth  int     `json:"depth"` // nesting: lookups made on the way (name server addresses, DS, DNSKEY)
	Kind   string  `json:"kind"`  // query, cname, keys, validate
	Zone   string  `json:"zone,omitempty"`
	Server string  `json:"server,omitempty"`
	Name   string  `json:"name,omitempty"`
	Type   string  `json:"type,omitempty"`
	RTT    float64 `json:"rtt_ms,omitempty"`
	Result string  `json:"result"`
	// DNSSEC: secure, insecure or bogus, and why
	Sec string `json:"dnssec,omitempty"`
	Why string `json:"why,omitempty"`
}

// TraceResult is a finished trace.
type TraceResult struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Rcode    string      `json:"rcode"`
	DNSSEC   string      `json:"dnssec"` // secure, insecure, bogus or unchecked
	EDE      string      `json:"ede,omitempty"`
	Why      string      `json:"why,omitempty"`
	Answers  []string    `json:"answers,omitempty"`
	MS       float64     `json:"ms"`
	Queries  int         `json:"queries"`
	Error    string      `json:"error,omitempty"`
	Steps    []TraceStep `json:"steps"`
	Truncate bool        `json:"truncated,omitempty"` // more steps than kept
}

const maxTraceSteps = 400

// tracer has no lock: one lookup (its task) runs on one goroutine, and a
// trace joins no other lookup in flight. (A lock would also make every
// task's fields escape to the heap, a cost on every query.)
type tracer struct {
	start time.Time
	steps []TraceStep
	cut   bool
}

func (tr *tracer) add(t *task, s TraceStep) {
	if len(tr.steps) >= maxTraceSteps {
		tr.cut = true
		return
	}
	s.MS = float64(time.Since(tr.start).Microseconds()) / 1000
	s.Depth = max(t.depth-1, 0)
	tr.steps = append(tr.steps, s)
}

// Trace resolves name (wire format) and type from scratch and records how.
func (r *Recursor) Trace(ctx context.Context, name string, qtype uint16) *TraceResult {
	cfg := r.cfg.Load()
	t := newTask()
	t.budget = 2 * maxQueriesPerTask // nothing comes from the cache
	t.trace = &tracer{start: time.Now()}
	t.fresh = true
	out := &TraceResult{Name: m.NameString(name), Type: m.TypeString(qtype)}
	r.netMu.RLock()
	ans, err := r.resolve(ctx, t, name, qtype, cfg.DNSSEC)
	r.netMu.RUnlock()
	out.MS = float64(time.Since(t.trace.start).Microseconds()) / 1000
	out.Queries = 2*maxQueriesPerTask - t.budget
	out.Steps, out.Truncate = t.trace.steps, t.trace.cut
	if err != nil {
		out.Rcode, out.Error = "SERVFAIL", err.Error()
		if errors.Is(err, errBudget) {
			out.Error = "gave up: too many queries for one name"
		}
		return out
	}
	out.Rcode, out.DNSSEC = m.RcodeString(ans.rcode), ans.sec.String()
	if ans.sec == secBogus {
		out.Rcode = "SERVFAIL" // what clients get
	}
	if ans.ede != 0 {
		out.EDE = EDEText(ans.ede)
	}
	out.Why = ans.why
	if out.Why == "" && ans.sec == secInsecure { // why it is not checked (no DS, an NTA)
		for i := len(out.Steps) - 1; i >= 0; i-- {
			if st := out.Steps[i]; st.Kind == "validate" && st.Sec == "insecure" && st.Why != "" {
				out.Why = st.Why
				break
			}
		}
	}
	for _, cs := range ans.chain {
		for _, rec := range cs.set.records() {
			out.Answers = append(out.Answers, describeRR(rec))
		}
	}
	return out
}

// traceQuery records one question to one server and what came of it.
func (r *Recursor) traceQuery(t *task, zone string, a netip.Addr, name string, qtype uint16, rtt time.Duration, msg *message, err error, lame bool) {
	s := TraceStep{Kind: "query", Zone: zoneName(zone), Server: a.String(), Name: m.NameString(name), Type: m.TypeString(qtype),
		RTT: float64(rtt.Microseconds()) / 1000}
	switch {
	case err != nil:
		s.Result = "no answer: " + err.Error()
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			s.Result = "no answer (timeout)"
		}
	case msg.rcode != m.RcodeNoError && msg.rcode != m.RcodeNXDomain:
		s.Result = "refused to answer: " + m.RcodeString(msg.rcode) + "; next server"
	case lame:
		s.Result = "not authoritative for this name (lame); next server"
	default:
		if child, _ := referral(msg, zone, name); child != nil {
			s.Result = "referral to " + zoneName(child.zone) + " (" + strings.Join(nsNames(child), ", ") + ")"
		} else if msg.rcode == m.RcodeNXDomain {
			s.Result = "NXDOMAIN: the name does not exist"
		} else if n := len(msg.answer); n > 0 {
			s.Result = fmt.Sprintf("answer: %d record%s", n, plural(n))
		} else {
			s.Result = "no records of this type (NODATA)"
		}
	}
	t.trace.add(t, s)
}

func nsNames(d *delegation) []string {
	var out []string
	for i, h := range d.ns {
		if i == 3 {
			out = append(out, fmt.Sprintf("+%d more", len(d.ns)-3))
			break
		}
		out = append(out, m.NameString(h.name))
	}
	return out
}

func zoneName(z string) string {
	if z == "" {
		return "."
	}
	return m.NameString(z)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// describeRR renders a record in zone file style, data short.
func describeRR(x rr) string {
	var data string
	switch x.typ {
	case m.TypeA, m.TypeAAAA:
		if a, ok := netip.AddrFromSlice(x.data); ok {
			data = a.Unmap().String()
		}
	case m.TypeCNAME, m.TypeNS, typeDNAME:
		data = m.NameString(lower(nameOf(x.data)))
	default:
		data = fmt.Sprintf("(%d bytes)", len(x.data))
	}
	return fmt.Sprintf("%s %d %s %s", m.NameString(x.name), x.ttl, m.TypeString(x.typ), data)
}

// EDEText names an Extended DNS Error code (RFC 8914).
func EDEText(code uint16) string {
	names := map[uint16]string{0: "Other", 1: "Unsupported DNSKEY Algorithm", 2: "Unsupported DS Digest Type", 3: "Stale Answer",
		4: "Forged Answer", 5: "DNSSEC Indeterminate", 6: "DNSSEC Bogus", 7: "Signature Expired", 8: "Signature Not Yet Valid",
		9: "DNSKEY Missing", 10: "RRSIGs Missing", 11: "No Zone Key Bit Set", 12: "NSEC Missing", 13: "Cached Error",
		14: "Not Ready", 15: "Blocked", 16: "Censored", 17: "Filtered", 18: "Prohibited", 19: "Stale NXDOMAIN Answer",
		20: "Not Authoritative", 21: "Not Supported", 22: "No Reachable Authority", 23: "Network Error", 24: "Invalid Data",
		27: "Unsupported NSEC3 Iterations Value"}
	if n, ok := names[code]; ok {
		return n
	}
	return fmt.Sprintf("code %d", code)
}

// ---- DNSSEC failures, for the admin's DNSSEC page ----

// Failure is a name whose answers failed validation (and were refused to
// clients), most recent last. No client data is kept.
type Failure struct {
	Name  string    `json:"name"`
	Type  string    `json:"type"`
	EDE   string    `json:"ede"`
	Why   string    `json:"why"`
	Count int64     `json:"count"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

const maxFailures = 200

type failureLog struct {
	mu sync.Mutex
	m  map[string]*Failure // by name and type
}

func (l *failureLog) add(name string, qtype uint16, ede uint16, why string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*Failure{}
	}
	key := tkey(name, qtype)
	f := l.m[key]
	if f == nil {
		if len(l.m) >= maxFailures { // forget the one seen longest ago
			var oldest string
			for k, v := range l.m {
				if oldest == "" || v.Last.Before(l.m[oldest].Last) {
					oldest = k
				}
			}
			delete(l.m, oldest)
		}
		f = &Failure{Name: m.NameString(name), Type: m.TypeString(qtype), First: now}
		l.m[key] = f
	}
	f.Count++
	f.Last, f.EDE, f.Why = now, EDEText(ede), why
}

// Failures returns the names that failed validation, most recent first.
func (r *Recursor) Failures() []Failure {
	r.failures.mu.Lock()
	out := make([]Failure, 0, len(r.failures.m))
	for _, f := range r.failures.m {
		out = append(out, *f)
	}
	r.failures.mu.Unlock()
	slices.SortFunc(out, func(a, b Failure) int { return b.Last.Compare(a.Last) })
	return out
}

// ClearFailures forgets them.
func (r *Recursor) ClearFailures() {
	r.failures.mu.Lock()
	r.failures.m = nil
	r.failures.mu.Unlock()
}

// ---- negative trust anchors (RFC 7646) ----

// underNTA returns the negative trust anchor covering name, if any: a
// domain whose DNSSEC the operator knows to be broken, below which
// answers are treated as unsigned rather than refused.
func (r *Recursor) underNTA(name string) (string, bool) {
	for _, d := range r.cfg.Load().NTAs {
		if isSub(name, d) {
			return d, true
		}
	}
	return "", false
}

func ntaWhy(d string) string {
	return "not validated: " + zoneName(d) + " is a negative trust anchor (recursion.negative_trust_anchors)"
}
