package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/recursor"
)

// Trace implements admin.Backend. With recursion it walks down from the
// root, ignoring the cache; with upstreams only, it asks each one
// directly (validation is theirs then, as their AD bit says).
func (s *Server) Trace(ctx context.Context, name string, qtype uint16) *recursor.TraceResult {
	cfg := s.state.Load().cfg
	if cfg.Recursion.Enabled {
		return s.Rec.Trace(ctx, name, qtype)
	}
	start := time.Now()
	out := &recursor.TraceResult{Name: m.NameString(name), Type: m.TypeString(qtype), DNSSEC: "unchecked",
		Why: "this server forwards to upstreams: DNSSEC is checked by them"}
	for _, r := range s.Lookup(ctx, name, qtype, nil) {
		st := recursor.TraceStep{Kind: "query", Server: r.Upstream, Name: out.Name, Type: out.Type, RTT: r.MS,
			MS: float64(time.Since(start).Microseconds()) / 1000}
		switch {
		case r.Error != "":
			st.Result = "no answer: " + r.Error
		case len(r.Answers) > 0:
			st.Result = fmt.Sprintf("%s: %s", r.Rcode, strings.Join(r.Answers, ", "))
		default:
			st.Result = r.Rcode + ": no records"
		}
		out.Steps = append(out.Steps, st)
		out.Queries++
		if out.Rcode == "" && r.Error == "" {
			out.Rcode, out.Answers = r.Rcode, r.Answers
		}
	}
	if out.Rcode == "" {
		out.Rcode, out.Error = "SERVFAIL", "no upstream answered"
	}
	out.MS = float64(time.Since(start).Microseconds()) / 1000
	return out
}

// DNSSEC implements admin.Backend.
func (s *Server) DNSSEC() admin.DNSSEC {
	c := s.state.Load().cfg
	out := admin.DNSSEC{Recursion: c.Recursion.Enabled, Enabled: c.Recursion.Enabled && c.Recursion.DNSSEC,
		NTAs: slices.Clone(c.Recursion.NegativeTrustAnchors), Failures: []recursor.Failure{}}
	if out.NTAs == nil {
		out.NTAs = []string{}
	}
	if s.Rec != nil {
		out.Secure, out.Insecure, out.Bogus = s.Rec.Stats.Secure.Load(), s.Rec.Stats.Insecure.Load(), s.Rec.Stats.Bogus.Load()
		out.Failures = append(out.Failures, s.Rec.Failures()...)
	}
	return out
}

// ClearDNSSECFailures implements admin.Backend.
func (s *Server) ClearDNSSECFailures() {
	if s.Rec != nil {
		s.Rec.ClearFailures()
	}
}
