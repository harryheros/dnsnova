package server

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/recursor"
	"github.com/harryheros/dnsnova/internal/resolver"
)

// recursive is the resolver's Exchanger while recursion is on: DNSNova asks
// the authoritative servers itself, and the upstreams only when none of
// them could be reached (never after a DNSSEC failure: the answer would be
// just as wrong there).
type recursive struct {
	s  *Server
	up resolver.Exchanger // nil: no fallback
}

func (x *recursive) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	rctx := ctx
	if x.up != nil {
		if dl, ok := ctx.Deadline(); ok { // leave the upstreams time to answer
			var cancel context.CancelFunc
			rctx, cancel = context.WithDeadline(ctx, time.Now().Add(time.Until(dl)*2/3))
			defer cancel()
		}
	}
	resp, err := x.s.Rec.Exchange(rctx, msg)
	if err == nil || x.up == nil || ctx.Err() != nil {
		return resp, err
	}
	x.s.recFallbacks.Add(1)
	return x.up.Exchange(ctx, msg)
}

func recConfig(c *config.Config) recursor.Config {
	r := &c.Recursion
	return recursor.Config{
		DNSSEC:            r.DNSSEC,
		QNameMinimisation: r.QNameMinimisation,
		IPv6:              r.IPv6,
		BlockPrivate:      c.Server.Mode == config.ModePublic, // a public server must not be steered into private networks
		Allow:             c.RecursionNetworks(),
		RootHints:         c.RecursionRootHints(),
		TrustAnchors:      r.TrustAnchors,
		CacheSize:         c.Cache.Size,
		ECS:               ecsOption(c),
	}
}

// exchanger returns what the resolver asks: the recursor or the upstreams.
func (s *Server) exchanger(c *config.Config, st *state) resolver.Exchanger {
	if !c.Recursion.Enabled {
		return st.group
	}
	x := &recursive{s: s}
	if c.Recursion.Fallback && len(c.Upstream.Primary) > 0 {
		x.up = st.group
	}
	return x
}

// RecursionStatus implements admin.Backend.
func (s *Server) RecursionStatus() admin.Recursion {
	c := s.state.Load().cfg
	r := s.Rec
	sets, negs, keys, delegs, servers := r.CacheSizes()
	return admin.Recursion{
		Enabled: c.Recursion.Enabled, DNSSEC: c.Recursion.DNSSEC, QNameMinimisation: c.Recursion.QNameMinimisation,
		Fallback: c.Recursion.Fallback && len(c.Upstream.Primary) > 0, Healthy: r.Healthy(),
		Queries: r.Stats.Queries.Load(), Timeouts: r.Stats.Timeouts.Load(), TCP: r.Stats.TCP.Load(),
		Secure: r.Stats.Secure.Load(), Insecure: r.Stats.Insecure.Load(), Bogus: r.Stats.Bogus.Load(),
		Fallbacks: s.recFallbacks.Load(), Spoofed: r.Stats.Spoofed.Load(),
		Cache: map[string]int{"rrsets": sets, "negative": negs, "zones": keys, "delegations": delegs, "servers": servers},
	}
}

func (s *Server) writeRecursionMetrics(w io.Writer) {
	r := s.Rec
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_queries_total counter\ndnsnova_recursion_queries_total %d\n", r.Stats.Queries.Load())
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_timeouts_total counter\ndnsnova_recursion_timeouts_total %d\n", r.Stats.Timeouts.Load())
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_fallbacks_total counter\ndnsnova_recursion_fallbacks_total %d\n", s.recFallbacks.Load())
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_spoofed_total counter\ndnsnova_recursion_spoofed_total %d\n", r.Stats.Spoofed.Load())
	fmt.Fprintf(w, "# TYPE dnsnova_dnssec_answers_total counter\n")
	fmt.Fprintf(w, "dnsnova_dnssec_answers_total{result=\"secure\"} %d\n", r.Stats.Secure.Load())
	fmt.Fprintf(w, "dnsnova_dnssec_answers_total{result=\"insecure\"} %d\n", r.Stats.Insecure.Load())
	fmt.Fprintf(w, "dnsnova_dnssec_answers_total{result=\"bogus\"} %d\n", r.Stats.Bogus.Load())
	sets, negs, keys, delegs, servers := r.CacheSizes()
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_cache_entries gauge\n")
	for k, v := range map[string]int{"rrsets": sets, "negative": negs, "zones": keys, "delegations": delegs, "servers": servers} {
		fmt.Fprintf(w, "dnsnova_recursion_cache_entries{kind=%q} %d\n", k, v)
	}
}
