package server

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/recursor"
	"github.com/harryheros/dnsnova/internal/resolver"
)

// recursive is the resolver's Exchanger while recursion is on: DNSNova asks
// the authoritative servers itself, and the upstreams only when none of
// them could be reached (never after a DNSSEC failure: the answer would be
// just as wrong there).
//
// While recursion cannot work at all (no name server has answered for a
// while, or the network answers in their place), waiting for each lookup
// to fail before asking the upstreams would add that wait to every query.
// Then the upstreams answer at once, and one lookup at a time still goes
// to the name servers, in the background, so that recursion is used again
// as soon as they answer.
type recursive struct {
	s       *Server
	rec     recursorAPI
	up      resolver.Exchanger // nil: no fallback
	probing atomic.Bool
}

type recursorAPI interface {
	resolver.Exchanger
	Healthy() bool
	Intercepted() bool
}

// probeTimeout bounds a background lookup made while recursion is down.
const probeTimeout = 5 * time.Second

func (x *recursive) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	if x.up != nil && (!x.rec.Healthy() || x.rec.Intercepted()) {
		if x.probing.CompareAndSwap(false, true) {
			q := append([]byte(nil), msg...)
			go func() {
				defer x.probing.Store(false)
				pctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
				defer cancel()
				x.rec.Exchange(pctx, q)
			}()
		}
		x.s.recFallbacks.Add(1)
		return x.up.Exchange(ctx, msg)
	}
	rctx := ctx
	if x.up != nil {
		if dl, ok := ctx.Deadline(); ok { // leave the upstreams time to answer
			var cancel context.CancelFunc
			rctx, cancel = context.WithDeadline(ctx, time.Now().Add(time.Until(dl)*2/3))
			defer cancel()
		}
	}
	resp, err := x.rec.Exchange(rctx, msg)
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
		NTAs:              ntaNames(r.NegativeTrustAnchors),
		Cookies:           r.Cookies,
	}
}

// ntaNames turns domains into the wire names the recursor compares.
func ntaNames(list []string) []string {
	var out []string
	for _, d := range list {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d != "" {
			out = append(out, m.WireName(strings.Split(d, ".")...))
		}
	}
	return out
}

// exchanger returns what the resolver asks: the recursor or the upstreams.
func (s *Server) exchanger(c *config.Config, st *state) resolver.Exchanger {
	if !c.Recursion.Enabled {
		return st.group
	}
	x := &recursive{s: s, rec: s.Rec}
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
		Forged: r.Stats.Forged.Load(), Rewritten: r.Stats.Rewritten.Load(), Intercepted: r.Intercepted(),
		Cache: map[string]int{"rrsets": sets, "negative": negs, "zones": keys, "delegations": delegs, "servers": servers},
	}
}

func (s *Server) writeRecursionMetrics(w io.Writer) {
	r := s.Rec
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_queries_total counter\ndnsnova_recursion_queries_total %d\n", r.Stats.Queries.Load())
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_timeouts_total counter\ndnsnova_recursion_timeouts_total %d\n", r.Stats.Timeouts.Load())
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_fallbacks_total counter\ndnsnova_recursion_fallbacks_total %d\n", s.recFallbacks.Load())
	fmt.Fprintf(w, "# HELP dnsnova_recursion_cookie_rejected_total UDP answers from name servers whose DNS Cookie gave them away as forged (asked again over TCP).\n# TYPE dnsnova_recursion_cookie_rejected_total counter\n")
	fmt.Fprintf(w, "dnsnova_recursion_cookie_rejected_total{reason=\"mismatch\"} %d\n", r.Stats.CookieMismatch.Load())
	fmt.Fprintf(w, "dnsnova_recursion_cookie_rejected_total{reason=\"missing\"} %d\n", r.Stats.CookieMissing.Load())
	fmt.Fprintf(w, "# TYPE dnsnova_recursion_spoofed_total counter\ndnsnova_recursion_spoofed_total %d\n", r.Stats.Spoofed.Load())
	fmt.Fprintf(w, "# HELP dnsnova_recursion_forged_total UDP answers from the path dropped as forged while the genuine answer was waited for.\n# TYPE dnsnova_recursion_forged_total counter\ndnsnova_recursion_forged_total %d\n", r.Stats.Forged.Load())
	fmt.Fprintf(w, "# HELP dnsnova_recursion_rewritten_total Answers no name server sends, over UDP and TCP: the network answers in their place.\n# TYPE dnsnova_recursion_rewritten_total counter\ndnsnova_recursion_rewritten_total %d\n", r.Stats.Rewritten.Load())
	intercepted := 0
	if r.Intercepted() {
		intercepted = 1
	}
	fmt.Fprintf(w, "# HELP dnsnova_recursion_intercepted 1 while the network answers DNS questions in place of the name servers.\n# TYPE dnsnova_recursion_intercepted gauge\ndnsnova_recursion_intercepted %d\n", intercepted)
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
