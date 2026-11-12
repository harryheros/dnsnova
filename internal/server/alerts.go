package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/alert"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/filter"
	"github.com/harryheros/dnsnova/internal/recursor"
	"github.com/harryheros/dnsnova/internal/stats"
	"github.com/harryheros/dnsnova/internal/tlsmgr"
)

// ---- alerts ----
//
// Every alertEvery the server looks at itself (the counters over the last
// alertWindow, its upstreams, certificate, lists, cluster and anycast
// state) and hands what is wrong to the alert engine, which notifies.
// Nothing here is on the path of a query.

const (
	alertEvery  = 30 * time.Second
	alertWindow = 5 * time.Minute
	// an upstream is failing when at least half of at least this many
	// queries in the window failed
	failingMinQueries = 20
	maxNodeAlerts     = 50
)

type alertState struct {
	mu      sync.Mutex
	engine  *alert.Engine
	secrets *alert.Secrets
	path    string // data_dir/secrets/alerts.json
	samples []alertSample
	// the last automatic reload of the configuration file that failed
	reloadErr string
	// primary: the followers' alerts, as last reported (kept while a
	// node is offline, so they do not look resolved)
	nodeAlerts map[string][]alert.Condition
	enabled    bool
}

type alertSample struct {
	t       time.Time
	counts  stats.Counts
	bogus   int64
	members map[string][2]uint64 // upstream: queries, errors
}

// upstreamWindow is one upstream over the window.
type upstreamWindow struct {
	addr            string
	healthy         bool
	queries, errors uint64
}

// alertInput is everything the checks look at; evaluate turns it into
// conditions, and does nothing else (so it can be tested alone).
type alertInput struct {
	cfg       config.Alerts
	node      string
	now       time.Time
	span      time.Duration // the window the counts cover
	counts    stats.Counts  // over span
	bogus     int64         // answers refused for DNSSEC, over span
	recursion bool
	upstreams []upstreamWindow
	failures  []recursor.Failure
	certMode  string
	cert      tlsmgr.Status
	reloadErr string
	lists     []filter.ListStatus
	configErr string // follower: the primary's configuration does not work here
	anycast   string // announced, withdrawn or "" (off)
}

func pct(f float64) string { return fmt.Sprintf("%.1f%%", f*100) }

func evaluate(in alertInput) []alert.Condition {
	a := in.cfg
	var out []alert.Condition
	add := func(c alert.Condition) {
		c.Node = in.node
		if c.Kind == "" {
			c.Kind, _, _ = strings.Cut(c.Key, ":")
		}
		out = append(out, c)
	}
	mins := fmt.Sprintf("%d minutes", max(int(in.span.Round(time.Minute)/time.Minute), 1))

	// upstreams (when they answer the queries, not with recursion)
	if !in.recursion && len(in.upstreams) > 0 {
		down := true
		var errs uint64
		for _, u := range in.upstreams {
			errs += u.errors
			if u.healthy {
				down = false
			}
		}
		if down && errs > 0 {
			var d []string
			for _, u := range in.upstreams {
				d = append(d, fmt.Sprintf("%s: %d of %d queries failed", u.addr, u.errors, u.queries))
			}
			add(alert.Condition{Key: "upstreams_down", Severity: alert.Critical, For: a.UpstreamDownFor,
				Summary: "Every upstream is failing: queries not in the cache get no answer", Details: d})
		} else {
			for _, u := range in.upstreams {
				if u.queries >= failingMinQueries && u.errors*2 >= u.queries {
					add(alert.Condition{Key: "upstream_failing:" + u.addr, Severity: alert.Warning, For: a.UpstreamFailingFor,
						Summary: "Upstream " + u.addr + " is failing",
						Details: []string{fmt.Sprintf("%d of %d queries failed in the last %s; the others answer instead", u.errors, u.queries, mins)}})
				}
			}
		}
	}

	// SERVFAIL, DNSSEC failures aside (those have their own check)
	if a.ServfailRatio > 0 && in.counts.Answers >= uint64(max(a.ServfailMinQueries, 1)) {
		sf := int64(in.counts.ServFail) - in.bogus
		if r := float64(max(sf, 0)) / float64(in.counts.Answers); r >= a.ServfailRatio {
			sev := alert.Warning
			if r >= 0.5 {
				sev = alert.Critical
			}
			add(alert.Condition{Key: "servfail_rate", Severity: sev, For: a.ServfailFor,
				Summary: "Many queries fail (SERVFAIL " + pct(r) + ")",
				Details: []string{fmt.Sprintf("%d of %d answers in the last %s were SERVFAIL (threshold %s)", sf, in.counts.Answers, mins, pct(a.ServfailRatio))}})
		}
	}

	// how long queries not in the cache take
	if a.LatencyP95 > 0 && in.counts.UpstreamQueries() >= uint64(max(a.LatencyMinQueries, 1)) {
		if p := in.counts.UpstreamQuantile(0.95); p > a.LatencyP95 {
			add(alert.Condition{Key: "latency_p95", Severity: alert.Warning, For: a.LatencyFor,
				Summary: fmt.Sprintf("Slow answers: 95%% of queries not in the cache take up to %s", p.Round(time.Millisecond)),
				Details: []string{fmt.Sprintf("over %d such queries in the last %s (threshold %s)", in.counts.UpstreamQueries(), mins, a.LatencyP95)}})
		}
	}

	// DNSSEC
	if a.DNSSECFailures > 0 && in.bogus >= int64(a.DNSSECFailures) {
		var d []string
		recent := slices.DeleteFunc(slices.Clone(in.failures), func(f recursor.Failure) bool { return in.now.Sub(f.Last) > in.span })
		slices.SortFunc(recent, func(x, y recursor.Failure) int { return int(y.Count - x.Count) })
		for i, f := range recent {
			if i == 5 {
				d = append(d, fmt.Sprintf("and %d more names: see the DNSSEC page", len(recent)-5))
				break
			}
			d = append(d, fmt.Sprintf("%s %s: %s (%s)", f.Name, f.Type, f.EDE, f.Why))
		}
		add(alert.Condition{Key: "dnssec_failures", Severity: alert.Warning,
			Summary: fmt.Sprintf("%d answers refused for failing DNSSEC validation in the last %s", in.bogus, mins), Details: d})
	}

	// the certificate
	if in.certMode != "" && in.certMode != "off" {
		c := in.cert
		if c.Ready && !c.NotAfter.IsZero() && a.CertWarnDays > 0 {
			left := c.NotAfter.Sub(in.now)
			days := int(left.Hours() / 24)
			switch {
			case left <= 0:
				add(alert.Condition{Key: "cert_expiry", Severity: alert.Critical, Summary: "The TLS certificate has expired: DoT, DoH and DoQ clients refuse it",
					Details: []string{"expired " + c.NotAfter.UTC().Format("2006-01-02 15:04 UTC")}})
			case left <= time.Duration(a.CertCriticalDays)*24*time.Hour:
				add(alert.Condition{Key: "cert_expiry", Severity: alert.Critical, Summary: fmt.Sprintf("The TLS certificate expires in %d days", days),
					Details: []string{"expires " + c.NotAfter.UTC().Format("2006-01-02 15:04 UTC")}})
			case left <= time.Duration(a.CertWarnDays)*24*time.Hour:
				add(alert.Condition{Key: "cert_expiry", Severity: alert.Warning, Summary: fmt.Sprintf("The TLS certificate expires in %d days", days),
					Details: []string{"expires " + c.NotAfter.UTC().Format("2006-01-02 15:04 UTC")}})
			}
		}
		if c.LastError != "" {
			d := []string{c.LastError}
			if !c.NextAttempt.IsZero() {
				d = append(d, "next attempt "+c.NextAttempt.UTC().Format("2006-01-02 15:04 UTC"))
			}
			sev, sum := alert.Warning, "The TLS certificate could not be renewed"
			if !c.Ready {
				sev, sum = alert.Critical, "No TLS certificate: DoT, DoH and DoQ do not work"
			}
			add(alert.Condition{Key: "cert_renewal", Severity: sev, Summary: sum, Details: d})
		}
	}

	if in.reloadErr != "" {
		add(alert.Condition{Key: "config_reload", Severity: alert.Warning,
			Summary: "The configuration file changed but was not applied; the previous configuration stays in force",
			Details: []string{in.reloadErr}})
	}
	for _, l := range in.lists {
		if l.Error != "" {
			add(alert.Condition{Key: "filter_update:" + l.Source, Severity: alert.Warning,
				Summary: "A block list could not be updated; its previous copy stays in use",
				Details: []string{l.Source + ": " + l.Error}})
		}
	}
	if in.configErr != "" {
		add(alert.Condition{Key: "config_refused", Severity: alert.Warning,
			Summary: "This node cannot apply the cluster's configuration; it keeps its last good one",
			Details: []string{in.configErr}})
	}
	if in.anycast == anycastWithdrawn {
		add(alert.Condition{Key: "anycast_withdrawn", Severity: alert.Critical, For: time.Minute,
			Summary: "The anycast route is withdrawn: this node's health checks fail"})
	}
	return out
}

// startAlerts makes the engine and starts the checks; they do nothing
// until [alerts] enabled.
func (s *Server) startAlerts(c *config.Config) {
	s.al.engine.SetServer(s.cl.name)
	path := filepath.Join(c.Server.DataDir, "secrets", "alerts.json")
	sec, err := alert.LoadSecrets(path)
	if err != nil {
		s.Log.Error("alerts: cannot read the notification settings; none are sent until they are saved again", "err", err)
		sec = &alert.Secrets{}
	}
	s.al.mu.Lock()
	s.al.path, s.al.secrets = path, sec
	s.al.mu.Unlock()
	s.applyAlerts(c)
	s.alertTick(time.Now()) // the first sample: the window starts here
	go s.alertLoop()
	go alert.Heartbeat(s.ctx, func() string {
		s.al.mu.Lock()
		defer s.al.mu.Unlock()
		if !s.al.enabled {
			return ""
		}
		return s.al.secrets.Heartbeat.URL
	}, time.Minute, s.Log)
}

// applyAlerts takes a new configuration's [alerts].
func (s *Server) applyAlerts(c *config.Config) {
	s.al.mu.Lock()
	if s.al.path == "" { // not started
		s.al.mu.Unlock()
		return
	}
	was := s.al.enabled
	s.al.enabled = c.Alerts.Enabled
	var chs []alert.Channel
	// a follower notifies nothing itself: its primary sends for it
	if c.Alerts.Enabled && s.cl.run.Role != "follower" {
		chs = s.al.secrets.Channels()
	}
	s.al.mu.Unlock()
	s.al.engine.SetRepeat(c.Alerts.Repeat)
	s.al.engine.SetChannels(chs)
	if was && !c.Alerts.Enabled {
		s.al.engine.Reset()
	}
}

func (s *Server) alertLoop() {
	t := time.NewTicker(alertEvery)
	defer t.Stop()
	defer s.al.engine.Close()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.alertTick(now)
		}
	}
}

// alertTick takes a sample and, with alerts on, evaluates.
func (s *Server) alertTick(now time.Time) {
	st := s.state.Load()
	if st == nil {
		return
	}
	cur := alertSample{t: now, counts: s.Stats.Counts(), bogus: s.Rec.Stats.Bogus.Load(), members: map[string][2]uint64{}}
	members := st.group.Members()
	for _, m := range members {
		cur.members[m.U.String()] = [2]uint64{m.Queries(), m.Errors()}
	}
	s.al.mu.Lock()
	s.al.samples = append(s.al.samples, cur)
	// keep what covers the window: the oldest sample at most alertWindow old
	for len(s.al.samples) > 2 && now.Sub(s.al.samples[1].t) >= alertWindow {
		s.al.samples = s.al.samples[1:]
	}
	old := s.al.samples[0]
	enabled, reloadErr := s.al.enabled, s.al.reloadErr
	s.al.mu.Unlock()
	if !enabled {
		return
	}
	cfg := st.cfg
	in := alertInput{cfg: cfg.Alerts, node: s.cl.name, now: now, span: now.Sub(old.t), counts: cur.counts.Since(old.counts),
		bogus: max(cur.bogus-old.bogus, 0), recursion: cfg.Recursion.Enabled, certMode: cfg.TLS.Certificate, reloadErr: reloadErr}
	if in.span < alertEvery { // just started: no window yet, only what needs none
		in.counts, in.bogus = stats.Counts{}, 0
	}
	for _, m := range members {
		addr := m.U.String()
		c, o := cur.members[addr], old.members[addr]
		if c[0] < o[0] || c[1] < o[1] {
			o = [2]uint64{}
		}
		in.upstreams = append(in.upstreams, upstreamWindow{addr: addr, healthy: m.Healthy(), queries: c[0] - o[0], errors: c[1] - o[1]})
	}
	if in.bogus > 0 {
		in.failures = s.Rec.Failures()
	}
	if s.Certs != nil {
		in.cert = s.Certs.Status()
	}
	if s.Filter != nil {
		in.lists = s.Filter.Status().Lists
	}
	s.cl.mu.Lock()
	in.configErr = s.cl.configErr
	s.cl.mu.Unlock()
	if cfg.Anycast.Enabled {
		in.anycast = s.anycastState()
	}
	conds := evaluate(in)
	if s.cl.run.Role == "primary" && cfg.Alerts.Nodes {
		conds = append(conds, s.nodeConditions()...)
	}
	s.al.engine.Update(conds)
}

// nodeConditions are the followers' alerts, under their names, and the
// followers that stopped reporting.
func (s *Server) nodeConditions() []alert.Condition {
	cl := s.Cluster()
	s.al.mu.Lock()
	defer s.al.mu.Unlock()
	var out []alert.Condition
	for _, n := range cl.Nodes {
		if n.Self {
			continue
		}
		if !n.Online {
			out = append(out, alert.Condition{Key: n.Name + "/node_offline", Kind: "node_offline", Severity: alert.Critical, Node: n.Name,
				Summary: "Node " + n.Name + " stopped reporting to the primary",
				Details: []string{"last seen " + n.LastSeen.UTC().Format("2006-01-02 15:04:05 UTC") + "; its last alerts are kept until it is back"}})
		}
		for _, c := range s.al.nodeAlerts[n.Name] {
			c.Key, c.Node, c.For = n.Name+"/"+c.Key, n.Name, 0
			out = append(out, c)
		}
	}
	return out
}

// noteNodeAlerts keeps what a follower reported.
func (s *Server) noteNodeAlerts(node string, conds []alert.Condition) {
	if len(conds) > maxNodeAlerts {
		conds = conds[:maxNodeAlerts]
	}
	clip := func(x string, n int) string {
		if len(x) > n {
			return x[:n]
		}
		return x
	}
	for i := range conds {
		c := &conds[i]
		c.Key, c.Kind, c.Summary = clip(c.Key, 300), clip(c.Kind, 50), clip(c.Summary, 300)
		if c.Severity != alert.Critical {
			c.Severity = alert.Warning
		}
		if len(c.Details) > 10 {
			c.Details = c.Details[:10]
		}
		for j := range c.Details {
			c.Details[j] = clip(c.Details[j], 500)
		}
	}
	s.al.mu.Lock()
	defer s.al.mu.Unlock()
	if s.al.nodeAlerts == nil {
		s.al.nodeAlerts = map[string][]alert.Condition{}
	}
	s.al.nodeAlerts[node] = conds
}

// firingAlerts are this node's alerts for its report to the primary.
func (s *Server) firingAlerts() []alert.Condition {
	return s.al.engine.Firing()
}

// noteReload records how the last automatic reload went.
func (s *Server) noteReload(err error) {
	s.al.mu.Lock()
	defer s.al.mu.Unlock()
	if err == nil {
		s.al.reloadErr = ""
	} else {
		s.al.reloadErr = err.Error()
	}
}

// ---- admin API ----

// Alerts implements admin.Backend.
func (s *Server) Alerts() admin.Alerts {
	out := admin.Alerts{Role: s.cl.run.Role}
	s.al.mu.Lock()
	out.Enabled, out.Destinations = s.al.enabled, s.al.secrets.Show()
	s.al.mu.Unlock()
	out.Channels = s.al.engine.Channels()
	out.Active = s.al.engine.Active()
	out.History = s.al.engine.History()
	if out.Active == nil {
		out.Active = []alert.Active{}
	}
	if out.History == nil {
		out.History = []alert.Sent{}
	}
	return out
}

// SetAlertDestination implements admin.Backend: it changes where
// notifications go (empty fields: nowhere) and saves it.
func (s *Server) SetAlertDestination(name string, fields map[string]string) error {
	s.al.mu.Lock()
	if s.al.path == "" {
		s.al.mu.Unlock()
		return errors.New("not started")
	}
	next := *s.al.secrets
	if err := next.Set(name, fields); err != nil {
		s.al.mu.Unlock()
		return err
	}
	if err := next.Save(s.al.path); err != nil {
		s.al.mu.Unlock()
		return fmt.Errorf("could not save: %w", err)
	}
	s.al.secrets = &next
	s.al.mu.Unlock()
	if st := s.state.Load(); st != nil {
		s.applyAlerts(st.cfg)
	}
	return nil
}

// TestAlerts implements admin.Backend: a test notification to every
// channel, now.
func (s *Server) TestAlerts(ctx context.Context) (map[string]string, error) {
	s.al.mu.Lock()
	enabled := s.al.enabled
	s.al.mu.Unlock()
	switch {
	case s.cl.run.Role == "follower":
		return nil, errors.New("this node is a cluster follower: its primary sends the notifications")
	case !enabled:
		return nil, errors.New("alerts are off: turn on alerts.enabled first")
	case len(s.al.engine.Channels()) == 0:
		return nil, errors.New("no destination is set up")
	}
	return s.al.engine.SendTest(ctx), nil
}
