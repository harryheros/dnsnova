// Package server wires the configuration, guard, resolver and listeners
// together and applies configuration changes without a restart.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/events"
	"github.com/harryheros/dnsnova/internal/guard"
	"github.com/harryheros/dnsnova/internal/insight"
	"github.com/harryheros/dnsnova/internal/resolver"
	"github.com/harryheros/dnsnova/internal/stats"
	"github.com/harryheros/dnsnova/internal/tlsmgr"
	"github.com/harryheros/dnsnova/internal/upstream"
)

// state is everything a query needs, swapped atomically on reload.
type state struct {
	cfg   *config.Config
	guard *guard.Guard
	group *upstream.Group
}

// Server is a running dnsnova instance.
type Server struct {
	Store *config.Store
	Stats *stats.Stats
	Log   *slog.Logger
	// TLS overrides upstream TLS settings (tests only).
	TLS *tls.Config
	// BuildVersion is reported by the admin API.
	BuildVersion string
	// EventLog keeps recent log records for the admin API.
	EventLog *events.Log
	// History keeps counter snapshots for the admin API's charts.
	History *stats.History
	// Domains, NXDomains and Limited count popular domains, domains that
	// do not exist and networks that hit the limits, in memory only.
	Domains, NXDomains, Limited *insight.Top
	probes                      probes
	statusPage                  *admin.StatusPage

	// QLog records queries while an administrator has it running.
	QLog *insight.QueryLog

	res   *resolver.Resolver
	state atomic.Pointer[state]
	snap  atomic.Pointer[config.Snapshot]
	hash  string

	applyMu sync.Mutex // serialises admin API writes
	admin   *admin.Admin
	adminL  *adminListener

	// Certs provides the certificate for DoT, DoQ and DoH (set up by Start).
	Certs *tlsmgr.Manager
	// ACMEHTTP overrides the HTTP client used for ACME (tests only).
	ACMEHTTP *http.Client

	mu      sync.Mutex // serialises reloads and listener changes
	udp     map[string]*udpListener
	tcp     map[string]*tcpListener
	dot     map[string]*tcpListener
	doq     map[string]*quicListener
	https   map[string]*httpListener
	doh     *httpListener
	metrics *httpListener
	tlsDoT  *tls.Config
	tlsDoQ  *tls.Config
	tlsDoH  *tls.Config
	tlsH3   *tls.Config

	udpInflight chan struct{}
	tcpConns    atomic.Int64
	quicConns   atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New loads the configuration and prepares the server without listening.
func New(store *config.Store, log *slog.Logger) (*Server, error) {
	ev := &events.Log{}
	st := stats.New()
	s := &Server{
		Store:       store,
		Stats:       st,
		Log:         slog.New(events.Tee(log.Handler(), ev)),
		EventLog:    ev,
		History:     stats.NewHistory(st),
		Domains:     insight.NewTop(true, 168, time.Now()),
		NXDomains:   insight.NewTop(true, 168, time.Now()),
		Limited:     insight.NewTop(false, 24, time.Now()),
		QLog:        insight.NewQueryLog(),
		udp:         map[string]*udpListener{},
		tcp:         map[string]*tcpListener{},
		dot:         map[string]*tcpListener{},
		doq:         map[string]*quicListener{},
		https:       map[string]*httpListener{},
		udpInflight: make(chan struct{}, 20000),
	}
	s.statusPage = admin.NewStatusPage(s)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

func tlsSettings(c *config.Config) tlsmgr.Settings {
	t := tlsmgr.Settings{
		Mode:       c.TLS.Certificate,
		Domains:    c.TLS.Domains,
		Email:      c.TLS.Email,
		Directory:  c.TLS.ACMEDirectory,
		Challenge:  c.TLS.Challenge,
		HTTPListen: c.TLS.HTTPChallengeListen,
		CertFile:   c.TLS.CertFile,
		KeyFile:    c.TLS.KeyFile,
	}
	if c.TLS.IPAddresses {
		t.IPs = c.PublicListenIPs()
	}
	return t
}

// ddrFrom describes the encrypted endpoints to advertise, or nothing when
// DDR is off or there is no encrypted listener or resolver name.
func ddrFrom(c *config.Config) [][]byte {
	if !c.DDR.Enabled || c.TLS.Certificate == "off" || len(c.TLS.Domains) == 0 {
		return nil
	}
	d := resolver.DDR{Name: c.TLS.Domains[0], DoHPath: c.DoH.Path}
	port := func(list []string) int {
		for _, a := range list {
			if ap, err := netip.ParseAddrPort(a); err == nil {
				return int(ap.Port())
			}
		}
		return 0
	}
	d.DoTPort, d.DoQPort, d.DoHPort = port(c.DoT.Listen), port(c.DoQ.Listen), port(c.DoH.HTTPSListen)
	d.HTTP3 = c.DoH.HTTP3
	ips := c.PublicListenIPs()
	if len(ips) == 0 { // a private deployment: hint the listen addresses as they are
		for _, a := range c.Server.Listen {
			if ap, err := netip.ParseAddrPort(a); err == nil && !ap.Addr().IsUnspecified() {
				ips = append(ips, ap.Addr().Unmap())
			}
		}
	}
	for _, a := range ips {
		if a.Is4() {
			d.IPv4 = append(d.IPv4, a)
		} else {
			d.IPv6 = append(d.IPv6, a)
		}
	}
	return d.Records()
}

// checkZone is the zone of the status page's check names, when the status
// page is on and there is a domain.
func checkZone(c *config.Config) string {
	if !c.Status.Enabled || len(c.TLS.Domains) == 0 {
		return ""
	}
	return m.WireName(append([]string{"check"}, strings.Split(strings.ToLower(c.TLS.Domains[0]), ".")...)...)
}

// applyRetention sizes the in-memory statistics to stats.retention.
func (s *Server) applyRetention(c *config.Config) {
	h := config.RetentionHours[c.Stats.Retention]
	if h == 0 {
		h = 7 * 24
	}
	s.History.SetHours(h + 1)
	s.Domains.SetHours(h)
	s.NXDomains.SetHours(h)
}

// ClearStats implements admin.Backend: it forgets the statistics and the
// domain lists. Prometheus counters keep counting.
func (s *Server) ClearStats() {
	now := time.Now()
	s.History.Reset(now)
	s.Domains.Reset(now)
	s.NXDomains.Reset(now)
	s.Limited.Reset(now)
}

func localNames(c *config.Config) *resolver.LocalNames {
	recs, _ := config.ParseLocalRecords(c.Local.Records) // validated when loaded
	return resolver.NewLocalNames(recs)
}

func settingsFrom(c *config.Config) resolver.Settings {
	return resolver.Settings{
		DDR:                 ddrFrom(c),
		CheckZone:           checkZone(c),
		Local:               localNames(c),
		CacheSize:           c.Cache.Size,
		MinTTL:              c.Cache.MinTTL,
		MaxTTL:              c.Cache.MaxTTL,
		MaxNegTTL:           c.Cache.MaxNegativeTTL,
		ServeStale:          c.Cache.ServeStale,
		Prefetch:            c.Cache.Prefetch,
		BlockANY:            c.Limits.BlockANY,
		UDPMaxSize:          c.Limits.UDPMaxSize,
		Timeout:             c.Upstream.Timeout,
		UpstreamConcurrency: c.Limits.UpstreamConcurrency,
		ZoneConcurrency:     c.Limits.ZoneConcurrency,
	}
}

func (s *Server) buildState(c *config.Config) (*state, error) {
	g, err := upstream.NewGroup(upstream.Options{
		Primary:       c.Upstream.Primary,
		Fallback:      c.Upstream.Fallback,
		Bootstrap:     c.Upstream.Bootstrap,
		Parallel:      c.Upstream.Parallel,
		Timeout:       c.Upstream.Timeout,
		FallbackDelay: c.Upstream.FallbackDelay,
		TLS:           s.TLS,
	})
	if err != nil {
		return nil, err
	}
	gd := guard.New(guard.Limits{
		Private:      c.Server.Mode == config.ModePrivate,
		Allow:        guard.ACL(c.Access.Allow),
		Deny:         guard.ACL(c.Access.Deny),
		ClientQPS:    c.Limits.ClientQPS,
		ClientBurst:  c.Limits.ClientBurst,
		NetworkQPS:   c.Limits.PrefixQPS,
		NetworkBurst: c.Limits.PrefixBurst,
		GlobalQPS:    c.Limits.GlobalQPS,
		RRLRate:      c.Limits.RRLRate,
		RRLSlip:      c.Limits.RRLSlip,
	})
	return &state{cfg: c, guard: gd, group: g}, nil
}

// Start loads the configuration and opens every listener.
func (s *Server) Start() error {
	snap, err := s.Store.Load()
	if err != nil {
		return err
	}
	for _, w := range snap.Warnings {
		s.Log.Warn(w)
	}
	st, err := s.buildState(snap.Config)
	if err != nil {
		return err
	}
	s.res = resolver.New(settingsFrom(snap.Config), st.group, s.Stats)
	s.applyRetention(snap.Config)
	s.Certs = tlsmgr.NewManager(snap.Config.Server.DataDir, s.Log)
	s.Certs.HTTP = s.ACMEHTTP
	s.tlsDoT = s.Certs.TLSConfig("dot")
	s.tlsDoQ = s.Certs.TLSConfig("doq")
	s.tlsDoH = s.Certs.TLSConfig("h2", "http/1.1")
	s.tlsH3 = s.Certs.TLSConfig("h3")
	if err := s.Certs.Configure(tlsSettings(snap.Config)); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Store(st) // before any listener can receive a query
	s.snap.Store(snap)
	if err := s.syncListeners(snap.Config); err != nil {
		s.closeAllLocked()
		return err
	}
	s.hash = snap.Hash
	go s.res.Janitor(s.ctx)
	go s.sweeper()
	go s.Certs.Run(s.ctx)
	go s.recordHistory()
	s.Log.Info("dnsnova started", "mode", snap.Config.Server.Mode,
		"upstreams", len(snap.Config.Upstream.Primary), "fallbacks", len(snap.Config.Upstream.Fallback))
	return nil
}

// Reload re-reads the configuration file and applies it. On any error the
// running configuration stays in place.
func (s *Server) Reload() error {
	snap, err := s.Store.Load()
	if err != nil {
		return err
	}
	for _, w := range snap.Warnings {
		s.Log.Warn(w)
	}
	return s.Apply(snap)
}

// Apply switches to a loaded configuration: new listeners are opened first,
// then the state is swapped, then removed listeners are closed. Cached
// answers and statistics are kept.
func (s *Server) Apply(snap *config.Snapshot) error {
	st, err := s.buildState(snap.Config)
	if err != nil {
		return err
	}
	if old := s.state.Load(); old != nil && old.cfg.Server.DataDir != snap.Config.Server.DataDir {
		s.Log.Warn("server.data_dir changes take effect after a restart")
	}
	if err := s.Certs.Configure(tlsSettings(snap.Config)); err != nil {
		st.group.Close()
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncListeners(snap.Config); err != nil {
		st.group.Close()
		return err
	}
	old := s.state.Swap(st)
	s.snap.Store(snap)
	s.res.SetSettings(settingsFrom(snap.Config))
	s.applyRetention(snap.Config)
	s.res.SetUpstreams(st.group)
	s.hash = snap.Hash
	if old != nil {
		go func() { // let in-flight queries on the old upstreams finish
			time.Sleep(10 * time.Second)
			old.group.Close()
		}()
	}
	s.Log.Info("configuration applied", "mode", snap.Config.Server.Mode)
	return nil
}

// syncListeners opens listeners that the configuration adds and closes the
// ones it removes. If opening fails, nothing is closed and the new ones are
// rolled back.
func (s *Server) syncListeners(c *config.Config) error {
	type change struct{ undo func() }
	var changes []change
	var reopen []func() // put back listeners closed early to make room
	rollback := func() {
		for _, ch := range changes {
			ch.undo()
		}
		for _, f := range reopen {
			f()
		}
	}
	// A wildcard address and a specific one on the same port cannot both be
	// bound (":53" and "192.168.1.9:53"). When the configuration swaps one
	// for the other, close the old listener first.
	room := func(name string, m map[string]func(), want map[string]bool, open func(string) error) {
		for old, closeOld := range m {
			if want[old] {
				continue
			}
			for a := range want {
				if _, ok := m[a]; !ok && collide(old, a) {
					closeOld()
					o := old
					reopen = append(reopen, func() {
						if err := open(o); err != nil {
							s.Log.Error("could not reopen listener", "proto", name, "addr", o, "err", err)
						}
					})
					break
				}
			}
		}
	}
	{
		um := map[string]func(){}
		for a, l := range s.udp {
			a, l := a, l
			um[a] = func() { l.close(); delete(s.udp, a) }
		}
		room("udp", um, wantSet(c.Server.Listen), func(a string) error {
			l, err := s.listenUDP(a)
			if err == nil {
				s.udp[a] = l
			}
			return err
		})
		for _, x := range []struct {
			m     map[string]*tcpListener
			addrs []string
			tls   *tls.Config
			proto int
			name  string
		}{{s.tcp, c.Server.Listen, nil, stats.TCP, "tcp"}, {s.dot, c.DoT.Listen, s.tlsDoT, stats.DoT, "dot"}} {
			tm := map[string]func(){}
			for a, l := range x.m {
				a, l, m := a, l, x.m
				tm[a] = func() { l.close(); delete(m, a) }
			}
			room(x.name, tm, wantSet(x.addrs), func(a string) error {
				l, err := s.listenTCP(a, x.tls, x.proto, x.name)
				if err == nil {
					x.m[a] = l
				}
				return err
			})
		}
		qm := map[string]func(){}
		for a, l := range s.doq {
			a, l := a, l
			qm[a] = func() { l.close(); delete(s.doq, a) }
		}
		room("doq", qm, wantSet(c.DoQ.Listen), func(a string) error {
			l, err := s.listenDoQ(a, s.tlsDoQ)
			if err == nil {
				s.doq[a] = l
			}
			return err
		})
	}
	// stream listeners: plain TCP and DoT share one implementation
	streams := []struct {
		m     map[string]*tcpListener
		addrs []string
		tls   *tls.Config
		proto int
		name  string
	}{
		{s.tcp, c.Server.Listen, nil, stats.TCP, "tcp"},
		{s.dot, c.DoT.Listen, s.tlsDoT, stats.DoT, "dot"},
	}
	for a := range wantSet(c.Server.Listen) {
		if _, ok := s.udp[a]; !ok {
			l, err := s.listenUDP(a)
			if err != nil {
				rollback()
				return fmt.Errorf("listen udp %s: %w", a, err)
			}
			s.udp[a] = l
			a := a
			changes = append(changes, change{undo: func() { l.close(); delete(s.udp, a) }})
		}
	}
	for _, st := range streams {
		for a := range wantSet(st.addrs) {
			if _, ok := st.m[a]; ok {
				continue
			}
			l, err := s.listenTCP(a, st.tls, st.proto, st.name)
			if err != nil {
				rollback()
				return fmt.Errorf("listen %s %s: %w", st.name, a, err)
			}
			st.m[a] = l
			m, a := st.m, a
			changes = append(changes, change{undo: func() { l.close(); delete(m, a) }})
		}
	}
	for a := range wantSet(c.DoQ.Listen) {
		if _, ok := s.doq[a]; ok {
			continue
		}
		l, err := s.listenDoQ(a, s.tlsDoQ)
		if err != nil {
			rollback()
			return fmt.Errorf("listen doq %s: %w", a, err)
		}
		s.doq[a] = l
		a := a
		changes = append(changes, change{undo: func() { l.close(); delete(s.doq, a) }})
	}
	var h3Conf *tls.Config
	if c.DoH.HTTP3 {
		h3Conf = s.tlsH3
	}
	for a := range wantSet(c.DoH.HTTPSListen) {
		old, ok := s.https[a]
		if ok && old.path == c.DoH.Path && (old.h3 != nil) == c.DoH.HTTP3 {
			continue
		}
		if ok { // the path or HTTP/3 changed: the address must be released first
			old.close()
			delete(s.https, a)
		}
		l, err := s.listenHTTPS(a, c.DoH.Path, http.HandlerFunc(s.handleDoH), s.tlsDoH, h3Conf)
		if err != nil {
			rollback()
			return fmt.Errorf("listen https %s: %w", a, err)
		}
		s.https[a] = l
		a := a
		changes = append(changes, change{undo: func() { l.close(); delete(s.https, a) }})
	}
	var newDoH, newMetrics *httpListener
	var err error
	if c.DoH.Listen != "" && (s.doh == nil || s.doh.addr != c.DoH.Listen || s.doh.path != c.DoH.Path) {
		if newDoH, err = s.listenHTTP(c.DoH.Listen, c.DoH.Path, http.HandlerFunc(s.handleDoH), nil); err != nil {
			rollback()
			return fmt.Errorf("listen doh %s: %w", c.DoH.Listen, err)
		}
	}
	var newAdmin *adminListener
	if c.Admin.Listen != "" && (s.adminL == nil || s.adminL.addr != c.Admin.Listen) {
		var err error
		newAdmin, err = s.listenAdmin(c.Admin.Listen)
		if err != nil && s.adminL != nil && collide(s.adminL.addr, c.Admin.Listen) {
			// ":7000" to "127.0.0.1:7000": stop accepting on the old socket
			// (the request making this change still finishes) and bind again.
			s.adminL.ln.Close()
			if newAdmin, err = s.listenAdmin(c.Admin.Listen); err != nil {
				if back, e2 := s.listenAdmin(s.adminL.addr); e2 == nil {
					old := s.adminL
					s.adminL = back
					go old.close()
				}
			}
		}
		if err != nil {
			rollback()
			if newDoH != nil {
				newDoH.close()
			}
			return fmt.Errorf("listen admin %s: %w", c.Admin.Listen, err)
		}
		changes = append(changes, change{undo: func() { newAdmin.close() }})
	}
	if c.Metrics.Listen != "" && (s.metrics == nil || s.metrics.addr != c.Metrics.Listen) {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", s.handleMetrics)
		mux.HandleFunc("/healthz", s.handleHealth)
		if newMetrics, err = s.listenHTTP(c.Metrics.Listen, "", mux, nil); err != nil {
			rollback()
			if newDoH != nil {
				newDoH.close()
			}
			return fmt.Errorf("listen metrics %s: %w", c.Metrics.Listen, err)
		}
	}

	// Everything new is open: now close what is no longer wanted.
	want := wantSet(c.Server.Listen)
	for a, l := range s.udp {
		if !want[a] {
			l.close()
			delete(s.udp, a)
		}
	}
	for _, st := range streams {
		w := wantSet(st.addrs)
		for a, l := range st.m {
			if !w[a] {
				l.close()
				delete(st.m, a)
			}
		}
	}
	wq := wantSet(c.DoQ.Listen)
	for a, l := range s.doq {
		if !wq[a] {
			l.close()
			delete(s.doq, a)
		}
	}
	wh := wantSet(c.DoH.HTTPSListen)
	for a, l := range s.https {
		if !wh[a] {
			l.close()
			delete(s.https, a)
		}
	}
	if newDoH != nil || c.DoH.Listen == "" {
		if s.doh != nil {
			s.doh.close()
		}
		s.doh = newDoH
	}
	if newMetrics != nil || c.Metrics.Listen == "" {
		if s.metrics != nil {
			s.metrics.close()
		}
		s.metrics = newMetrics
	}
	if newAdmin != nil || c.Admin.Listen == "" {
		if old := s.adminL; old != nil {
			// The request that made this change may be running on the old
			// listener: close it in the background so it can finish.
			go old.close()
		}
		s.adminL = newAdmin
	}
	return nil
}

// collide reports whether two listen addresses cannot be bound together:
// the same port, and one of them on every address.
func collide(a, b string) bool {
	ia, ib := strings.LastIndex(a, ":"), strings.LastIndex(b, ":")
	if ia < 0 || ib < 0 || a[ia:] != b[ib:] {
		return false
	}
	wild := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "[::]" || h == "::" }
	return wild(a[:ia]) || wild(b[:ib])
}

func wantSet(list []string) map[string]bool {
	m := map[string]bool{}
	for _, a := range list {
		m[a] = true
	}
	return m
}

// Endpoints returns the bound DoT and HTTPS DoH addresses.
func (s *Server) Endpoints() (dot, https []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.dot {
		dot = append(dot, l.ln.Addr().String())
	}
	for _, l := range s.https {
		https = append(https, l.ln.Addr().String())
	}
	slices.Sort(dot)
	slices.Sort(https)
	return
}

// QUICEndpoints returns the bound DoQ and HTTP/3 (UDP) addresses.
func (s *Server) QUICEndpoints() (doq, h3 []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.doq {
		doq = append(doq, l.pc.LocalAddr().String())
	}
	for _, l := range s.https {
		if l.h3 != nil {
			h3 = append(h3, l.h3.pc.LocalAddr().String())
		}
	}
	slices.Sort(doq)
	slices.Sort(h3)
	return
}

// Addrs returns the bound addresses (useful when listening on port 0).
func (s *Server) Addrs() (udp, tcp []string, doh, metrics string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.udp {
		udp = append(udp, l.conn.LocalAddr().String())
	}
	for _, l := range s.tcp {
		tcp = append(tcp, l.ln.Addr().String())
	}
	slices.Sort(udp)
	slices.Sort(tcp)
	if s.doh != nil {
		doh = s.doh.ln.Addr().String()
	}
	if s.metrics != nil {
		metrics = s.metrics.ln.Addr().String()
	}
	return
}

// Resolver exposes the resolver (for the admin API and tests).
func (s *Server) Resolver() *resolver.Resolver { return s.res }

// Shutdown closes every listener and waits for in-flight queries.
func (s *Server) Shutdown() {
	s.cancel()
	s.mu.Lock()
	s.closeAllLocked()
	s.mu.Unlock()
	s.wg.Wait()
	if st := s.state.Load(); st != nil {
		st.group.Close()
	}
}

func (s *Server) closeAllLocked() {
	for a, l := range s.udp {
		l.close()
		delete(s.udp, a)
	}
	for a, l := range s.tcp {
		l.close()
		delete(s.tcp, a)
	}
	for a, l := range s.dot {
		l.close()
		delete(s.dot, a)
	}
	for a, l := range s.doq {
		l.close()
		delete(s.doq, a)
	}
	for a, l := range s.https {
		l.close()
		delete(s.https, a)
	}
	if s.doh != nil {
		s.doh.close()
		s.doh = nil
	}
	if s.metrics != nil {
		s.metrics.close()
		s.metrics = nil
	}
	if s.adminL != nil {
		s.adminL.close()
		s.adminL = nil
	}
}

// recordHistory samples the counters once a minute for the admin charts.
func (s *Server) recordHistory() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-t.C:
			s.History.Tick(now)
			s.Domains.Roll(now)
			s.NXDomains.Roll(now)
			s.Limited.Roll(now)
			s.probes.sweep(now)
		}
	}
}

// WatchConfig reloads the configuration when the file changes on disk.
func (s *Server) WatchConfig(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			if s.Store.Changed() {
				if err := s.Reload(); err != nil {
					s.Log.Error("configuration file changed but was not applied", "err", err)
				}
			}
		}
	}
}

func (s *Server) sweeper() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			if st := s.state.Load(); st != nil {
				st.guard.Sweep()
			}
		}
	}
}

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }
