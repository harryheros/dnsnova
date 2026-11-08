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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/guard"
	"github.com/harryheros/dnsnova/internal/resolver"
	"github.com/harryheros/dnsnova/internal/stats"
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

	res   *resolver.Resolver
	state atomic.Pointer[state]
	hash  string

	mu      sync.Mutex // serialises reloads and listener changes
	udp     map[string]*udpListener
	tcp     map[string]*tcpListener
	doh     *httpListener
	metrics *httpListener

	udpInflight chan struct{}
	tcpConns    atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New loads the configuration and prepares the server without listening.
func New(store *config.Store, log *slog.Logger) (*Server, error) {
	s := &Server{
		Store:       store,
		Stats:       stats.New(),
		Log:         log,
		udp:         map[string]*udpListener{},
		tcp:         map[string]*tcpListener{},
		udpInflight: make(chan struct{}, 20000),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

func settingsFrom(c *config.Config) resolver.Settings {
	return resolver.Settings{
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncListeners(snap.Config); err != nil {
		s.closeAllLocked()
		return err
	}
	s.state.Store(st)
	s.hash = snap.Hash
	go s.res.Janitor(s.ctx)
	go s.sweeper()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.syncListeners(snap.Config); err != nil {
		st.group.Close()
		return err
	}
	old := s.state.Swap(st)
	s.res.SetSettings(settingsFrom(snap.Config))
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
	want := map[string]bool{}
	for _, a := range c.Server.Listen {
		want[a] = true
	}
	var addedUDP, addedTCP []string
	rollback := func() {
		for _, a := range addedUDP {
			s.udp[a].close()
			delete(s.udp, a)
		}
		for _, a := range addedTCP {
			s.tcp[a].close()
			delete(s.tcp, a)
		}
	}
	for a := range want {
		if _, ok := s.udp[a]; !ok {
			l, err := s.listenUDP(a)
			if err != nil {
				rollback()
				return fmt.Errorf("listen udp %s: %w", a, err)
			}
			s.udp[a] = l
			addedUDP = append(addedUDP, a)
		}
		if _, ok := s.tcp[a]; !ok {
			l, err := s.listenTCP(a)
			if err != nil {
				rollback()
				return fmt.Errorf("listen tcp %s: %w", a, err)
			}
			s.tcp[a] = l
			addedTCP = append(addedTCP, a)
		}
	}
	var newDoH, newMetrics *httpListener
	var err error
	if c.DoH.Listen != "" && (s.doh == nil || s.doh.addr != c.DoH.Listen || s.doh.path != c.DoH.Path) {
		if newDoH, err = s.listenHTTP(c.DoH.Listen, c.DoH.Path, http.HandlerFunc(s.handleDoH)); err != nil {
			rollback()
			return fmt.Errorf("listen doh %s: %w", c.DoH.Listen, err)
		}
	}
	if c.Metrics.Listen != "" && (s.metrics == nil || s.metrics.addr != c.Metrics.Listen) {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", s.handleMetrics)
		mux.HandleFunc("/healthz", s.handleHealth)
		if newMetrics, err = s.listenHTTP(c.Metrics.Listen, "", mux); err != nil {
			rollback()
			if newDoH != nil {
				newDoH.close()
			}
			return fmt.Errorf("listen metrics %s: %w", c.Metrics.Listen, err)
		}
	}

	// Everything new is open: now close what is no longer wanted.
	for a, l := range s.udp {
		if !want[a] {
			l.close()
			delete(s.udp, a)
		}
	}
	for a, l := range s.tcp {
		if !want[a] {
			l.close()
			delete(s.tcp, a)
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
	return nil
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
	if s.doh != nil {
		s.doh.close()
		s.doh = nil
	}
	if s.metrics != nil {
		s.metrics.close()
		s.metrics = nil
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
