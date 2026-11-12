package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/cluster"
	"github.com/harryheros/dnsnova/internal/config"
)

// A cluster is optional: with no [cluster] role nothing here runs, and the
// query path never touches it either way. Each node keeps its own cache.

// sharedFile is a follower's copy of the primary's configuration, in
// data_dir, so it starts with its last settings when the primary is down.
const sharedFile = "cluster-shared.toml"

// keyFile is the cluster key under data_dir/secrets.
const keyFile = "cluster-key"

// clusterState is the cluster side of a Server.
type clusterState struct {
	mu   sync.Mutex
	run  config.Cluster // the settings it started with
	name string

	// follower
	shared      []byte // the primary's configuration last received
	sharedHash  string
	overrides   []string
	lastSync    time.Time
	syncErr     string
	configErr   string
	primaryName string
	follower    *cluster.Follower

	// primary
	ln        net.Listener
	srv       *http.Server
	nodes     map[string]*admin.Node
	timeouts  map[string]time.Duration // how long until a node counts as offline
	outSrc    []byte                   // the shared configuration handed out
	outHash   string
	outOfHash string // the snapshot it was made from
}

// followerLocal is what a follower reads from its own file before it has
// a whole configuration.
type followerLocal struct {
	dataDir, primary, name string
}

func readFollowerLocal(raw []byte) (followerLocal, error) {
	doc, err := config.Parse(raw)
	if err != nil {
		return followerLocal{}, err
	}
	str := func(table, key, def string) string {
		if e := doc.Lookup(table, key); e != nil && e.Value.Kind == config.String {
			return e.Value.Str
		}
		return def
	}
	return followerLocal{
		dataDir: str("server", "data_dir", config.Defaults().Server.DataDir),
		primary: str("cluster", "primary", ""),
		name:    str("cluster", "name", ""),
	}, nil
}

// loadSnapshot reads the configuration: the file, or for a follower the
// primary's configuration with the file's settings on top.
func (s *Server) loadSnapshot() (*config.Snapshot, error) {
	raw, err := s.Store.LoadRaw()
	if err != nil {
		return nil, err
	}
	follower, err := config.IsFollower(raw)
	if err != nil || !follower {
		return s.Store.Load()
	}
	loc, err := readFollowerLocal(raw)
	if err != nil {
		return nil, err
	}
	s.cl.mu.Lock()
	shared := s.cl.shared
	s.cl.mu.Unlock()
	if shared == nil {
		if b, err := os.ReadFile(filepath.Join(loc.dataDir, sharedFile)); err == nil {
			shared = b
		} else if shared, err = s.firstSync(loc); err != nil {
			return nil, fmt.Errorf("cluster: no copy of the primary's configuration yet, and the primary (%s) could not be reached: %w", loc.primary, err)
		}
		s.cl.mu.Lock()
		s.cl.shared, s.cl.sharedHash = shared, config.HashOf(shared)
		s.cl.mu.Unlock()
	}
	return s.mergeSnapshot(shared, raw)
}

func (s *Server) mergeSnapshot(shared, local []byte) (*config.Snapshot, error) {
	merged, keys, err := config.Merge(shared, local)
	if err != nil {
		return nil, err
	}
	cfg, doc, warns, err := config.Load(merged)
	if err != nil {
		return nil, err
	}
	s.cl.mu.Lock()
	s.cl.overrides = keys
	s.cl.mu.Unlock()
	return &config.Snapshot{Config: cfg, Doc: doc, Hash: config.HashOf(merged), Warnings: warns}, nil
}

// firstSync fetches the configuration when a follower starts with none.
func (s *Server) firstSync(loc followerLocal) ([]byte, error) {
	key, _, err := cluster.LoadKey(filepath.Join(loc.dataDir, "secrets", keyFile), false)
	if err != nil {
		return nil, fmt.Errorf("cluster key: %w (copy secrets/%s from the primary)", err, keyFile)
	}
	f := cluster.NewFollower(key, loc.primary)
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	reply, err := f.Sync(ctx, cluster.Report{Node: nodeName(loc.name), Version: s.Version(), Status: "setup"})
	if err != nil {
		return nil, err
	}
	if reply.Config == "" || config.HashOf([]byte(reply.Config)) != reply.Hash {
		return nil, errors.New("the primary sent no usable configuration")
	}
	if err := writeShared(loc.dataDir, []byte(reply.Config)); err != nil {
		return nil, err
	}
	s.cl.mu.Lock()
	s.cl.primaryName, s.cl.lastSync = reply.Primary, time.Now()
	s.cl.mu.Unlock()
	return []byte(reply.Config), nil
}

func writeShared(dataDir string, src []byte) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dataDir, sharedFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, src, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func nodeName(configured string) string {
	if configured != "" {
		return configured
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "dnsnova"
}

// startCluster starts the cluster role once the server runs. Changes to
// [cluster] apply after a restart.
func (s *Server) startCluster(c *config.Config) error {
	s.cl.run = c.Cluster
	s.cl.name = nodeName(c.Cluster.Name)
	keyPath := filepath.Join(c.Server.DataDir, "secrets", keyFile)
	switch c.Cluster.Role {
	case "primary":
		key, created, err := cluster.LoadKey(keyPath, true)
		if err != nil {
			return fmt.Errorf("cluster key: %w", err)
		}
		if created {
			s.Log.Warn("cluster: a new cluster key was made; copy " + keyPath + " to every follower (same path, mode 0600)")
		}
		p := cluster.NewPrimary(key, s.cl.name)
		p.Shared = s.sharedOut
		p.OnReport = s.noteNode
		p.OnReject = func(from netip.Addr, err error) {
			s.Log.Warn("cluster: request refused", "from", from.String(), "err", err)
		}
		ln, err := net.Listen("tcp", c.Cluster.Listen)
		if err != nil {
			return fmt.Errorf("listen cluster %s: %w", c.Cluster.Listen, err)
		}
		srv := &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
			WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10}
		s.cl.ln, s.cl.srv, s.cl.nodes, s.cl.timeouts = ln, srv, map[string]*admin.Node{}, map[string]time.Duration{}
		go srv.Serve(ln)
		s.Log.Info("listening", "proto", "cluster", "addr", ln.Addr().String(), "node", s.cl.name)
	case "follower":
		key, _, err := cluster.LoadKey(keyPath, false)
		if err != nil {
			return fmt.Errorf("cluster key: %w (copy secrets/%s from the primary)", err, keyFile)
		}
		s.cl.follower = cluster.NewFollower(key, c.Cluster.Primary)
		go s.followLoop(c.Cluster.Interval)
		s.Log.Info("cluster: following", "primary", c.Cluster.Primary, "node", s.cl.name)
	}
	return nil
}

func (s *Server) stopCluster() {
	if s.cl.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.cl.srv.Shutdown(ctx)
	}
}

// ClusterAddr is the primary's cluster address ("" otherwise; tests).
func (s *Server) ClusterAddr() string {
	if s.cl.ln == nil {
		return ""
	}
	return s.cl.ln.Addr().String()
}

// sharedOut is what the primary hands out: its configuration without the
// node-local tables, made again only when the configuration changed.
func (s *Server) sharedOut() ([]byte, string) {
	snap := s.snap.Load()
	s.cl.mu.Lock()
	defer s.cl.mu.Unlock()
	if s.cl.outOfHash != snap.Hash {
		out, err := config.SharedPart(snap.Doc.Src)
		if err != nil {
			out = nil // cannot happen: the snapshot parsed
		}
		s.cl.outSrc, s.cl.outHash, s.cl.outOfHash = out, config.HashOf(out), snap.Hash
	}
	return s.cl.outSrc, s.cl.outHash
}

// noteNode records a follower's report (on the primary).
func (s *Server) noteNode(r cluster.Report, from netip.Addr) {
	_, hash := s.sharedOut()
	n := &admin.Node{
		Name: r.Node, Region: r.Region, Address: from.String(), Online: true, LastSeen: time.Now(),
		Version: r.Version, Status: r.Status, Anycast: r.Anycast, ConfigError: r.ConfigError,
		InSync: r.Have == hash && r.ConfigError == "", Uptime: r.Uptime, Overrides: r.Overrides,
	}
	if r.CertUntil > 0 {
		n.CertUntil = time.Unix(r.CertUntil, 0)
	}
	s.cl.mu.Lock()
	defer s.cl.mu.Unlock()
	old := s.cl.nodes[r.Node]
	if old == nil && len(s.cl.nodes) >= 1000 {
		return // a cluster of this size is not what this is for
	}
	if old == nil {
		s.Log.Info("cluster: node joined", "node", r.Node, "from", from.String(), "version", r.Version)
	}
	s.cl.nodes[r.Node] = n
	s.noteNodeAlerts(r.Node, r.Alerts)
	// it counts as offline after three missed syncs
	s.cl.timeouts[r.Node] = 3*time.Duration(max(r.Interval, 1))*time.Second + 5*time.Second
}

// followLoop syncs with the primary until the server stops.
func (s *Server) followLoop(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.syncOnce()
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncOnce reports to the primary and applies a new configuration if it
// sent one. A configuration that does not work here is not applied: the
// node keeps the last good one and reports the error.
func (s *Server) syncOnce() {
	ctx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()
	reply, err := s.cl.follower.Sync(ctx, s.nodeReport())
	s.cl.mu.Lock()
	prevErr := s.cl.syncErr
	if err != nil {
		s.cl.syncErr = err.Error()
		s.cl.mu.Unlock()
		if prevErr != err.Error() {
			s.Log.Warn("cluster: cannot sync with the primary; keeping the current settings", "primary", s.cl.run.Primary, "err", err)
		}
		return
	}
	s.cl.syncErr, s.cl.lastSync, s.cl.primaryName = "", time.Now(), reply.Primary
	have := s.cl.sharedHash
	s.cl.mu.Unlock()
	if prevErr != "" {
		s.Log.Info("cluster: in touch with the primary again", "primary", reply.Primary)
	}
	if reply.Config == "" || reply.Hash == have {
		return
	}
	if config.HashOf([]byte(reply.Config)) != reply.Hash {
		s.Log.Warn("cluster: the primary's configuration does not match its hash; ignored")
		return
	}
	s.applyShared([]byte(reply.Config))
}

// applyShared applies a new configuration from the primary.
func (s *Server) applyShared(shared []byte) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	fail := func(err error) {
		s.cl.mu.Lock()
		changed := s.cl.configErr != err.Error()
		s.cl.configErr = err.Error()
		s.cl.mu.Unlock()
		if changed {
			s.Log.Error("cluster: the primary's configuration was not applied here; keeping the last one", "err", err)
		}
	}
	raw, err := s.Store.LoadRaw()
	if err != nil {
		fail(err)
		return
	}
	snap, err := s.mergeSnapshot(shared, raw)
	if err != nil {
		fail(err)
		return
	}
	if err := s.Apply(snap); err != nil {
		fail(err)
		return
	}
	if err := writeShared(snap.Config.Server.DataDir, shared); err != nil {
		s.Log.Warn("cluster: could not keep a copy of the configuration", "err", err)
	}
	s.cl.mu.Lock()
	s.cl.shared, s.cl.sharedHash, s.cl.configErr = shared, config.HashOf(shared), ""
	s.cl.mu.Unlock()
	s.Log.Info("cluster: configuration from the primary applied", "hash", config.HashOf(shared)[:12])
}

// nodeReport describes this node for its primary (and the Nodes page).
func (s *Server) nodeReport() cluster.Report {
	st := s.snap.Load()
	status, _ := s.health()
	s.cl.mu.Lock()
	r := cluster.Report{
		Node: s.cl.name, Region: s.cl.run.Region, Version: s.Version(), Have: s.cl.sharedHash,
		ConfigError: s.cl.configErr, Overrides: slices.Clone(s.cl.overrides), Status: status,
		Uptime: int64(time.Since(s.Stats.Started).Seconds()), Interval: int64(s.cl.run.Interval / time.Second),
	}
	s.cl.mu.Unlock()
	if s.cl.run.Role == "follower" {
		r.Alerts = s.firingAlerts()
	}
	if st != nil && st.Config.Anycast.Enabled {
		r.Anycast = s.anycastState()
	}
	if s.Certs != nil {
		if c := s.Certs.Status(); c.Ready && !c.NotAfter.IsZero() {
			r.CertUntil = c.NotAfter.Unix()
		}
	}
	return r
}

// Cluster implements admin.Backend.
func (s *Server) Cluster() admin.Cluster {
	self := s.nodeReport()
	s.cl.mu.Lock()
	defer s.cl.mu.Unlock()
	out := admin.Cluster{Role: s.cl.run.Role, Name: s.cl.name, Region: s.cl.run.Region}
	switch s.cl.run.Role {
	case "follower":
		out.Primary, out.PrimaryName, out.LastSync, out.SyncError = s.cl.run.Primary, s.cl.primaryName, s.cl.lastSync, s.cl.syncErr
		out.ConfigHash, out.Overrides = s.cl.sharedHash, slices.Clone(s.cl.overrides)
		if s.cl.configErr != "" {
			out.SyncError = s.cl.configErr
		}
	case "primary":
		me := admin.Node{Name: s.cl.name, Region: s.cl.run.Region, Self: true, Online: true, LastSeen: time.Now(),
			Version: self.Version, Status: self.Status, Anycast: self.Anycast, InSync: true, Uptime: self.Uptime}
		if self.CertUntil > 0 {
			me.CertUntil = time.Unix(self.CertUntil, 0)
		}
		out.Nodes = append(out.Nodes, me)
		names := make([]string, 0, len(s.cl.nodes))
		for n := range s.cl.nodes {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, name := range names {
			n := *s.cl.nodes[name]
			if time.Since(n.LastSeen) > s.cl.timeouts[name] {
				n.Online = false
			}
			out.Nodes = append(out.Nodes, n)
		}
	}
	return out
}

func clusterEqual(a, b config.Cluster) bool { return a == b }
