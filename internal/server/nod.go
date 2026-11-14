package server

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/insight"
	"github.com/harryheros/dnsnova/internal/resolver"
	"github.com/harryheros/dnsnova/internal/stats"
)

// nodFile keeps the newly-observed-domain filters (hashes, no names).
const nodFile = "nod.bin"

// nodEvery is how often the filters are saved and newly seen domains
// are sent to the alert destinations.
const nodEvery = 10 * time.Minute

// applyNOD starts or stops the detector. Turned off, its file is deleted.
func (s *Server) applyNOD(c *config.Config) {
	path := filepath.Join(c.Server.DataDir, nodFile)
	if !c.NOD.Enabled {
		if old := s.nod.Swap(nil); old != nil {
			s.Log.Info("newly observed domains: off")
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.Log.Warn("newly observed domains: could not delete the saved state", "err", err)
		}
		return
	}
	n := s.nod.Load()
	if n == nil {
		n = insight.NewNOD(c.NOD.Learn)
		switch err := n.LoadFile(path); {
		case err == nil:
			s.Log.Info("newly observed domains: on, state loaded")
		case errors.Is(err, fs.ErrNotExist):
			s.Log.Info("newly observed domains: on, learning the network's domains first", "for", c.NOD.Learn.String())
		default:
			s.Log.Warn("newly observed domains: saved state unreadable, learning again", "err", err)
			n = insight.NewNOD(c.NOD.Learn)
		}
	}
	n.SetIgnore(c.NOD.Ignore)
	s.nodFull.Store(c.NOD.FullIP)
	s.nodAlert.Store(c.NOD.Alert)
	s.nod.Store(n)
}

// observeNOD checks the domain of an answered query. Only real answers
// count: not blocked, local or failed ones.
func (s *Server) observeNOD(domain, name string, ip netip.Addr, res resolver.Result) bool {
	n := s.nod.Load()
	if n == nil || m.Rcode(res.Resp) != m.RcodeNoError || len(res.Resp) < m.HeaderLen || m.U16(res.Resp, 6) == 0 {
		return false
	}
	switch res.Source {
	case stats.SourceUpstream, stats.SourceCache, stats.SourceStale:
	default:
		return false
	}
	client := insight.Mask(ip)
	if s.nodFull.Load() {
		client = ip.Unmap().String()
	}
	return n.Observe(domain, trimDot(name), m.TypeString(res.Q.Type), client)
}

func trimDot(name string) string {
	if len(name) > 1 && name[len(name)-1] == '.' {
		return name[:len(name)-1]
	}
	return name
}

// nodLoop saves the filters and sends newly seen domains, every nodEvery
// and at shutdown.
func (s *Server) nodLoop() {
	t := time.NewTicker(nodEvery)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.nodTick()
			return
		case <-t.C:
			s.nodTick()
		}
	}
}

func (s *Server) nodTick() {
	n := s.nod.Load()
	if n == nil {
		return
	}
	st := s.state.Load()
	if st == nil {
		return
	}
	if err := n.SaveFile(filepath.Join(st.cfg.Server.DataDir, nodFile)); err != nil {
		s.Log.Warn("newly observed domains: state not saved", "err", err)
	}
	found := n.TakePending()
	if len(found) == 0 || !s.nodAlert.Load() {
		return
	}
	details := make([]string, 0, 21)
	for i, d := range found {
		if i == 20 {
			details = append(details, fmt.Sprintf("and %d more (Status › New domains)", len(found)-20))
			break
		}
		details = append(details, fmt.Sprintf("%s: %s %s, first asked by %s at %s", d.Domain, d.Name, d.Type, d.Client, d.Time.UTC().Format("15:04 UTC")))
	}
	summary := "1 newly seen domain"
	if len(found) > 1 {
		summary = fmt.Sprintf("%d newly seen domains", len(found))
	}
	s.al.engine.Event("new_domains", s.cl.name, summary, details)
}
