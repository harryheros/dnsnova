package server

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/locality"
	"github.com/harryheros/dnsnova/internal/recursor"
)

// ---- private locality (package locality) ----
//
// The recursion asks from the exits; the resolver gives each client its
// view's answer. What outlives one configuration lives here: the country
// table and the job that keeps it current, and the siting report.

type locServer struct {
	mu        sync.Mutex
	countries atomic.Pointer[locality.Countries]
	report    locality.Report
	updater   *locality.Updater
	stop      context.CancelFunc
	sources   string // the sources the updater runs with
	// CountryHTTP overrides the HTTP client for the registry files (tests).
	http *http.Client
}

// localityOn reports whether private locality is in use.
func localityOn(c *config.Config) bool {
	return c.Locality.Enabled && c.Recursion.Enabled && c.ECS.Address == "" && len(c.Locality.Exits) > 0
}

// localityMapper returns what the resolver picks views with (nil: off).
func (s *Server) localityMapper(c *config.Config) *locality.Mapper {
	if !localityOn(c) {
		return nil
	}
	mp := locality.NewMapper(c.LocalityExits())
	mp.Share(&s.loc.countries, &s.loc.report)
	return mp
}

// localityConfig is the recursion's part (nil: off).
func localityConfig(c *config.Config) *recursor.LocalityConfig {
	if !localityOn(c) {
		return nil
	}
	return &recursor.LocalityConfig{Exits: c.LocalityExits(), ExitTimeout: c.Locality.ExitTimeout,
		FanoutQPS: c.Locality.FanoutQPS, Relearn: c.Locality.Relearn}
}

func countrySources(c *config.Config) []string {
	if len(c.Locality.CountrySources) > 0 {
		return c.Locality.CountrySources
	}
	return locality.DefaultCountrySources
}

// applyLocality starts the country table's updates when an exit serves
// clients by country, and stops them (forgetting the table and the counts)
// when private locality is turned off.
func (s *Server) applyLocality(c *config.Config) {
	s.loc.mu.Lock()
	defer s.loc.mu.Unlock()
	need := localityOn(c) && locality.NewMapper(c.LocalityExits()).NeedsCountries()
	sources := strings.Join(countrySources(c), "\n")
	if s.loc.stop != nil && (!need || sources != s.loc.sources) {
		s.loc.stop()
		s.loc.stop, s.loc.updater = nil, nil
	}
	if !localityOn(c) {
		s.loc.countries.Store(nil)
		s.loc.report.Reset()
		return
	}
	if !need || s.loc.stop != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	u := &locality.Updater{
		Dir: filepath.Join(c.Server.DataDir, "locality"), Sources: countrySources(c), HTTP: s.loc.http, Log: s.Log,
		Publish: func(t *locality.Countries) {
			s.loc.countries.Store(t)
			s.Log.Info("locality: country table loaded", "blocks", t.Len())
		},
	}
	s.loc.updater, s.loc.stop, s.loc.sources = u, cancel, sources
	go u.Run(ctx)
}

// zonesFile keeps the zones whose answers vary (private locality) with the
// cache: zone names only.
const zonesFile = "locality-zones.bin"

func zonesPath(c *config.Config) string { return filepath.Join(c.Server.DataDir, zonesFile) }

func (s *Server) loadZones(c *config.Config) {
	if !c.PersistCache() || !localityOn(c) {
		return
	}
	f, err := os.Open(zonesPath(c))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.Log.Warn("locality: zones file not loaded", "err", err)
		return
	}
	defer f.Close()
	if n, err := s.Rec.LoadZones(f); err != nil {
		s.Log.Warn("locality: zones file not loaded: they are learnt again", "file", zonesPath(c), "err", err)
	} else if n > 0 {
		s.Log.Info("locality: zones whose answers vary remembered", "zones", n)
	}
}

// ---- measurements through one exit (locality.measure_path) ----

// measurePrefix is the DoH path prefix the exit's name follows, or "".
func measurePrefix(c *config.Config) string {
	if c.Locality.MeasurePath == "" || !localityOn(c) {
		return ""
	}
	return c.Locality.MeasurePath + "/"
}

// handleExitDoH answers a query as asked through the exit named in the
// path: for tools that measure how names resolve there (DomainNova's
// regional view). Like ecs.client_path: no shared cache, no filtering, no
// query log.
func (s *Server) handleExitDoH(w http.ResponseWriter, r *http.Request, msg []byte, c *config.Config) {
	exit := strings.TrimPrefix(r.URL.Path, measurePrefix(c))
	ctx, cancel := context.WithTimeout(r.Context(), max(timeout(c), subnetDeadline))
	defer cancel()
	resp, err := s.Rec.ExchangeExit(ctx, msg, exit)
	if errors.Is(err, recursor.ErrNoExit) {
		http.Error(w, "no such exit", http.StatusNotFound)
		return
	}
	if err != nil {
		q, _, perr := m.ParseQuery(msg)
		if perr != nil {
			http.Error(w, "malformed dns message", http.StatusBadRequest)
			return
		}
		s.Log.Info("locality.measure_path: no answer", "exit", exit, "name", m.NameString(q.Name), "type", m.TypeString(q.Type), "err", err.Error())
		resp = m.ErrorResponse(msg, q, m.RcodeServFail)
	}
	s.Stats.Rcode(int(resp[3] & 0xF))
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(resp)
}

// ---- what the admin interface shows ----

// Locality implements admin.Backend.
func (s *Server) Locality() admin.Locality {
	st := s.state.Load()
	if st == nil || !localityOn(st.cfg) {
		return admin.Locality{Exits: []admin.LocalityExit{}, Zones: []string{}, Report: []locality.ReportRow{}}
	}
	out := admin.Locality{Enabled: true, Report: s.loc.report.Rows(), Status: s.Rec.Locality(), Zones: s.Rec.VaryingZones()}
	s.loc.mu.Lock()
	if u := s.loc.updater; u != nil {
		cs := u.Status()
		out.Countries = &cs
	}
	s.loc.mu.Unlock()
	exits := st.cfg.LocalityExits()
	if out.Status != nil {
		for i, es := range out.Status.Exits {
			x := admin.LocalityExit{ExitStatus: es}
			if i < len(exits) {
				x.Serves = append(slices.Clone(exits[i].Countries), prefixStrings(exits[i].Networks)...)
			}
			out.Exits = append(out.Exits, x)
		}
	}
	if out.Zones == nil {
		out.Zones = []string{}
	}
	if out.Report == nil {
		out.Report = []locality.ReportRow{}
	}
	return out
}

// localityDown reports the exits not in use now, for the alerts.
func (s *Server) localityDown() []string {
	st := s.Rec.Locality()
	if st == nil {
		return nil
	}
	var out []string
	for _, e := range st.Exits {
		if !e.Up {
			out = append(out, e.Name)
		}
	}
	return out
}

func prefixStrings[P interface{ String() string }](ps []P) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
