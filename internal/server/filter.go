package server

import (
	"context"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/filter"
)

// The filtered service ("the second door") is the same server reached
// another way: a plain DNS address in filter.listen, a name in filter.names
// (DoT, DoQ and DoH, told apart by the name the client asks for in the TLS
// handshake), or the DoH path filter.doh_path. Everything else is answered
// unfiltered unless filter.all is set.

// filterPlain reports whether plain DNS on the configured address key is
// filtered.
func (st *state) filterPlain(key string) bool {
	f := &st.cfg.Filter
	return f.Enabled && (f.All || slices.Contains(f.Listen, key))
}

// filterName reports whether a TLS connection for name (SNI) is filtered.
func (st *state) filterName(name string) bool {
	f := &st.cfg.Filter
	return f.Enabled && (f.All || nameIn(f.Names, name))
}

// filterDoH reports whether a DoH request is filtered: by its path, by the
// name it was sent to (Host), or by the TLS name (SNI).
func (st *state) filterDoH(path, host, sni string) bool {
	f := &st.cfg.Filter
	if !f.Enabled {
		return false
	}
	if h, _, ok := strings.Cut(host, ":"); ok && !strings.HasPrefix(host, "[") {
		host = h
	}
	return f.All || path == f.DoHPath || nameIn(f.Names, host) || nameIn(f.Names, sni)
}

func nameIn(list []string, name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return false
	}
	for _, n := range list {
		if strings.EqualFold(strings.TrimSuffix(n, "."), name) {
			return true
		}
	}
	return false
}

// plainListen is every plain DNS address to listen on: server.listen and,
// while filtering is on, filter.listen.
func plainListen(c *config.Config) []string {
	if !c.Filter.Enabled {
		return c.Server.Listen
	}
	return append(slices.Clone(c.Server.Listen), c.Filter.Listen...)
}

// dohPaths lists the DoH paths, separated by a space: doh.path and, while
// filtering is on, filter.doh_path. A listener is reopened when it changes.
func dohPaths(c *config.Config) string {
	if c.Filter.Enabled && c.Filter.DoHPath != "" {
		return c.DoH.Path + " " + c.Filter.DoHPath
	}
	return c.DoH.Path
}

// dohMux serves h on each of the space-separated paths and the status page
// everywhere else.
func (s *Server) dohMux(paths string, h http.Handler) http.Handler {
	mux := http.NewServeMux()
	for _, p := range strings.Fields(paths) {
		mux.Handle(p, h)
	}
	mux.Handle("/", http.HandlerFunc(s.handlePublic))
	return mux
}

func filterSettings(c *config.Config) filter.Settings {
	f := &c.Filter
	return filter.Settings{Enabled: f.Enabled, Lists: f.Lists, Block: f.Block, Allow: f.Allow, Interval: f.UpdateInterval}
}

// startFilter creates the list manager; copies of the lists are kept under
// <data_dir>/filter.
func (s *Server) startFilter(c *config.Config) {
	s.Filter = filter.NewManager(filepath.Join(c.Server.DataDir, "filter"), s.Log, s.res.SetFilter)
	if s.FilterHTTP != nil {
		s.Filter.HTTP = s.FilterHTTP
	}
	s.Filter.Configure(filterSettings(c))
	go s.Filter.Run(s.ctx)
}

// FilterStatus implements admin.Backend.
func (s *Server) FilterStatus() filter.Status { return s.Filter.Status() }

// UpdateFilter implements admin.Backend: download every list now.
func (s *Server) UpdateFilter(ctx context.Context) { s.Filter.UpdateNow(ctx) }

// FilterWhy implements admin.Backend.
func (s *Server) FilterWhy(name string) filter.Why { return s.Filter.Why(name) }

// filteredInfo lists the filtered service's addresses for the setup guide
// and the status page: nil while filtering is off. With filter.all every
// address filters, so there is nothing separate to list.
func (s *Server) filteredInfo(c *config.Config, domain string) *admin.Filtered {
	f := &c.Filter
	if !f.Enabled {
		return nil
	}
	out := &admin.Filtered{Rules: s.Filter.Status().Rules}
	if f.All {
		return out
	}
	port := func(list []string, def uint16) (string, bool) {
		for _, a := range list {
			if ap, err := netip.ParseAddrPort(a); err == nil {
				if ap.Port() == def {
					return "", true
				}
				return ":" + strconv.Itoa(int(ap.Port())), true
			}
		}
		return "", false
	}
	if domain != "" {
		if p, ok := port(c.DoH.HTTPSListen, 443); ok {
			out.DoH = "https://" + domain + p + f.DoHPath
		} else if c.DoH.Listen != "" {
			out.DoH = "https://" + domain + f.DoHPath
		}
	}
	if len(f.Names) > 0 {
		name := strings.ToLower(strings.TrimSuffix(f.Names[0], "."))
		if p, ok := port(c.DoT.Listen, 853); ok {
			out.DoT = name + p
		}
		if p, ok := port(c.DoQ.Listen, 853); ok {
			out.DoQ = "quic://" + name + p
		}
	}
	for _, a := range f.Listen {
		ap, err := netip.ParseAddrPort(a)
		if err != nil || ap.Addr().IsUnspecified() || ap.Addr().IsLoopback() {
			continue
		}
		if ap.Port() == 53 {
			out.Plain = append(out.Plain, ap.Addr().Unmap().String())
		} else {
			out.Plain = append(out.Plain, ap.String())
		}
	}
	return out
}
