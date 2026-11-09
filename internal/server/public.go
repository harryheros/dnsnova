package server

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/resolver"
)

// probes remembers which check names were asked for and over which
// protocol, for the status page's "check it yourself". Only the random
// token and the protocol are kept, for a few minutes; no address.
type probes struct {
	mu sync.Mutex
	m  map[string]probeHit
}

type probeHit struct {
	proto string
	t     time.Time
}

const (
	probeMax = 20000
	probeTTL = 5 * time.Minute
)

func validToken(t string) bool {
	if len(t) < 16 || len(t) > 40 {
		return false
	}
	for _, c := range t {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (p *probes) add(token, proto string, now time.Time) {
	if !validToken(token) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]probeHit{}
	}
	if _, ok := p.m[token]; !ok && len(p.m) >= probeMax {
		return
	}
	p.m[token] = probeHit{proto, now}
}

func (p *probes) seen(token string, now time.Time) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.m[token]
	if !ok || now.Sub(h.t) > probeTTL {
		return "", false
	}
	return h.proto, true
}

func (p *probes) sweep(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, h := range p.m {
		if now.Sub(h.t) > probeTTL {
			delete(p.m, k)
		}
	}
}

// resolve answers one query and notes check names for the status page.
func (s *Server) resolve(msg []byte, udp bool, proto string, filtered bool) resolver.Result {
	res := s.res.ResolveOpts(msg, resolveOpts(udp, proto, filtered))
	s.noteProbe(res, proto)
	return res
}

// resolveCached answers a query only if no upstream needs to be asked (see
// resolver.ResolveCached).
func (s *Server) resolveCached(msg []byte, udp bool, proto string, filtered bool) (resolver.Result, bool) {
	res, ok := s.res.ResolveCached(msg, resolveOpts(udp, proto, filtered))
	if ok {
		s.noteProbe(res, proto)
	}
	return res, ok
}

func resolveOpts(udp bool, proto string, filtered bool) resolver.Opts {
	encrypted := proto == "dot" || proto == "doh" || proto == "doh3" || proto == "doq"
	return resolver.Opts{UDP: udp, Encrypted: encrypted, Filter: filtered}
}

func (s *Server) noteProbe(res resolver.Result, proto string) {
	if res.Status == "probe" && res.Q != nil {
		s.probes.add(resolver.ProbeToken(res.Q.Name), proto, time.Now())
	}
}

// handlePublic serves the status page on the DoH addresses (every path but
// the DoH path). It is 404 when the page is off, and in private mode for
// clients outside the access list.
func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	st := s.state.Load()
	if !st.cfg.Status.Enabled || !st.guard.Permitted(clientIP(r, st.cfg.DoH.TrustedProxies)) {
		http.NotFound(w, r)
		return
	}
	s.statusPage.ServeHTTP(w, r)
}

// PublicStatus implements admin.PublicBackend.
func (s *Server) PublicStatus() admin.PublicInfo {
	c := s.state.Load().cfg
	info := admin.PublicInfo{Mode: c.Server.Mode}
	if len(c.TLS.Domains) > 0 {
		info.Domain = strings.ToLower(c.TLS.Domains[0])
	}
	cert := s.Certificate()
	info.Encrypted = info.Domain != "" && cert.Ready
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
	if info.Domain != "" {
		if p, ok := port(c.DoT.Listen, 853); ok {
			info.DoT = info.Domain + p
		}
		if p, ok := port(c.DoQ.Listen, 853); ok {
			info.DoQ = "quic://" + info.Domain + p
		}
		if p, ok := port(c.DoH.HTTPSListen, 443); ok {
			info.DoH = "https://" + info.Domain + p + c.DoH.Path
			info.HTTP3 = c.DoH.HTTP3
		} else if c.DoH.Listen != "" { // behind a reverse proxy on the standard port
			info.DoH = "https://" + info.Domain + c.DoH.Path
		}
		info.Check = checkZone(c) != ""
	}
	if c.Server.Mode == config.ModePublic {
		for _, ip := range c.PublicListenIPs() {
			info.Plain = append(info.Plain, ip.String())
		}
		if len(info.Plain) == 0 && listensOnAll(c) {
			for _, a := range s.Addresses() {
				if a.Public {
					info.Plain = append(info.Plain, a.Address)
				}
			}
		}
	}
	info.Filtered = s.filteredInfo(c, info.Domain)
	ups := s.Upstreams()
	for _, u := range ups {
		if u.Role == "primary" && u.Healthy {
			info.Healthy = true
		}
	}
	ql := s.QLog.State(time.Now())
	info.QueryLog, info.QueryLogFullIP = ql.On, ql.On && ql.FullIP
	return info
}

// ProbeSeen implements admin.PublicBackend.
func (s *Server) ProbeSeen(token string) (string, bool) { return s.probes.seen(token, time.Now()) }

// Guide implements admin.Backend.
func (s *Server) Guide() admin.GuideInfo {
	c := s.state.Load().cfg
	g := admin.GuideInfo{PublicInfo: s.PublicStatus()}
	g.Plain = nil
	for _, a := range c.Server.Listen {
		if ap, err := netip.ParseAddrPort(a); err == nil && !ap.Addr().IsUnspecified() && !ap.Addr().IsLoopback() {
			g.Plain = append(g.Plain, ap.Addr().Unmap().String())
		}
	}
	if listensOnAll(c) { // ":53": every address of the machine
		for _, a := range s.Addresses() {
			if !a.Loopback && !strings.HasPrefix(a.Interface, "docker") && !strings.HasPrefix(a.Interface, "veth") && !strings.HasPrefix(a.Interface, "br-") {
				g.Plain = append(g.Plain, a.Address)
			}
		}
	}
	g.Port = 53
	for _, a := range c.Server.Listen {
		if i := strings.LastIndex(a, ":"); i >= 0 {
			if p, err := strconv.Atoi(a[i+1:]); err == nil {
				g.Port = p
				break
			}
		}
	}
	if c.Status.Enabled && g.Domain != "" && g.DoH != "" {
		base := strings.TrimSuffix(g.DoH, c.DoH.Path)
		g.Profile = &base
	}
	return g
}

// listensOnAll reports whether server.listen has a wildcard address.
func listensOnAll(c *config.Config) bool {
	for _, a := range c.Server.Listen {
		if strings.HasPrefix(a, ":") || strings.HasPrefix(a, "0.0.0.0:") || strings.HasPrefix(a, "[::]:") {
			return true
		}
	}
	return false
}
