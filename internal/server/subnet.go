package server

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// ---- ecs.client_path ----
//
// On this DoH path, kept secret, a query's own EDNS Client Subnet goes to
// the domains' name servers, so a measurement tool sees how a name resolves
// for that network (DomainNova checks where domains are hosted this way).
// The answers come straight from the recursion: no shared cache, no
// filtering, no query log. They never reach any other client.

// subnetMax is the longest prefix passed on (RFC 7871 11.1): enough for
// name servers to answer for the network, not a single machine.
var subnetMax = map[bool]int{false: 24, true: 56}

func (s *Server) handleSubnetDoH(w http.ResponseWriter, r *http.Request, msg []byte, c *config.Config) {
	var ecs []byte
	p, ok, err := m.QueryClientSubnet(msg)
	if err != nil {
		http.Error(w, "malformed dns message", http.StatusBadRequest)
		return
	}
	if ok {
		bits := min(p.Bits(), subnetMax[p.Addr().Is6()])
		ecs = m.ClientSubnet(netip.PrefixFrom(p.Addr(), bits).Masked())
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout(c))
	defer cancel()
	resp, err := s.Rec.ExchangeSubnet(ctx, msg, ecs)
	if err != nil {
		q, _, perr := m.ParseQuery(msg)
		if perr != nil {
			http.Error(w, "malformed dns message", http.StatusBadRequest)
			return
		}
		resp = m.ErrorResponse(msg, q, m.RcodeServFail)
	}
	s.Stats.Rcode(int(resp[3] & 0xF))
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store") // the answer is for that network only
	w.Header().Set("Content-Length", fmt.Sprint(len(resp)))
	w.Write(resp)
}
