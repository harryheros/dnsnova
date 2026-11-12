package server

import (
	"net"
	"net/netip"

	"github.com/harryheros/dnsnova/internal/guard"
	"github.com/harryheros/dnsnova/internal/proxyproto"
	"github.com/harryheros/dnsnova/internal/stats"
)

// proxyListener requires a PROXY protocol header (v1 or v2) on connections
// from the load balancers in server.proxy_protocol, and makes the client
// address it gives the connection's RemoteAddr, so access lists, limits,
// cookies and logs see the client rather than the balancer. Others'
// connections are untouched. The list is read for each connection, so a
// change applies at once.
func (s *Server) proxyListener(ln net.Listener) net.Listener {
	pl := proxyproto.NewListener(ln, s.proxyTrusted)
	pl.Rejected = func(peer netip.Addr, err error) {
		s.Stats.Rejected[stats.RejectMalformed].Add(1)
	}
	return pl
}

func (s *Server) proxyTrusted(ip netip.Addr) bool {
	st := s.state.Load()
	return st != nil && guard.ACL(st.cfg.Server.ProxyProtocol).Contains(ip)
}
