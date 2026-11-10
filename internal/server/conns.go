package server

import (
	"net"
	"net/netip"
	"sync"

	"github.com/harryheros/dnsnova/internal/guard"
	"github.com/harryheros/dnsnova/internal/stats"
)

// clientConns counts the open connections of each client address (an IPv4
// address or an IPv6 /56, as the query limits do), so that one address
// cannot take every connection the server allows.
type clientConns struct {
	mu sync.Mutex
	m  map[netip.Addr]int
}

// acquire counts a new connection from ip; false when it already has limit
// open (0: no limit). The machine itself is not limited.
func (c *clientConns) acquire(ip netip.Addr, limit int) bool {
	if limit <= 0 || ip.IsLoopback() {
		return true
	}
	k := guard.ClientKey(ip)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[netip.Addr]int{}
	}
	if c.m[k] >= limit {
		return false
	}
	c.m[k]++
	return true
}

// count reports how many connections ip has open.
func (c *clientConns) count(ip netip.Addr) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[guard.ClientKey(ip)]
}

// release ends a connection counted by acquire with the same limit.
func (c *clientConns) release(ip netip.Addr, limit int) {
	if limit <= 0 || ip.IsLoopback() {
		return
	}
	k := guard.ClientKey(ip)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m[k]--; c.m[k] <= 0 {
		delete(c.m, k)
	}
}

// admitTCP decides on a new TCP connection (plain DNS, DoT or DoH): the
// access list (with acl), the server's connection limit, and the client's
// (with perClient). On true, done must be called when the connection
// closes.
func (s *Server) admitTCP(ip netip.Addr, acl, perClient bool) (done func(), ok bool) {
	st := s.state.Load()
	if st == nil {
		return nil, false
	}
	if acl && !st.guard.Permitted(ip) {
		s.Stats.Rejected[stats.RejectACL].Add(1)
		return nil, false
	}
	if s.tcpConns.Add(1) > int64(st.cfg.Limits.TCPConnections) {
		s.tcpConns.Add(-1)
		s.Stats.Rejected[stats.RejectOverload].Add(1)
		return nil, false
	}
	limit := 0
	if perClient {
		limit = st.cfg.Limits.ClientConnections
	}
	if !s.clientConns.acquire(ip, limit) {
		s.tcpConns.Add(-1)
		s.Stats.Rejected[stats.RejectClientLimit].Add(1)
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.clientConns.release(ip, limit)
			s.tcpConns.Add(-1)
		})
	}, true
}

// admitListener applies admitTCP to the connections of an HTTP listener
// (DoH), which net/http accepts by itself. The access list is left to the
// handler: Let's Encrypt checks the domain on the same port (TLS-ALPN),
// from addresses that are not on it. direct: HTTPS from clients, not plain
// HTTP from a proxy, where every connection comes from the proxy.
type admitListener struct {
	net.Listener
	s      *Server
	direct bool
}

func (l admitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := netip.Addr{}
		if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
			ip = ap.Addr().Unmap()
		}
		perClient := l.direct
		if st := l.s.state.Load(); st != nil && guard.ACL(st.cfg.DoH.TrustedProxies).Contains(ip) {
			perClient = false // a proxy in front, passing TLS through
		}
		done, ok := l.s.admitTCP(ip, false, perClient)
		if !ok {
			c.Close()
			continue
		}
		return &admittedConn{Conn: c, done: done}, nil
	}
}

type admittedConn struct {
	net.Conn
	done func()
}

func (c *admittedConn) Close() error {
	c.done()
	return c.Conn.Close()
}
