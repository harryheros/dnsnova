package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/guard"
	"github.com/harryheros/dnsnova/internal/stats"
)

// DNS over QUIC error codes (RFC 9250 section 4.3).
const (
	doqNoError       = 0x0
	doqInternalError = 0x1
	doqProtocolError = 0x2
	doqRequestCancel = 0x3
	doqExcessiveLoad = 0x4
	h3ProtocolError  = 0x101 // H3_GENERAL_PROTOCOL_ERROR (RFC 9114 section 8.1)
)

var errQUICRefused = errors.New("connection refused")

// quicListener is one UDP socket serving DNS over QUIC or HTTP/3. Both share
// the same admission rules:
//
//   - 0-RTT is never accepted: the listener is not an early listener and
//     Allow0RTT is off, so a query can never be replayed.
//   - Clients outside the access list (private mode) are refused before the
//     handshake; the refusal is a single packet smaller than the client's
//     padded Initial, so it cannot be used for amplification.
//   - limits.quic_connections caps open connections; above half of it, new
//     clients must first prove their address with a Retry.
//   - Idle timeout and stream concurrency come from the configuration in
//     force when each connection starts, so they change without a restart.
type quicListener struct {
	pc *net.UDPConn
	tr *quic.Transport
	ln *quic.Listener
	h3 *http3.Server // HTTP/3 only

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[*quic.Conn]struct{}
}

// listenQUIC opens a UDP socket and a QUIC listener offering the ALPN
// protocols in tlsConf.
func (s *Server) listenQUIC(addr string, tlsConf *tls.Config) (*quicListener, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	l := &quicListener{pc: pc, conns: map[*quic.Conn]struct{}{}}
	l.tr = &quic.Transport{
		Conn:                pc,
		VerifySourceAddress: s.quicVerifySource,
		ConnContext:         s.quicAdmit,
	}
	conf := s.quicConfig(s.state.Load())
	conf.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) {
		return s.quicConfig(s.state.Load()), nil
	}
	ln, err := l.tr.Listen(tlsConf, conf)
	if err != nil {
		l.tr.Close()
		pc.Close()
		return nil, err
	}
	l.ln = ln
	return l, nil
}

// quicConfig returns the QUIC parameters for new connections.
func (s *Server) quicConfig(st *state) *quic.Config {
	idle, streams := 10*time.Second, int64(16)
	if st != nil {
		idle, streams = st.cfg.Limits.TCPIdleTimeout, int64(st.cfg.Limits.TCPPipeline)
	}
	return &quic.Config{
		Allow0RTT:             false,
		HandshakeIdleTimeout:  5 * time.Second,
		MaxIdleTimeout:        idle,
		MaxIncomingStreams:    streams,
		MaxIncomingUniStreams: 3, // HTTP/3 control and QPACK streams; DoQ uses none
		// DNS messages are at most 64 KB: keep per-connection buffers small.
		InitialStreamReceiveWindow:     64 << 10,
		MaxStreamReceiveWindow:         128 << 10,
		InitialConnectionReceiveWindow: 256 << 10,
		MaxConnectionReceiveWindow:     1 << 20,
	}
}

// quicAdmit runs when a client opens a connection, before the handshake.
func (s *Server) quicAdmit(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	st := s.state.Load()
	if st == nil {
		return nil, errQUICRefused
	}
	ip := addrIP(info.RemoteAddr)
	if !st.guard.Permitted(ip) {
		s.Stats.Rejected[stats.RejectACL].Add(1)
		return nil, errQUICRefused
	}
	if s.quicConns.Add(1) > int64(st.cfg.Limits.QUICConnections) {
		s.quicConns.Add(-1)
		s.Stats.Rejected[stats.RejectOverload].Add(1)
		return nil, errQUICRefused
	}
	context.AfterFunc(ctx, func() { s.quicConns.Add(-1) })
	return ctx, nil
}

// quicVerifySource asks for a Retry (address validation) when the server is
// busy, so spoofed sources cannot fill the connection table.
// Clients outside the access list get no Retry: quicAdmit refuses them.
func (s *Server) quicVerifySource(a net.Addr) bool {
	st := s.state.Load()
	return st != nil && st.guard.Permitted(addrIP(a)) &&
		s.quicConns.Load() >= int64(st.cfg.Limits.QUICConnections)/2
}

func addrIP(a net.Addr) netip.Addr {
	if ua, ok := a.(*net.UDPAddr); ok {
		ip, _ := netip.AddrFromSlice(ua.IP)
		return ip.Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (l *quicListener) track(c *quic.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns == nil {
		return false // closing
	}
	l.conns[c] = struct{}{}
	return true
}

func (l *quicListener) untrack(c *quic.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

func (l *quicListener) close() {
	if l.h3 != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		l.h3.Shutdown(ctx) // GOAWAY, then close what is left
		cancel()
	}
	l.ln.Close()
	l.mu.Lock()
	conns := l.conns
	l.conns = nil
	l.mu.Unlock()
	for c := range conns {
		c.CloseWithError(doqNoError, "")
	}
	l.wg.Wait()
	l.tr.Close()
	l.pc.Close()
}

// ---- DNS over QUIC (RFC 9250) ----

func (s *Server) listenDoQ(addr string, tlsConf *tls.Config) (*quicListener, error) {
	l, err := s.listenQUIC(addr, tlsConf)
	if err != nil {
		return nil, err
	}
	l.wg.Add(1)
	go s.serveDoQ(l)
	s.Log.Info("listening", "proto", "doq", "addr", l.pc.LocalAddr().String())
	return l, nil
}

func (s *Server) serveDoQ(l *quicListener) {
	defer l.wg.Done()
	for {
		c, err := l.ln.Accept(context.Background())
		if err != nil {
			return // listener closed
		}
		if c.ConnectionState().TLS.NegotiatedProtocol != "doq" {
			c.CloseWithError(doqProtocolError, "doq alpn required")
			continue
		}
		if !l.track(c) {
			c.CloseWithError(doqNoError, "")
			return
		}
		l.wg.Add(1)
		go func() {
			defer func() { l.untrack(c); l.wg.Done() }()
			s.serveDoQConn(c, addrIP(c.RemoteAddr()))
		}()
	}
}

func (s *Server) serveDoQConn(c *quic.Conn, ip netip.Addr) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		str, err := c.AcceptStream(c.Context())
		if err != nil {
			return // closed by either side, or idle timeout
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveDoQStream(c, str, ip)
		}()
	}
}

func (s *Server) serveDoQStream(c *quic.Conn, str *quic.Stream, ip netip.Addr) {
	st := s.state.Load()
	str.SetReadDeadline(time.Now().Add(st.cfg.Limits.TCPIdleTimeout))
	var lb [2]byte
	if _, err := io.ReadFull(str, lb[:]); err != nil {
		str.CancelRead(doqRequestCancel)
		str.CancelWrite(doqRequestCancel)
		return
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	msg := make([]byte, n)
	if _, err := io.ReadFull(str, msg); err != nil {
		str.CancelRead(doqRequestCancel)
		str.CancelWrite(doqRequestCancel)
		return
	}
	s.Stats.Queries[stats.DoQ].Add(1)
	// RFC 9250 4.2.1: the Message ID must be 0, and a single message per
	// stream; anything else is a protocol error that ends the connection.
	if n < m.HeaderLen || m.U16(msg, 0) != 0 {
		s.Stats.Rejected[stats.RejectMalformed].Add(1)
		c.CloseWithError(doqProtocolError, "invalid query")
		return
	}
	switch v := st.guard.Admit(ip); v {
	case guard.Allow:
	case guard.DenyACL:
		s.reject(v, ip)
		c.CloseWithError(doqNoError, "")
		return
	default:
		s.reject(v, ip)
		if q, _, err := m.ParseQuery(msg); err == nil {
			writeDoQ(str, m.ErrorResponse(msg, q, m.RcodeRefused))
		} else {
			str.CancelWrite(doqExcessiveLoad)
		}
		return
	}
	start := time.Now()
	res := s.res.Resolve(msg, false)
	if res.Resp == nil {
		c.CloseWithError(doqProtocolError, "malformed query")
		return
	}
	writeDoQ(str, res.Resp)
	s.logQuery(st, ip, "doq", res, start)
}

// writeDoQ sends one length-prefixed response and closes the stream (FIN).
func writeDoQ(str *quic.Stream, resp []byte) {
	buf := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(buf, uint16(len(resp)))
	copy(buf[2:], resp)
	str.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := str.Write(buf); err != nil {
		str.CancelWrite(doqInternalError)
		return
	}
	str.Close()
	str.CancelRead(doqNoError) // the query has been read; ignore anything after it
}

// ---- DNS over HTTPS over HTTP/3 ----

// listenH3 serves h on UDP addr over HTTP/3.
func (s *Server) listenH3(addr, path string, h http.Handler, tlsConf *tls.Config) (*quicListener, error) {
	l, err := s.listenQUIC(addr, tlsConf)
	if err != nil {
		return nil, err
	}
	if path != "" {
		mux := http.NewServeMux()
		mux.Handle(path, h)
		h = mux
	}
	l.h3 = &http3.Server{
		Handler:        h,
		MaxHeaderBytes: 16 << 10,
		IdleTimeout:    120 * time.Second,
	}
	go l.h3.ServeListener(&h3Accepter{l: l})
	s.Log.Info("listening", "proto", "http3", "addr", l.pc.LocalAddr().String(), "path", path)
	return l, nil
}

// h3Accepter hands the HTTP/3 server only connections that negotiated h3.
type h3Accepter struct{ l *quicListener }

func (a *h3Accepter) Accept(ctx context.Context) (*quic.Conn, error) {
	for {
		c, err := a.l.ln.Accept(ctx)
		if err != nil {
			return nil, err
		}
		if c.ConnectionState().TLS.NegotiatedProtocol == "h3" {
			return c, nil
		}
		c.CloseWithError(h3ProtocolError, "h3 alpn required")
	}
}

func (a *h3Accepter) Addr() net.Addr { return a.l.ln.Addr() }
func (a *h3Accepter) Close() error   { return a.l.ln.Close() }
