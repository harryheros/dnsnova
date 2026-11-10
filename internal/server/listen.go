package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/guard"
	"github.com/harryheros/dnsnova/internal/insight"
	"github.com/harryheros/dnsnova/internal/resolver"
	"github.com/harryheros/dnsnova/internal/stats"
)

// ---- UDP ----

// udpListener serves one address. On Linux it has one socket per CPU core
// (up to 16) sharing the address with SO_REUSEPORT, so the kernel spreads
// queries across cores; each socket has its own reader. An answer always
// leaves through the socket its query came in on.
type udpListener struct {
	key   string         // the address as configured, to tell which service it is
	conn  *net.UDPConn   // the first socket (for its address)
	conns []*net.UDPConn // every socket, conn included
	wg    sync.WaitGroup
}

// udpSockets is how many sockets listenUDP opens per address.
func udpSockets() int {
	if !canReusePort {
		return 1
	}
	return min(max(runtime.NumCPU(), 1), 16)
}

func (s *Server) listenUDP(addr string) (*udpListener, error) {
	lc := net.ListenConfig{}
	n := udpSockets()
	if n > 1 {
		lc.Control = reusePort
	}
	l := &udpListener{key: addr}
	bind := addr
	for i := 0; i < n; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", bind)
		if err != nil {
			for _, c := range l.conns {
				c.Close()
			}
			return nil, err
		}
		c := pc.(*net.UDPConn)
		c.SetReadBuffer(4 << 20)
		c.SetWriteBuffer(4 << 20)
		if i == 0 {
			l.conn = c
			bind = c.LocalAddr().String() // with port 0 (tests), the port the first socket got
		}
		l.conns = append(l.conns, c)
	}
	// Readers per socket: with one socket, several readers share it.
	readers := 2
	if n == 1 {
		readers = max(runtime.NumCPU(), 2)
	}
	for _, c := range l.conns {
		for range readers {
			l.wg.Add(1)
			go s.serveUDP(l, c)
		}
	}
	s.Log.Info("listening", "proto", "udp", "addr", l.conn.LocalAddr().String(), "sockets", n)
	return l, nil
}

func (l *udpListener) close() {
	for _, c := range l.conns {
		c.Close()
	}
	l.wg.Wait()
}

func (s *Server) serveUDP(l *udpListener, conn *net.UDPConn) {
	defer l.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if isClosed(err) {
				return
			}
			continue
		}
		if n < m.HeaderLen {
			continue
		}
		s.Stats.Queries[stats.UDP].Add(1)
		st := s.state.Load()
		ip := addr.Addr().Unmap()
		if v := st.guard.Admit(ip); v != guard.Allow {
			s.reject(v, ip) // never answer over UDP: that is what an attacker wants
			continue
		}
		// Most queries are answered from the cache: do that right here, and
		// start a goroutine only for those that must wait for an upstream.
		start := time.Now()
		filtered := st.filterPlain(l.key)
		if res, ok := s.resolveCached(buf[:n], true, "udp", filtered); ok {
			s.answerUDP(conn, st, ip, addr, buf[:n], res, start)
			continue
		}
		select {
		case s.udpInflight <- struct{}{}:
		default:
			s.Stats.Rejected[stats.RejectOverload].Add(1)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.wg.Add(1)
		s.dispatch(func() {
			defer func() { <-s.udpInflight; s.wg.Done() }()
			s.answerUDP(conn, st, ip, addr, pkt, s.resolve(pkt, true, "udp", filtered), start)
		})
	}
}

// dispatch runs job on an idle worker, or a new one. Workers stay for a
// while after their job, so the goroutine stacks that deep lookups grow are
// reused instead of grown again for every query (about a tenth of the CPU
// time when resolving from the root).
func (s *Server) dispatch(job func()) {
	select {
	case s.jobs <- job:
	default:
		go s.worker(job)
	}
}

func (s *Server) worker(job func()) {
	idle := time.NewTimer(workerIdle)
	defer idle.Stop()
	for {
		job()
		idle.Reset(workerIdle)
		select {
		case job = <-s.jobs:
		case <-idle.C:
			return
		case <-s.ctx.Done():
			return
		}
	}
}

const workerIdle = 20 * time.Second

// answerUDP applies response rate limiting and sends one UDP answer.
func (s *Server) answerUDP(conn *net.UDPConn, st *state, ip netip.Addr, addr netip.AddrPort, pkt []byte, res resolver.Result, start time.Time) {
	if res.Resp == nil {
		return
	}
	resp := res.Resp
	switch st.guard.RRL.Check(ip, res.Q.Name, res.Q.Type, m.Rcode(resp)) {
	case guard.Drop:
		s.Stats.Rejected[stats.RejectRRLDrop].Add(1)
		s.Limited.Add(insight.NetworkOf(ip).String(), ip)
		return
	case guard.Slip:
		s.Stats.Rejected[stats.RejectRRLSlip].Add(1)
		s.Limited.Add(insight.NetworkOf(ip).String(), ip)
		resp = m.Truncated(pkt, res.Q, m.Rcode(resp))
	}
	s.logQuery(st, ip, "udp", res, start) // before sending: a client may read the log as soon as it has its answer
	conn.WriteToUDPAddrPort(resp, addr)
}

func (s *Server) reject(v guard.Verdict, ip netip.Addr) {
	switch v {
	case guard.DenyACL:
		s.Stats.Rejected[stats.RejectACL].Add(1)
		return // not a limit: private mode refuses these by design
	case guard.DenyClient:
		s.Stats.Rejected[stats.RejectClientLimit].Add(1)
	case guard.DenyNetwork:
		s.Stats.Rejected[stats.RejectNetworkLimit].Add(1)
	case guard.DenyGlobal:
		s.Stats.Rejected[stats.RejectGlobalLimit].Add(1)
		return // everyone is limited; no network stands out
	}
	s.Limited.Add(insight.NetworkOf(ip).String(), ip)
}

// logQuery counts an answered query for the domain lists and, while it
// runs, records it in the query log. Nothing is written to disk.
func (s *Server) logQuery(st *state, ip netip.Addr, proto string, res resolver.Result, start time.Time) {
	if res.Q == nil || res.Resp == nil {
		return
	}
	name := m.NameString(res.Q.Name)
	rc := m.Rcode(res.Resp)
	d := insight.Domain(name)
	s.Domains.Add(d, ip)
	if rc == m.RcodeNXDomain {
		s.NXDomains.Add(d, ip)
	}
	if s.QLog.On() {
		s.QLog.Add(insight.Query{
			Time: start, Proto: proto, Name: strings.ToLower(strings.TrimSuffix(name, ".")),
			Type: m.TypeString(res.Q.Type), Rcode: m.RcodeString(rc), Source: stats.SourceName(res.Source), Filtered: res.Filtered,
			MS: float64(time.Since(start).Microseconds()) / 1000,
		}, ip)
	}
}

// ---- TCP (pipelined queries are answered concurrently) ----

type tcpListener struct {
	key   string // the address as configured
	proto int
	ln    net.Listener
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// listenTCP serves length-prefixed DNS over TCP, or over TLS (DoT) when
// tlsConf is set.
func (s *Server) listenTCP(addr string, tlsConf *tls.Config, proto int, name string) (*tcpListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsConf != nil {
		ln = tls.NewListener(ln, tlsConf)
	}
	l := &tcpListener{key: addr, proto: proto, ln: ln, conns: map[net.Conn]struct{}{}}
	l.wg.Add(1)
	go s.serveTCP(l)
	s.Log.Info("listening", "proto", name, "addr", ln.Addr().String())
	return l, nil
}

func (l *tcpListener) close() {
	l.ln.Close()
	l.mu.Lock()
	for c := range l.conns {
		c.Close()
	}
	l.mu.Unlock()
	l.wg.Wait()
}

func (s *Server) serveTCP(l *tcpListener) {
	defer l.wg.Done()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if isClosed(err) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		st := s.state.Load()
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil {
			c.Close()
			continue
		}
		ip := ap.Addr().Unmap()
		done, ok := s.admitTCP(ip, true, true)
		if !ok {
			c.Close()
			continue
		}
		l.mu.Lock()
		l.conns[c] = struct{}{}
		l.mu.Unlock()
		l.wg.Add(1)
		go func() {
			defer func() {
				l.mu.Lock()
				delete(l.conns, c)
				l.mu.Unlock()
				done()
				l.wg.Done()
			}()
			s.serveTCPConn(c, ip, l.key, l.proto, st.cfg.Limits.TCPPipeline, st.cfg.Limits.TCPIdleTimeout)
		}()
	}
}

func (s *Server) serveTCPConn(c net.Conn, ip netip.Addr, key string, proto, pipeline int, idle time.Duration) {
	name := "tcp"
	// Which service: plain DNS by the address it came to, DoT by the name
	// the client asked for in the TLS handshake (SNI).
	filtered := func(st *state) bool { return st.filterPlain(key) }
	if proto == stats.DoT {
		name = "dot"
		// the TLS handshake must finish within the idle timeout too
		c.SetDeadline(time.Now().Add(idle))
		if err := c.(*tls.Conn).Handshake(); err != nil {
			c.Close()
			return
		}
		c.SetDeadline(time.Time{})
		sni := c.(*tls.Conn).ConnectionState().ServerName
		filtered = func(st *state) bool { return st.filterName(sni) }
	}
	var wmu sync.Mutex
	var wg sync.WaitGroup
	inflight := make(chan struct{}, pipeline)
	defer func() {
		wg.Wait()
		c.Close()
	}()
	for {
		c.SetReadDeadline(time.Now().Add(idle))
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < m.HeaderLen {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		s.Stats.Queries[proto].Add(1)
		st := s.state.Load()
		if v := st.guard.Admit(ip); v != guard.Allow {
			s.reject(v, ip)
			if v == guard.DenyACL {
				return
			}
			if q, _, err := m.ParseQuery(msg); err == nil {
				writeTCP(c, &wmu, m.ErrorResponse(msg, q, m.RcodeRefused))
			}
			continue
		}
		inflight <- struct{}{} // back-pressure: at most `pipeline` queries at once
		wg.Add(1)
		go func() {
			defer func() { <-inflight; wg.Done() }()
			start := time.Now()
			res := s.resolve(msg, false, name, filtered(st))
			if res.Resp != nil {
				s.logQuery(st, ip, name, res, start)
				writeTCP(c, &wmu, res.Resp)
			}
		}()
	}
}

func writeTCP(c net.Conn, mu *sync.Mutex, resp []byte) {
	buf := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(buf, uint16(len(resp)))
	copy(buf[2:], resp)
	mu.Lock()
	defer mu.Unlock()
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(buf); err != nil {
		c.Close() // a client that stops reading gets disconnected
	}
}

// ---- HTTP listeners (DoH behind a reverse proxy, metrics) ----

type httpListener struct {
	addr, path string
	ln         net.Listener
	srv        *http.Server
	h3         *quicListener // HTTP/3 on the same address over UDP, if enabled
}

// listenHTTP serves h on addr: plain HTTP, or HTTPS with HTTP/2 when
// tlsConf is set.
func (s *Server) listenHTTP(addr, path string, h http.Handler, tlsConf *tls.Config) (*httpListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return s.serveHTTP(ln, addr, path, h, tlsConf), nil
}

func (s *Server) serveHTTP(ln net.Listener, addr, path string, h http.Handler, tlsConf *tls.Config) *httpListener {
	if path != "" {
		h = s.dohMux(path, h)
		// DoH connections count like TCP and DoT ones; directly from
		// clients (HTTPS), the per-client limit applies too.
		ln = admitListener{Listener: ln, s: s, direct: tlsConf != nil}
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	proto := "http"
	if tlsConf != nil {
		proto = "https"
		srv.TLSConfig = tlsConf
		go srv.ServeTLS(ln, "", "") // ServeTLS enables HTTP/2
	} else {
		go srv.Serve(ln)
	}
	s.Log.Info("listening", "proto", proto, "addr", ln.Addr().String(), "path", path)
	return &httpListener{addr: addr, path: path, ln: ln, srv: srv}
}

// listenHTTPS serves h over HTTPS on TCP addr and, when h3Conf is set, over
// HTTP/3 on the same address and port over UDP. HTTP/1.1 and HTTP/2
// responses then advertise HTTP/3 with Alt-Svc.
func (s *Server) listenHTTPS(addr, path string, h http.Handler, tlsConf, h3Conf *tls.Config) (*httpListener, error) {
	if h3Conf == nil {
		return s.listenHTTP(addr, path, h, tlsConf)
	}
	// Bind TCP first: with port 0 (tests) UDP must use the port TCP got.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	port := ln.Addr().(*net.TCPAddr).Port
	q, err := s.listenH3(net.JoinHostPort(host, strconv.Itoa(port)), path, h, h3Conf)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("http3 (udp): %w (set doh.http3 = false to serve HTTP/1.1 and HTTP/2 only)", err)
	}
	altSvc := fmt.Sprintf(`h3=":%d"; ma=86400`, port)
	withAltSvc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", altSvc)
		h.ServeHTTP(w, r)
	})
	l := s.serveHTTP(ln, addr, path, withAltSvc, tlsConf)
	l.h3 = q
	return l, nil
}

func (l *httpListener) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l.srv.Shutdown(ctx)
	if l.h3 != nil {
		l.h3.close()
	}
}

// clientIP returns the real client address. X-Real-IP (or the last
// X-Forwarded-For entry) is trusted only from configured proxies.
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := ap.Addr().Unmap()
	if !guard.ACL(trusted).Contains(ip) {
		return ip
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		if a, err := netip.ParseAddr(v); err == nil {
			return a.Unmap()
		}
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		parts := strings.Split(v, ",")
		if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
			return a.Unmap()
		}
	}
	return ip
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var msg []byte
	var err error
	switch r.Method {
	case http.MethodGet:
		d := strings.TrimRight(r.URL.Query().Get("dns"), "=")
		if msg, err = base64.RawURLEncoding.DecodeString(d); err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/dns-message") {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		if msg, err = io.ReadAll(io.LimitReader(r.Body, 65535)); err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(msg) < m.HeaderLen {
		http.Error(w, "message too short", http.StatusBadRequest)
		return
	}
	proto, name := stats.DoH, "doh"
	if r.ProtoMajor == 3 {
		proto, name = stats.DoH3, "doh3"
	}
	s.Stats.Queries[proto].Add(1)
	st := s.state.Load()
	ip := clientIP(r, st.cfg.DoH.TrustedProxies)
	switch v := st.guard.Admit(ip); v {
	case guard.Allow:
	case guard.DenyACL:
		s.reject(v, ip)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	default:
		s.reject(v, ip)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	start := time.Now()
	sni := ""
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	res := s.resolve(msg, false, name, st.filterDoH(r.URL.Path, r.Host, sni))
	if res.Resp == nil {
		http.Error(w, "malformed dns message", http.StatusBadRequest)
		return
	}
	s.logQuery(st, ip, name, res, start)
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", m.ResponseMinTTL(res.Resp)))
	w.Write(res.Resp)
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.Stats.WritePrometheus(w)
	pos, neg := s.res.CacheCounts()
	fmt.Fprintf(w, "# TYPE dnsnova_cache_entries gauge\n")
	fmt.Fprintf(w, "dnsnova_cache_entries{kind=\"positive\"} %d\n", pos)
	fmt.Fprintf(w, "dnsnova_cache_entries{kind=\"negative\"} %d\n", neg)
	fmt.Fprintf(w, "# TYPE dnsnova_tcp_connections gauge\ndnsnova_tcp_connections %d\n", s.tcpConns.Load())
	fmt.Fprintf(w, "# TYPE dnsnova_quic_connections gauge\ndnsnova_quic_connections %d\n", s.quicConns.Load())
	st := s.state.Load()
	fmt.Fprintf(w, "# TYPE dnsnova_upstream_queries_total counter\n")
	for _, u := range st.group.Members() {
		fmt.Fprintf(w, "dnsnova_upstream_queries_total{upstream=%q,role=%q} %d\n", u.U.String(), role(u.Fallback), u.Queries())
	}
	fmt.Fprintf(w, "# TYPE dnsnova_upstream_errors_total counter\n")
	for _, u := range st.group.Members() {
		fmt.Fprintf(w, "dnsnova_upstream_errors_total{upstream=%q,role=%q} %d\n", u.U.String(), role(u.Fallback), u.Errors())
	}
	fmt.Fprintf(w, "# TYPE dnsnova_upstream_latency_seconds gauge\n")
	for _, u := range st.group.Members() {
		fmt.Fprintf(w, "dnsnova_upstream_latency_seconds{upstream=%q,role=%q} %.6f\n", u.U.String(), role(u.Fallback), u.Latency().Seconds())
	}
	fmt.Fprintf(w, "# TYPE dnsnova_upstream_healthy gauge\n")
	for _, u := range st.group.Members() {
		h := 0
		if u.Healthy() {
			h = 1
		}
		fmt.Fprintf(w, "dnsnova_upstream_healthy{upstream=%q,role=%q} %d\n", u.U.String(), role(u.Fallback), h)
	}
	s.writeRecursionMetrics(w)
}

func role(fallback bool) string {
	if fallback {
		return "fallback"
	}
	return "primary"
}

// handleHealth answers 200 when at least one upstream is healthy, 503
// otherwise, for monitors such as Uptime Kuma. Upstream addresses are not
// included, so the endpoint is safe to expose.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	st := s.state.Load()
	healthy, total := 0, 0
	for _, u := range st.group.Members() {
		total++
		if u.Healthy() {
			healthy++
		}
	}
	status, code := "ok", http.StatusOK
	recursion := st.cfg.Recursion.Enabled
	switch {
	case total == 0 && !recursion && !st.cfg.ServesDNS():
		status = "setup" // a fresh install: only the web interface runs
	case recursion && (s.Rec.Healthy() || healthy > 0):
	case recursion:
		status, code = "unhealthy", http.StatusServiceUnavailable
	case healthy == 0:
		status, code = "unhealthy", http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"status":            status,
		"upstreams_healthy": healthy,
		"upstreams_total":   total,
		"recursion":         recursion,
		"uptime_seconds":    int(time.Since(s.Stats.Started).Seconds()),
	})
}
