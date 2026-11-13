package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/events"
	"github.com/harryheros/dnsnova/internal/insight"
	"github.com/harryheros/dnsnova/internal/stats"
	"github.com/harryheros/dnsnova/internal/tlsmgr"
)

// adminListener serves the admin API on one TCP port, over HTTPS when a
// certificate is available and plain HTTP otherwise: the first byte of each
// connection tells them apart (0x16 starts a TLS handshake). Plain HTTP is
// answered only on this machine (see adminPlain).
type adminListener struct {
	addr          string
	ln            net.Listener
	plain, secure *http.Server
	plainL, tlsL  *chanListener
	wg            sync.WaitGroup
}

func (s *Server) listenAdmin(addr string) (*adminListener, error) {
	if s.admin == nil {
		a, err := admin.New(s, s.state.Load().cfg.Server.DataDir, s.Log)
		if err != nil {
			return nil, err
		}
		s.admin = a
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &adminListener{addr: addr, ln: ln, plainL: newChanListener(ln.Addr()), tlsL: newChanListener(ln.Addr())}
	newSrv := func(h http.Handler) *http.Server {
		return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
	}
	port := ""
	if _, p, err := net.SplitHostPort(ln.Addr().String()); err == nil {
		port = p
	}
	l.secure = newSrv(s.admin)
	l.plain = newSrv(s.adminPlain(port))
	tlsConf := s.Certs.TLSConfig("http/1.1")
	go l.plain.Serve(l.plainL)
	go l.secure.Serve(l.tlsL)
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				if isClosed(err) {
					return
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			go l.route(c, tlsConf, s.Certs.Ready)
		}
	}()
	s.Log.Info("listening", "proto", "admin", "addr", ln.Addr().String())
	return l, nil
}

func (l *adminListener) route(c net.Conn, tlsConf *tls.Config, ready func() bool) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	pc := &peekedConn{Conn: c, r: br}
	if b[0] == 0x16 {
		if !ready() {
			c.Close() // no certificate yet: TLS is not offered
			return
		}
		if !l.tlsL.put(tls.Server(pc, tlsConf)) {
			c.Close()
		}
		return
	}
	if !l.plainL.put(pc) {
		c.Close()
	}
}

func (l *adminListener) close() {
	l.ln.Close()
	l.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l.plain.Shutdown(ctx)
	l.secure.Shutdown(ctx)
}

// adminPlain serves the admin interface over plain HTTP, which carries the
// password and the session cookie in the clear. It is answered on this
// machine (a browser on the server itself or at the end of an SSH tunnel,
// or a reverse proxy here that says the visitor used HTTPS) and, on a
// server installed for a home or office network (server.mode = "private"),
// to that network. Anyone else is sent to HTTPS when the certificate covers
// the name they used, and otherwise refused with directions, so a password
// is never typed into an unencrypted page across the internet.
func (s *Server) adminPlain(port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if admin.Local(r) || admin.ForwardedHTTPS(r) || s.admin.LAN(r) {
			s.admin.ServeHTTP(w, r)
			return
		}
		ready := s.Certs != nil && s.Certs.Ready()
		var names []string
		if ready {
			names = s.Certs.Status().Names
			if certCovers(names, r.Host) && !proxied(r) {
				http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusPermanentRedirect)
				return
			}
		}
		msg := plainRefusal(r, port, names)
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
			return
		}
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, msg+"\n")
	})
}

// proxied reports whether a reverse proxy forwarded r (as admin sees it).
func proxied(r *http.Request) bool {
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Host", "X-Forwarded-Proto", "Via"} {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// plainRefusal says how to reach the admin interface instead.
func plainRefusal(r *http.Request, port string, certNames []string) string {
	if proxied(r) {
		return "The admin interface needs HTTPS. This request came through a reverse proxy without X-Forwarded-Proto: https; serve HTTPS there and send that header."
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		port = "7000"
	}
	lanHint := ""
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil && admin.NonPublic(ap.Addr()) {
		lanHint = " This server is set up for the internet (server.mode = \"public\"); on a home or office network, choose \"My network\" in the setup wizard or set server.mode = \"private\", and it opens directly from there."
	}
	tunnel := "ssh -L " + port + ":127.0.0.1:" + port + " user@" + host + " then open http://127.0.0.1:" + port + "/"
	for _, n := range certNames {
		if _, err := netip.ParseAddr(n); err != nil && !strings.HasPrefix(n, "*.") {
			return "The admin interface is not served over plain HTTP from other machines. Open https://" + n + ":" + port + "/ or use an SSH tunnel: " + tunnel + "." + lanHint
		}
	}
	return "The admin interface has no certificate yet, so other machines cannot open it: plain HTTP would expose the password. From your computer, open an SSH tunnel: " + tunnel + ". Once a domain is set up (Settings > Encrypted DNS), it also opens over HTTPS on this port." + lanHint
}

// certCovers reports whether a certificate for names is valid for the host
// in hostport (exact names, IP addresses and one-label wildcards).
func certCovers(names []string, hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return false
	}
	ip, ipErr := netip.ParseAddr(host)
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		if ipErr == nil {
			if a, err := netip.ParseAddr(n); err == nil && a.Unmap() == ip.Unmap() {
				return true
			}
			continue
		}
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if _, after, ok := strings.Cut(host, "."); ok && after == rest {
				return true
			}
		}
	}
	return false
}

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// chanListener hands connections accepted elsewhere to an http.Server.
type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener(a net.Addr) *chanListener {
	return &chanListener{addr: a, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) put(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

// AdminAddr returns the bound admin address, or "".
func (s *Server) AdminAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.adminL == nil {
		return ""
	}
	return s.adminL.ln.Addr().String()
}

// Admin returns the admin API (nil until admin.listen is set).
func (s *Server) Admin() *admin.Admin {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.admin
}

// ---- admin.Backend ----

// Version implements admin.Backend.
func (s *Server) Version() string {
	if s.BuildVersion == "" {
		return "dev"
	}
	return s.BuildVersion
}

// Started implements admin.Backend.
func (s *Server) Started() time.Time { return s.Stats.Started }

// Snapshot implements admin.Backend.
func (s *Server) Snapshot() *config.Snapshot { return s.snap.Load() }

// ApplyConfig implements admin.Backend: write, apply, and put the previous
// file back if applying fails (a port already in use, for example).
func (s *Server) ApplyConfig(src []byte, expected string) (*config.Snapshot, error) {
	if s.cl.run.Role == "follower" {
		return nil, config.ErrFollower
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	old := s.snap.Load()
	snap, err := s.Store.Write(src, expected)
	if err != nil {
		return nil, err
	}
	if err := s.Apply(snap); err != nil {
		if _, rerr := s.Store.Write(old.Doc.Src, snap.Hash); rerr != nil {
			s.Log.Error("could not restore the previous configuration file", "err", rerr)
		}
		return nil, err
	}
	return snap, nil
}

// ConfigHistory implements admin.Backend.
func (s *Server) ConfigHistory() ([]config.HistoryEntry, error) { return s.Store.History() }

// ConfigHistoryFile implements admin.Backend.
func (s *Server) ConfigHistoryFile(name string) ([]byte, error) {
	if name != filepath.Base(name) || !strings.HasSuffix(name, ".toml") || strings.HasPrefix(name, ".") {
		return nil, errors.New("invalid name")
	}
	return os.ReadFile(filepath.Join(s.Store.HistoryDir, name))
}

// Report implements admin.Backend.
func (s *Server) Report(span time.Duration) stats.Report { return s.History.Report(span, time.Now()) }

// Upstreams implements admin.Backend.
func (s *Server) Upstreams() []admin.Upstream {
	st := s.state.Load()
	if st == nil {
		return nil
	}
	var out []admin.Upstream
	for _, m := range st.group.Members() {
		role := "primary"
		if m.Fallback {
			role = "fallback"
		}
		out = append(out, admin.Upstream{Address: m.U.String(), Role: role, Healthy: m.Healthy(),
			LatencyMS: float64(m.Latency().Microseconds()) / 1000, Queries: m.Queries(), Errors: m.Errors(),
			LastOK: m.LastOK(), LastError: m.LastError()})
	}
	return out
}

// Certificate implements admin.Backend.
func (s *Server) Certificate() tlsmgr.Status { return s.Certs.Status() }

// Events implements admin.Backend.
func (s *Server) Events(limit int) []events.Event { return s.EventLog.Recent(limit) }

// Cache implements admin.Backend.
func (s *Server) Cache() (positive, negative int) { return s.res.CacheCounts() }

// ClearCache implements admin.Backend.
func (s *Server) ClearCache() {
	s.res.ClearCache()
	s.Rec.ClearCache()
	if st := s.state.Load(); st != nil {
		s.dropCacheFile(st.cfg) // or the old answers would come back after a restart
	}
}

// Listeners implements admin.Backend.
func (s *Server) Listeners() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	add := func(k, v string) { out[k] = append(out[k], v) }
	for _, l := range s.udp {
		add("udp", l.conn.LocalAddr().String())
	}
	for _, l := range s.tcp {
		add("tcp", l.ln.Addr().String())
	}
	for _, l := range s.dot {
		add("dot", l.ln.Addr().String())
	}
	for _, l := range s.doq {
		add("doq", l.pc.LocalAddr().String())
	}
	for _, l := range s.https {
		add("doh", l.ln.Addr().String())
		if l.h3 != nil {
			add("doh3", l.h3.pc.LocalAddr().String())
		}
	}
	if s.doh != nil {
		add("doh_proxy", s.doh.ln.Addr().String())
	}
	if s.metrics != nil {
		add("metrics", s.metrics.ln.Addr().String())
	}
	if s.adminL != nil {
		add("admin", s.adminL.ln.Addr().String())
	}
	for _, v := range out {
		slices.Sort(v)
	}
	return out
}

// Tops implements admin.Backend.
func (s *Server) Tops(span time.Duration) admin.Tops {
	now := time.Now()
	return admin.Tops{
		Domains:   s.Domains.List(span, now, 20),
		NXDomains: s.NXDomains.List(span, now, 20),
		Limited:   s.Limited.List(min(span, 24*time.Hour), now, 10),
	}
}

// QueryLog implements admin.Backend.
func (s *Server) QueryLog() *insight.QueryLog { return s.QLog }
