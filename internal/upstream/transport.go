package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Upstream sends one query and returns the matching response.
type Upstream interface {
	Exchange(ctx context.Context, msg []byte) ([]byte, error)
	String() string
	Close()
}

// New creates the transport for s. tlsConf overrides the TLS settings
// (used by tests); nil means the system roots and TLS 1.2 or later.
func New(s Spec, d *Dialer, tlsConf *tls.Config) (Upstream, error) {
	dial := d.DialFunc(s.Pin)
	switch s.Scheme {
	case "udp":
		return &udpUpstream{spec: s, dial: dial, tcp: &tcpUpstream{spec: s, dial: dial}}, nil
	case "tcp":
		return &tcpUpstream{spec: s, dial: dial}, nil
	case "tls":
		conf := tlsConfig(tlsConf)
		conf.ServerName = s.Host
		return &dotUpstream{spec: s, dial: dial, conf: conf}, nil
	case "https":
		conf := tlsConfig(tlsConf)
		tr := &http.Transport{
			DialContext:         dial,
			TLSClientConfig:     conf,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			Proxy:               nil, // never send DNS through an HTTP proxy from the environment
		}
		return &dohUpstream{spec: s, tr: tr, client: &http.Client{Transport: tr}}, nil
	case "quic":
		conf := tlsConfig(tlsConf)
		conf.ServerName = s.Host
		conf.NextProtos = []string{"doq"}
		return &doqUpstream{spec: s, dialer: d, conf: conf}, nil
	}
	return nil, fmt.Errorf("unsupported scheme %q", s.Scheme)
}

func tlsConfig(override *tls.Config) *tls.Config {
	if override != nil {
		return override.Clone()
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(32)}
}

// deadline applies ctx's deadline and cancellation to conn. The returned
// function must be called when the exchange is over; it reports false if the
// context fired, in which case conn must not be reused.
func deadline(ctx context.Context, conn net.Conn) func() bool {
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	return context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
}

// ---- UDP, falling back to TCP when the answer is truncated ----

// udpBufs holds receive buffers: allocating 64 KB for every upstream query
// cost about a quarter of the CPU time on a busy server (mostly garbage
// collection).
var udpBufs = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

type udpUpstream struct {
	spec Spec
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	tcp  *tcpUpstream
}

func (u *udpUpstream) String() string { return u.spec.Raw }
func (u *udpUpstream) Close()         {}

func (u *udpUpstream) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	q := dnsmsg.WithID(msg, uint16(rand.Uint32()))
	conn, err := u.dial(ctx, "udp", u.spec.Addr()) // a fresh socket: random source port
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := deadline(ctx, conn)
	defer stop()
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	bp := udpBufs.Get().(*[]byte)
	defer udpBufs.Put(bp)
	buf := *bp
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		resp := buf[:n]
		if !dnsmsg.MatchResponse(q, resp) {
			continue // not ours (spoofed or late); keep waiting
		}
		if dnsmsg.U16(resp, 2)&dnsmsg.FlagTC != 0 {
			return u.tcp.Exchange(ctx, msg)
		}
		return append([]byte(nil), resp...), nil
	}
}

// ---- TCP ----

type tcpUpstream struct {
	spec Spec
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (u *tcpUpstream) String() string { return u.spec.Raw }
func (u *tcpUpstream) Close()         {}

func (u *tcpUpstream) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	q := dnsmsg.WithID(msg, uint16(rand.Uint32()))
	conn, err := u.dial(ctx, "tcp", u.spec.Addr())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := deadline(ctx, conn)
	defer stop()
	resp, err := streamExchange(conn, q)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return resp, err
}

// streamExchange writes one length-prefixed query and reads its response.
func streamExchange(conn net.Conn, q []byte) ([]byte, error) {
	buf := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(buf, uint16(len(q)))
	copy(buf[2:], q)
	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}
	for i := 0; i < 8; i++ {
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		if dnsmsg.MatchResponse(q, resp) {
			return resp, nil
		}
	}
	return nil, errors.New("no matching response")
}

// ---- DNS over TLS, with a small pool of persistent connections ----

type dotUpstream struct {
	spec Spec
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	conf *tls.Config
	mu   sync.Mutex
	idle []*dotConn
}

type dotConn struct {
	c    net.Conn
	last time.Time
}

func (u *dotUpstream) String() string { return u.spec.Raw }

func (u *dotUpstream) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, c := range u.idle {
		c.c.Close()
	}
	u.idle = nil
}

func (u *dotUpstream) get() *dotConn {
	u.mu.Lock()
	defer u.mu.Unlock()
	for len(u.idle) > 0 {
		c := u.idle[len(u.idle)-1]
		u.idle = u.idle[:len(u.idle)-1]
		if time.Since(c.last) < 20*time.Second {
			return c
		}
		c.c.Close()
	}
	return nil
}

func (u *dotUpstream) put(c *dotConn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.idle) < 16 {
		u.idle = append(u.idle, c)
		return
	}
	c.c.Close()
}

func (u *dotUpstream) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	q := dnsmsg.WithID(msg, uint16(rand.Uint32()))
	for attempt := 0; attempt < 2; attempt++ {
		dc := u.get()
		reused := dc != nil
		if dc == nil {
			raw, err := u.dial(ctx, "tcp", u.spec.Addr())
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, u.conf)
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			dc = &dotConn{c: tc}
		}
		stop := deadline(ctx, dc.c)
		resp, err := streamExchange(dc.c, q)
		clean := stop()
		if err != nil {
			dc.c.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if reused {
				continue // the server probably closed the idle connection
			}
			return nil, err
		}
		if clean {
			dc.c.SetDeadline(time.Time{})
			dc.last = time.Now()
			u.put(dc)
		} else {
			dc.c.Close()
		}
		return resp, nil
	}
	return nil, errors.New("dot: retry failed")
}

// ---- DNS over HTTPS (HTTP/2 when the server offers it) ----

type dohUpstream struct {
	spec   Spec
	tr     *http.Transport
	client *http.Client
}

func (u *dohUpstream) String() string { return u.spec.Raw }
func (u *dohUpstream) Close()         { u.tr.CloseIdleConnections() }

func (u *dohUpstream) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	q := dnsmsg.WithID(msg, 0) // RFC 8484 4.1
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.spec.URL, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "dnsnova")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	if !dnsmsg.MatchResponse(q, body) {
		return nil, dnsmsg.ErrMalformed
	}
	return body, nil
}
