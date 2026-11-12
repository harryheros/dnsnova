// Package proxyproto reads the PROXY protocol header (versions 1 and 2, as
// specified by HAProxy) that a load balancer puts in front of a connection,
// or of each UDP datagram (version 2, as dnsdist sends it), to tell the
// server the client's real address.
//
// The header is believed only from configured proxies; from them it is
// required, as the specification asks: a receiver must not guess.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sigV2 starts every version 2 header.
var sigV2 = []byte("\r\n\r\n\x00\r\nQUIT\n")

// ErrHeader is returned for a missing, malformed or unsupported header.
var ErrHeader = errors.New("proxy protocol: bad header")

const (
	maxV1   = 107 // the longest version 1 line, CRLF included
	v2Fixed = 16
	// MaxV2 bounds the address and TLV part of a version 2 header: real
	// ones are a few dozen bytes; the format allows 64 KB.
	MaxV2 = 1024
)

// Header is what a PROXY header says. Local: the proxy's own connection
// (a health check, or "UNKNOWN"): use the connection's addresses.
type Header struct {
	Source, Dest netip.AddrPort
	Local        bool
}

// ParseV2 parses a version 2 header at the start of b and returns it and
// its length. For UDP, where every datagram starts with one.
func ParseV2(b []byte) (Header, int, error) {
	if len(b) < v2Fixed || !bytes.Equal(b[:12], sigV2) {
		return Header{}, 0, ErrHeader
	}
	n := int(binary.BigEndian.Uint16(b[14:16]))
	if n > MaxV2 || len(b) < v2Fixed+n {
		return Header{}, 0, ErrHeader
	}
	h, err := v2Body(b[12], b[13], b[v2Fixed:v2Fixed+n])
	return h, v2Fixed + n, err
}

func v2Body(verCmd, fam byte, body []byte) (Header, error) {
	if verCmd>>4 != 2 {
		return Header{}, ErrHeader
	}
	switch verCmd & 0xF {
	case 0: // LOCAL
		return Header{Local: true}, nil
	case 1: // PROXY
	default:
		return Header{}, ErrHeader
	}
	var h Header
	switch fam >> 4 {
	case 0: // AF_UNSPEC: addresses not known
		return Header{Local: true}, nil
	case 1: // AF_INET
		if len(body) < 12 {
			return Header{}, ErrHeader
		}
		h.Source = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[0:4])), binary.BigEndian.Uint16(body[8:]))
		h.Dest = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[4:8])), binary.BigEndian.Uint16(body[10:]))
	case 2: // AF_INET6
		if len(body) < 36 {
			return Header{}, ErrHeader
		}
		h.Source = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[0:16])).Unmap(), binary.BigEndian.Uint16(body[32:]))
		h.Dest = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[16:32])).Unmap(), binary.BigEndian.Uint16(body[34:]))
	default: // AF_UNIX: no address to use
		return Header{}, ErrHeader
	}
	if p := fam & 0xF; p != 1 && p != 2 { // STREAM or DGRAM
		return Header{}, ErrHeader
	}
	return h, nil
}

// parseV1 parses a version 1 line, CRLF included.
func parseV1(line string) (Header, error) {
	line, ok := strings.CutSuffix(line, "\r\n")
	if !ok || len(line)+2 > maxV1 {
		return Header{}, ErrHeader
	}
	f := strings.Split(line, " ")
	if len(f) >= 2 && f[0] == "PROXY" && f[1] == "UNKNOWN" {
		return Header{Local: true}, nil // the rest of the line is to be ignored
	}
	if len(f) != 6 || f[0] != "PROXY" || (f[1] != "TCP4" && f[1] != "TCP6") {
		return Header{}, ErrHeader
	}
	src, err1 := netip.ParseAddr(f[2])
	dst, err2 := netip.ParseAddr(f[3])
	sp, err3 := port(f[4])
	dp, err4 := port(f[5])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || src.Is4() != (f[1] == "TCP4") || dst.Is4() != src.Is4() || src.Zone() != "" {
		return Header{}, ErrHeader
	}
	return Header{Source: netip.AddrPortFrom(src, sp), Dest: netip.AddrPortFrom(dst, dp)}, nil
}

// port parses a decimal port without sign or leading zeros.
func port(s string) (uint16, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') || s[0] == '+' || s[0] == '-' {
		return 0, ErrHeader
	}
	n, err := strconv.ParseUint(s, 10, 16)
	return uint16(n), err
}

// Read reads one header, version 1 or 2, from the start of a stream, and
// nothing past it.
func Read(r io.Reader) (Header, error) {
	var b [v2Fixed]byte
	if _, err := io.ReadFull(r, b[:6]); err != nil {
		return Header{}, ErrHeader
	}
	if string(b[:6]) == "PROXY " {
		line := make([]byte, 6, maxV1)
		copy(line, b[:6])
		for len(line) < maxV1 {
			var c [1]byte
			if _, err := io.ReadFull(r, c[:]); err != nil {
				return Header{}, ErrHeader
			}
			line = append(line, c[0])
			if c[0] == '\n' {
				return parseV1(string(line))
			}
		}
		return Header{}, ErrHeader
	}
	if !bytes.Equal(b[:6], sigV2[:6]) {
		return Header{}, ErrHeader
	}
	if _, err := io.ReadFull(r, b[6:]); err != nil || !bytes.Equal(b[:12], sigV2) {
		return Header{}, ErrHeader
	}
	n := int(binary.BigEndian.Uint16(b[14:]))
	if n > MaxV2 {
		return Header{}, ErrHeader
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Header{}, ErrHeader
	}
	return v2Body(b[12], b[13], body)
}

// Conn is a connection whose RemoteAddr (and LocalAddr) are the ones its
// PROXY header gave.
type Conn struct {
	net.Conn
	remote, local net.Addr
}

func (c *Conn) RemoteAddr() net.Addr { return c.remote }
func (c *Conn) LocalAddr() net.Addr  { return c.local }

// HeaderTimeout is how long a trusted proxy has to send the header.
const HeaderTimeout = 5 * time.Second

// Listener wraps a TCP listener: connections from Trusted must start with a
// PROXY header, and are returned with the client's address; others are
// returned as they are. Headers are read off the accept loop, so a proxy
// that is slow to send one holds up no one else.
type Listener struct {
	net.Listener
	// Trusted reports whether a connection's peer is a proxy whose header
	// is required and believed (read for each connection, so it can change).
	Trusted func(netip.Addr) bool
	// Rejected is called for a trusted peer whose header was missing or
	// malformed (the connection is closed); may be nil.
	Rejected func(peer netip.Addr, err error)

	once, closeOnce sync.Once
	ready           chan net.Conn
	errc            chan error
	done            chan struct{}
}

// NewListener returns ln with PROXY headers required from trusted peers.
func NewListener(ln net.Listener, trusted func(netip.Addr) bool) *Listener {
	return &Listener{Listener: ln, Trusted: trusted}
}

func (l *Listener) start() {
	l.ready = make(chan net.Conn)
	l.errc = make(chan error, 1)
	l.done = make(chan struct{})
	go func() {
		for {
			c, err := l.Listener.Accept()
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				l.errc <- err
				return
			}
			peer := netip.Addr{}
			if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
				peer = ap.Addr().Unmap()
			}
			if l.Trusted == nil || !l.Trusted(peer) {
				l.deliver(c)
				continue
			}
			go func() {
				c.SetReadDeadline(time.Now().Add(HeaderTimeout))
				h, err := Read(c)
				c.SetReadDeadline(time.Time{})
				if err != nil {
					if l.Rejected != nil {
						l.Rejected(peer, err)
					}
					c.Close()
					return
				}
				if h.Local {
					l.deliver(c)
					return
				}
				l.deliver(&Conn{Conn: c, remote: net.TCPAddrFromAddrPort(h.Source), local: net.TCPAddrFromAddrPort(h.Dest)})
			}()
		}
	}()
}

func (l *Listener) deliver(c net.Conn) {
	select {
	case l.ready <- c:
	case <-l.done:
		c.Close()
	}
}

// Accept returns the next connection, its header read when one is due.
func (l *Listener) Accept() (net.Conn, error) {
	l.once.Do(l.start)
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.errc:
		l.errc <- err // every later call fails the same way
		return nil, err
	}
}

// Close stops the listener; connections whose header was still being read
// are closed.
func (l *Listener) Close() error {
	l.once.Do(l.start)
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}
