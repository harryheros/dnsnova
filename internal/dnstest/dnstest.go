// Package dnstest provides helpers for dnsnova's tests: building queries,
// inspecting responses and a small fake authoritative server.
package dnstest

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Wire converts a dotted name to wire format with the final zero.
func Wire(name string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// Query builds a query with RD set.
func Query(id uint16, name string, qtype uint16, edns, do bool) []byte {
	b := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	b = append(b, Wire(name)...)
	b = append(b, byte(qtype>>8), byte(qtype), 0, 1)
	if edns {
		b[11] = 1
		b = m.AppendOPT(b, 1232, do, nil)
	}
	return b
}

// Resp is a decoded response.
type Resp struct {
	ID, Flags  uint16
	AN, NS, AR int
	Rcode      int
	TTLs       []uint32
	Types      []uint16
	HasOPT     bool
	OPTDO      bool
	QName      []byte
}

// TC, AD and AA report flags.
func (r Resp) TC() bool { return r.Flags&m.FlagTC != 0 }
func (r Resp) AD() bool { return r.Flags&m.FlagAD != 0 }
func (r Resp) AA() bool { return r.Flags&m.FlagAA != 0 }

// Parse decodes a response or fails the test.
func Parse(t testing.TB, b []byte) Resp {
	t.Helper()
	if len(b) < m.HeaderLen {
		t.Fatalf("short response (%d bytes)", len(b))
	}
	r := Resp{ID: m.U16(b, 0), Flags: m.U16(b, 2), AN: int(m.U16(b, 6)), NS: int(m.U16(b, 8)), AR: int(m.U16(b, 10))}
	r.Rcode = int(r.Flags & 0xF)
	off := m.HeaderLen
	if m.U16(b, 4) == 1 {
		end, err := m.SkipName(b, m.HeaderLen)
		if err != nil {
			t.Fatal(err)
		}
		r.QName = b[m.HeaderLen:end]
		off = end + 4
	}
	off, err := m.WalkRRs(b, off, r.AN+r.NS, func(rr m.RR) error {
		r.TTLs = append(r.TTLs, m.U32(b, rr.TTLOff))
		r.Types = append(r.Types, rr.Type)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.WalkRRs(b, off, r.AR, func(rr m.RR) error {
		if rr.Type == m.TypeOPT {
			r.HasOPT = true
			r.OPTDO = b[rr.TTLOff+2]&0x80 != 0
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

// Auth is a fake authoritative server. Names it knows:
//
//	nx.test.    NXDOMAIN with an SOA (TTL 900, minimum 300)
//	big.test.   15 TXT records (about 1 KB)
//	huge.test.  60 TXT records (truncated over UDP)
//	signed.test. an A record with the AD flag set
//	anything else: A 1.2.3.4 with TTL from SetTTL (default 300),
//	               other types NODATA with an SOA
type Auth struct {
	mu       sync.Mutex
	counts   map[string]int
	ttl      atomic.Uint32
	delay    atomic.Int64
	ServFail atomic.Bool
}

// NewAuth returns a fake server.
func NewAuth() *Auth {
	a := &Auth{counts: map[string]int{}}
	a.ttl.Store(300)
	return a
}

// SetTTL sets the TTL of A records.
func (a *Auth) SetTTL(ttl uint32) { a.ttl.Store(ttl) }

// SetDelay makes every answer wait d.
func (a *Auth) SetDelay(d time.Duration) { a.delay.Store(int64(d)) }

// Count returns how many times a dotted name was queried.
func (a *Auth) Count(name string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counts[name]
}

// Answer builds the response to req; udp limits it to 1232 bytes.
func (a *Auth) Answer(req []byte, udp bool) []byte {
	q, rc, err := m.ParseQuery(req)
	if err != nil || rc != 0 {
		return nil
	}
	name := m.NameString(q.Name)
	a.mu.Lock()
	a.counts[name]++
	a.mu.Unlock()
	if d := a.delay.Load(); d > 0 {
		time.Sleep(time.Duration(d))
	}
	flags := uint16(m.FlagQR|m.FlagRD|m.FlagRA) | q.Flags&m.FlagCD
	b := []byte{req[0], req[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	b = append(b, req[12:q.QEnd]...)
	rr := func(typ uint16, ttl uint32, rdata []byte) {
		b = append(b, 0xC0, 0x0C, byte(typ>>8), byte(typ), 0, 1)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
		b = append(b, rdata...)
	}
	soa := func() {
		rd := append(Wire("ns.test"), Wire("admin.test")...)
		for _, v := range []uint32{1, 3600, 600, 86400, 300} {
			rd = binary.BigEndian.AppendUint32(rd, v)
		}
		rr(m.TypeSOA, 900, rd)
	}
	var an, ns uint16
	switch {
	case a.ServFail.Load():
		flags |= m.RcodeServFail
	case name == "nx.test.":
		flags |= m.RcodeNXDomain
		soa()
		ns = 1
	case name == "big.test." || name == "huge.test.":
		n := 15
		if name == "huge.test." {
			n = 60
		}
		for i := 0; i < n; i++ {
			rr(16, 300, append([]byte{48}, bytes.Repeat([]byte{'x'}, 48)...))
		}
		an = uint16(n)
	case q.Type == m.TypeA:
		if name == "signed.test." {
			flags |= m.FlagAD
		}
		rr(m.TypeA, a.ttl.Load(), []byte{1, 2, 3, 4})
		an = 1
	default:
		soa()
		ns = 1
	}
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[6:], an)
	binary.BigEndian.PutUint16(b[8:], ns)
	if q.EDNS {
		b[11] = 1
		b = m.AppendOPT(b, 1232, q.DO, nil)
	}
	if udp && len(b) > 1232 {
		t := []byte{req[0], req[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(t[2:], flags|m.FlagTC)
		return append(t, req[12:q.QEnd]...)
	}
	return b
}

// Server runs an Auth on UDP and TCP on the same loopback port.
type Server struct {
	*Auth
	Addr string
	uc   *net.UDPConn
	tl   net.Listener
}

// Serve starts a fake server; it stops when the test ends.
func Serve(t testing.TB) *Server {
	t.Helper()
	for i := 0; i < 20; i++ {
		uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		tl, err := net.Listen("tcp", uc.LocalAddr().String())
		if err != nil {
			uc.Close()
			continue
		}
		s := &Server{Auth: NewAuth(), Addr: uc.LocalAddr().String(), uc: uc, tl: tl}
		go s.serveUDP()
		go s.serveTCP()
		t.Cleanup(func() { uc.Close(); tl.Close() })
		return s
	}
	t.Fatal("could not bind a fake upstream")
	return nil
}

func (s *Server) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, a, err := s.uc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		go func() {
			if r := s.Answer(pkt, true); r != nil {
				s.uc.WriteToUDPAddrPort(r, a)
			}
		}()
	}
}

func (s *Server) serveTCP() {
	for {
		c, err := s.tl.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				r := s.Answer(msg, false)
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
			}
		}()
	}
}

// Exchanger adapts an Auth to the resolver's upstream interface, in process.
type Exchanger struct{ *Auth }

// Exchange answers msg as if over TCP (no truncation).
func (e Exchanger) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := e.Answer(msg, false)
	if r == nil {
		return nil, m.ErrMalformed
	}
	return r, nil
}
