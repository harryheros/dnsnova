package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/harryheros/dnsnova/internal/dnsmsg"
)

// DNS over QUIC error codes (RFC 9250 section 4.3).
const (
	doqNoError       = 0x0
	doqRequestCancel = 0x3
)

// doqUpstream sends queries over DNS over QUIC (RFC 9250): one long-lived
// connection, one bidirectional stream per query. 0-RTT is never used, so a
// query cannot be replayed; a reconnect costs one round trip.
type doqUpstream struct {
	spec   Spec
	dialer *Dialer
	conf   *tls.Config

	mu   sync.Mutex
	conn *quic.Conn
	tr   *quic.Transport
}

func (u *doqUpstream) String() string { return u.spec.Raw }

func (u *doqUpstream) Close() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closeLocked()
}

func (u *doqUpstream) closeLocked() {
	if u.conn != nil {
		u.conn.CloseWithError(doqNoError, "")
		u.conn = nil
	}
	if u.tr != nil {
		u.tr.Close()
		u.tr.Conn.Close()
		u.tr = nil
	}
}

// connect returns the open connection, or dials a new one. reused reports
// whether the connection existed before this call.
func (u *doqUpstream) connect(ctx context.Context) (c *quic.Conn, reused bool, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn != nil && u.conn.Context().Err() == nil {
		return u.conn, true, nil
	}
	u.closeLocked()
	addrs, err := u.dialer.Resolve(ctx, u.spec.Host, u.spec.Pin)
	if err != nil {
		return nil, false, err
	}
	qconf := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
	}
	for _, a := range addrs {
		pc, lerr := net.ListenUDP("udp", nil) // a fresh socket: random source port
		if lerr != nil {
			return nil, false, lerr
		}
		tr := &quic.Transport{Conn: pc}
		c, err = tr.Dial(ctx, net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, uint16(u.spec.Port))), u.conf, qconf)
		if err == nil {
			u.conn, u.tr = c, tr
			return c, false, nil
		}
		tr.Close()
		pc.Close()
		if ctx.Err() != nil {
			break
		}
	}
	return nil, false, err
}

// drop forgets c if it is still the current connection.
func (u *doqUpstream) drop(c *quic.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn == c {
		u.closeLocked()
	}
}

func (u *doqUpstream) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	q := dnsmsg.WithID(msg, 0) // RFC 9250 4.2.1
	for attempt := 0; attempt < 2; attempt++ {
		c, reused, err := u.connect(ctx)
		if err != nil {
			return nil, err
		}
		resp, err := u.exchange(ctx, c, q)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if c.Context().Err() != nil {
			u.drop(c)
			if reused {
				continue // the server probably closed the idle connection
			}
		}
		return nil, err
	}
	return nil, errors.New("doq: retry failed")
}

func (u *doqUpstream) exchange(ctx context.Context, c *quic.Conn, q []byte) ([]byte, error) {
	str, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		str.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() {
		str.CancelRead(doqRequestCancel)
		str.CancelWrite(doqRequestCancel)
	})
	defer stop()
	buf := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(buf, uint16(len(q)))
	copy(buf[2:], q)
	if _, err := str.Write(buf); err != nil {
		return nil, err
	}
	str.Close() // FIN: one query per stream
	var lb [2]byte
	if _, err := io.ReadFull(str, lb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(str, resp); err != nil {
		return nil, err
	}
	str.CancelRead(doqNoError) // done with this stream
	if !dnsmsg.MatchResponse(q, resp) {
		return nil, dnsmsg.ErrMalformed
	}
	return resp, nil
}
