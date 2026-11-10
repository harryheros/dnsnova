package recursor

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Outgoing UDP queries go out from a pool of sockets, each bound to a
// random port by the kernel. Opening a socket for every query costs about
// a fifth of the CPU time on a busy server; the pool keeps most of the
// protection that gives against forged answers: each query uses one of up
// to poolSize sockets at random, and every socket is replaced after
// sockUses queries or sockAge, so ports keep changing. A forged answer has
// to match the port, the 16-bit ID, the server's address and the question.
//
// A port in use can be learnt (a query to a server the attacker runs shows
// it), which leaves the ID to guess. Guessing sends many wrong answers in a
// row, and those are seen: after spoofLimit packets from the server's
// address that are not the answer, the query gives up on UDP (ErrSpoofed)
// and is asked again over TCP, where an answer cannot be forged from off
// the path.
const (
	spoofLimit = 5
	poolSize   = 1024
	sockUses   = 100
	sockAge    = 30 * time.Second
)

type sockPool struct {
	mu    sync.Mutex
	slots [2][poolSize]*psock // IPv4, IPv6
}

type psock struct {
	conn    *net.UDPConn
	born    time.Time
	uses    int
	retired bool
	mu      sync.Mutex
	waiting map[waitKey]*waiter
}

type waitKey struct {
	id   uint16
	addr netip.AddrPort
}

type waiter struct {
	q       []byte
	ch      chan []byte
	wrong   int           // packets from the server that were not the answer (under psock.mu)
	spoofed chan struct{} // closed at spoofLimit wrong packets
}

var errBusy = errors.New("query id in use")

// ErrSpoofed reports a UDP query that drew forged answers.
var ErrSpoofed = errors.New("forged answers received")

// get returns a socket for a query to addr, registered to receive the
// answer to q.
func (p *sockPool) get(addr netip.AddrPort, q []byte) (*psock, *waiter, error) {
	fam := 0
	if addr.Addr().Is6() {
		fam = 1
	}
	now := time.Now()
	key := waitKey{id: be16(q), addr: addr}
	w := &waiter{q: q, ch: make(chan []byte, 1), spoofed: make(chan struct{})}
	for attempt := 0; attempt < 4; attempt++ {
		i := rand.IntN(poolSize)
		p.mu.Lock()
		s := p.slots[fam][i]
		if s == nil || s.uses >= sockUses || now.Sub(s.born) > sockAge {
			if s != nil {
				s.retire()
			}
			network := "udp4"
			if fam == 1 {
				network = "udp6"
			}
			c, err := net.ListenUDP(network, nil)
			if err != nil {
				p.slots[fam][i] = nil
				p.mu.Unlock()
				return nil, nil, err
			}
			s = &psock{conn: c, born: now, waiting: map[waitKey]*waiter{}}
			p.slots[fam][i] = s
			go s.read()
		}
		s.uses++
		p.mu.Unlock()
		s.mu.Lock()
		if _, busy := s.waiting[key]; !busy && !s.retired {
			s.waiting[key] = w
			s.mu.Unlock()
			return s, w, nil
		}
		s.mu.Unlock()
	}
	return nil, nil, errBusy
}

// retire stops new queries; the socket closes when the last one is done.
func (s *psock) retire() {
	s.mu.Lock()
	s.retired = true
	empty := len(s.waiting) == 0
	s.mu.Unlock()
	if empty {
		s.conn.Close()
	}
}

func (s *psock) done(w *waiter, key waitKey) {
	s.mu.Lock()
	if s.waiting[key] == w {
		delete(s.waiting, key)
	}
	closeNow := s.retired && len(s.waiting) == 0
	s.mu.Unlock()
	if closeNow {
		s.conn.Close()
	}
}

func (s *psock) read() {
	bp := udpBufs.Get().(*[]byte)
	defer udpBufs.Put(bp)
	buf := *bp
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < m.HeaderLen {
			continue
		}
		src := netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		key := waitKey{id: be16(buf), addr: src}
		s.mu.Lock()
		w := s.waiting[key]
		s.mu.Unlock()
		if w != nil && m.MatchResponse(w.q, buf[:n]) {
			select {
			case w.ch <- append([]byte(nil), buf[:n]...):
			default:
			}
			continue
		}
		s.wrongAnswer(src)
	}
}

// wrongAnswer counts a packet from src that answers nothing asked against
// every query waiting for src on this socket.
func (s *psock) wrongAnswer(src netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, w := range s.waiting {
		if k.addr == src {
			if w.wrong++; w.wrong == spoofLimit {
				close(w.spoofed)
			}
		}
	}
}

// exchangeUDP sends q to addr from a pooled socket and waits for the answer.
func (p *sockPool) exchangeUDP(ctx context.Context, addr netip.AddrPort, q []byte) ([]byte, error) {
	s, w, err := p.get(addr, q)
	if err != nil {
		return nil, err
	}
	key := waitKey{id: be16(q), addr: addr}
	defer s.done(w, key)
	if _, err := s.conn.WriteToUDPAddrPort(q, addr); err != nil {
		return nil, err
	}
	select {
	case resp := <-w.ch:
		return resp, nil
	case <-w.spoofed:
		return nil, ErrSpoofed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
