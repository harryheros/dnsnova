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
	ch      chan []byte   // answers that match the question, as they arrive
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
	w := &waiter{q: q, ch: make(chan []byte, 4), spoofed: make(chan struct{})}
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
	return pick(ctx, judgeOf(ctx), w.ch, w.spoofed)
}

// Censors on the path between a resolver and name servers (the Great
// Firewall of China is the best known) answer questions about the names
// they block themselves: they see the question go by and send forged
// answers at once, from the server's address, with its port, ID and
// question. They cannot stop the genuine answer, which arrives after
// theirs (in China, 99% of forged answers come at most 364 ms earlier;
// Hoang et al., USENIX Security 2021). Taking the first answer that
// matches, as resolvers do, takes the forged one; asking again over TCP
// does not help, as the censor resets those connections.
//
// So each answer is judged as it arrives (judgeFn, made by ask for the
// question): one that cannot be the server's is dropped and the socket
// kept open; one that is merely unusual for it is kept while a better one
// may still come. Answers that pass come through at once, as before.

// verdict is what a judge makes of one answer.
type verdict int

const (
	vAccept  verdict = iota
	vSuspect         // possible, but unlike the server: wait a little for another
	vForged          // cannot be the server's over UDP: wait for another
	vGiveUp          // cannot be the server's, and no better one will come
)

// judgeFn judges one UDP answer that matches the question.
type judgeFn func(resp []byte) verdict

type judgeKey struct{}

// withJudge makes the UDP exchanges under ctx judge their answers.
func withJudge(ctx context.Context, j judgeFn) context.Context {
	return context.WithValue(ctx, judgeKey{}, j)
}

func judgeOf(ctx context.Context) judgeFn {
	j, _ := ctx.Value(judgeKey{}).(judgeFn)
	return j
}

// ErrForged reports a UDP question whose answers were all judged forged
// or doubtful, with no better one before the time ran out. The question
// is asked again over TCP.
var ErrForged = errors.New("only forged answers received")

// forgedGrace is how long a better answer is waited for after a forged or
// doubtful one, within the query's own timeout.
const forgedGrace = 500 * time.Millisecond

// pick returns the first answer on ch that judge accepts (any, without a
// judge). After one it rejects, it waits at most forgedGrace for a good
// one, then gives up with ErrForged (at once for vGiveUp).
func pick(ctx context.Context, judge judgeFn, ch <-chan []byte, spoofed <-chan struct{}) ([]byte, error) {
	var grace <-chan time.Time
	rejected := false
	for {
		select {
		case resp := <-ch:
			v := vAccept
			if judge != nil {
				v = judge(resp)
			}
			switch v {
			case vAccept:
				return resp, nil
			case vGiveUp:
				return nil, ErrForged
			}
			if !rejected {
				rejected = true
				t := time.NewTimer(forgedGrace)
				defer t.Stop()
				grace = t.C
			}
		case <-grace:
			return nil, ErrForged
		case <-spoofed:
			return nil, ErrSpoofed
		case <-ctx.Done():
			if rejected {
				return nil, ErrForged
			}
			return nil, ctx.Err()
		}
	}
}
