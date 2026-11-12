package server

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Anycast: several nodes announce the same address with BGP, and each
// client reaches the nearest. A node that cannot answer must take its
// route back, or the clients near it get no answers at all. DNSNova checks
// itself every anycast.interval; after anycast.fall failed checks in a row
// it runs the operator's withdraw command (for example
// "birdc disable anycast"), after anycast.rise good ones the announce
// command. A failed command is tried again at the next check.
//
// A check passes when the server reports itself healthy (as /healthz: it
// can resolve) and its own UDP listener answers a query for "localhost",
// which is answered locally, through the same socket clients use.
//
// At shutdown the route is withdrawn first, and the server keeps answering
// for anycast.drain while the routers move traffic to other nodes.
//
// The commands come from the file only (never the admin API or a cluster
// primary) and run as the dnsnova user, without a shell.

const (
	anycastAnnounced = "announced"
	anycastWithdrawn = "withdrawn"
)

type anycastState struct {
	mu        sync.Mutex
	state     string // announced or withdrawn ("" before the first command)
	good, bad int
	lastErr   string
	cancel    context.CancelFunc
	done      chan struct{}
	// testHealth replaces the health check in tests (nil: the real one).
	testHealth func() bool
}

// startAnycast starts the checks when [anycast] is enabled. Changes to
// [anycast] enabled apply after a restart; the commands, interval, rise,
// fall and drain are read again at every check.
func (s *Server) startAnycast() {
	st := s.state.Load()
	if st == nil || !st.cfg.Anycast.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.any.cancel, s.any.done = cancel, make(chan struct{})
	go func() {
		defer close(s.any.done)
		// start from a known state: withdrawn until the checks pass
		s.anycastRun(st.cfg.Anycast.Withdraw, anycastWithdrawn)
		for {
			c := s.state.Load().cfg.Anycast
			select {
			case <-ctx.Done():
				return
			case <-time.After(c.Interval):
			}
			s.anycastCheck(ctx)
		}
	}()
}

func (s *Server) anycastCheck(ctx context.Context) {
	c := s.state.Load().cfg.Anycast
	ok := s.anycastHealthy(ctx)
	s.any.mu.Lock()
	if ok {
		s.any.good, s.any.bad = s.any.good+1, 0
	} else {
		s.any.good, s.any.bad = 0, s.any.bad+1
	}
	state, good, bad := s.any.state, s.any.good, s.any.bad
	s.any.mu.Unlock()
	switch {
	case state != anycastAnnounced && good >= c.Rise:
		s.anycastRun(c.Announce, anycastAnnounced)
	case state != anycastWithdrawn && bad >= c.Fall:
		s.anycastRun(c.Withdraw, anycastWithdrawn)
	}
}

// anycastRun runs argv and, if it succeeds, records the new state.
func (s *Server) anycastRun(argv []string, to string) bool {
	if len(argv) == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	s.any.mu.Lock()
	defer s.any.mu.Unlock()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if s.any.lastErr != err.Error()+msg {
			s.Log.Error("anycast: command failed; trying again at the next check", "command", strings.Join(argv, " "), "err", err, "output", msg)
		}
		s.any.lastErr = err.Error() + msg
		return false
	}
	s.any.lastErr = ""
	if s.any.state != to {
		if to == anycastAnnounced {
			s.Log.Info("anycast: route announced", "after_good_checks", s.any.good)
		} else {
			s.Log.Warn("anycast: route withdrawn", "after_failed_checks", s.any.bad)
		}
	}
	s.any.state = to
	return true
}

// anycastHealthy is one check: healthy, and the UDP listener answers.
func (s *Server) anycastHealthy(ctx context.Context) bool {
	s.any.mu.Lock()
	th := s.any.testHealth
	s.any.mu.Unlock()
	if th != nil {
		return th() && probeUDP(ctx, s.probeAddr())
	}
	if status, ok := s.health(); !ok || status == "setup" {
		return false
	}
	addr := s.probeAddr()
	if !addr.IsValid() {
		return true // no plain DNS listener (encrypted DNS only): health alone
	}
	return probeUDP(ctx, addr)
}

// probeAddr is where to send the self-check: the first plain DNS socket,
// on loopback when it listens on every address.
func (s *Server) probeAddr() netip.AddrPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.udp {
		ap, err := netip.ParseAddrPort(l.conn.LocalAddr().String())
		if err != nil {
			continue
		}
		a := ap.Addr()
		if a.IsUnspecified() {
			a = netip.MustParseAddr("127.0.0.1")
			if ap.Addr().Is6() && !ap.Addr().Is4In6() {
				a = netip.IPv6Loopback()
			}
		}
		return netip.AddrPortFrom(a.Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

// probeUDP asks addr for localhost/A and expects an answer.
func probeUDP(ctx context.Context, addr netip.AddrPort) bool {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	id := uint16(time.Now().UnixNano())
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	q = append(q, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0, 0, 1, 0, 1)
	if _, err := c.Write(q); err != nil {
		return false
	}
	b := make([]byte, 512)
	n, err := c.Read(b)
	return err == nil && n >= m.HeaderLen && binary.BigEndian.Uint16(b) == id && m.Rcode(b[:n]) == m.RcodeNoError
}

// anycastState is "announced", "withdrawn", or "" when anycast is off.
func (s *Server) anycastState() string {
	s.any.mu.Lock()
	defer s.any.mu.Unlock()
	return s.any.state
}

// anycastDrain withdraws the route before shutdown and waits for the
// routers to move traffic away, while the server still answers.
func (s *Server) anycastDrain() {
	if s.any.cancel == nil {
		return
	}
	s.any.cancel()
	<-s.any.done
	c := s.state.Load().cfg.Anycast
	if s.anycastState() == anycastAnnounced && s.anycastRun(c.Withdraw, anycastWithdrawn) && c.Drain > 0 {
		s.Log.Info("anycast: route withdrawn for shutdown; still answering while traffic moves away", "drain", c.Drain.String())
		time.Sleep(c.Drain)
	}
}
