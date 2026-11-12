package recursor

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// cookieNet puts DNS Cookies (RFC 7873) on the fake servers' answers, per
// server and as each test needs:
//
//	echo       a server with cookies: the client cookie back, and its own
//	wrong      UDP answers carry someone else's client cookie (forged)
//	udp-drop   after three answers, UDP ones come without a cookie (forged);
//	           TCP ones still have it
//	never      after three answers, none has a cookie, TCP included (anycast
//	           instances that differ)
//	badcookie  BADCOOKIE until the client sends the server cookie
//	formerr    FORMERR for any question with a COOKIE option
type cookieNet struct {
	*fakeNet
	mode     map[netip.Addr]string
	mu       sync.Mutex
	answered map[netip.Addr]int
	sent     map[netip.Addr][][]byte // the COOKIE data of each question
}

var serverCookie = []byte("SRVCOOKIE1234567")

func newCookieNet(modes map[netip.Addr]string) *cookieNet {
	return &cookieNet{fakeNet: world(), mode: modes, answered: map[netip.Addr]int{}, sent: map[netip.Addr][][]byte{}}
}

func (n *cookieNet) send(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
	a := addr.Addr()
	qm, err := parseMessage(q)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.sent[a] = append(n.sent[a], qm.cookie)
	n.mu.Unlock()
	mode := n.mode[a]
	if mode == "formerr" && qm.cookie != nil {
		return buildMessage(qm.id, m.FlagQR|m.RcodeFormErr, qm.qname, qm.qtype, nil, nil, nil, true, false, nil), nil
	}
	resp, err := n.fakeNet.send(ctx, addr, q, tcp)
	if err != nil || mode == "" || qm.cookie == nil {
		return resp, err
	}
	msg, err := parseMessage(resp)
	if err != nil {
		return resp, nil
	}
	n.mu.Lock()
	n.answered[a]++
	count := n.answered[a]
	n.mu.Unlock()
	cc := qm.cookie[:8]
	var opt []byte
	rcode := -1
	switch {
	case mode == "wrong" && !tcp:
		opt = cookieOption([]byte("NOTYOURS"), serverCookie)
	case mode == "udp-drop" && !tcp && count > 3:
	case mode == "never" && count > 3:
	case mode == "badcookie" && !bytes.Equal(qm.cookie[8:], serverCookie):
		opt, rcode = cookieOption(cc, serverCookie), m.RcodeBadCookie
	default:
		opt = cookieOption(cc, serverCookie)
	}
	flags := msg.flags
	if rcode >= 0 {
		flags = flags&^0xF | uint16(rcode&0xF)
		msg.answer, msg.authority, msg.additional = nil, nil, nil
	}
	out := buildMessage(msg.id, flags, msg.qname, msg.qtype, msg.answer, msg.authority, msg.additional, true, false, opt)
	if rcode > 0xF {
		out[len(out)-len(opt)-6] = byte(rcode >> 4) // the upper bits, in the OPT record
	}
	return out, nil
}

func newCookieTest(t *testing.T, n *cookieNet, cookies bool) *Recursor {
	t.Helper()
	r := New(Config{RootHints: []netip.Addr{rootA}, Allow: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Cookies: cookies},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.send = n.send
	return r
}

// resolveAgain asks for name again from scratch, n times.
func resolveAgain(t *testing.T, r *Recursor, name string, times int) {
	t.Helper()
	for range times {
		r.ClearCache()
		if got := addrs(ask(t, r, name, m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
			t.Fatalf("%s: %v", name, got)
		}
	}
}

// Every question carries a client cookie made for its server; once a
// server has given its cookie, it goes back with every question.
func TestCookiesSent(t *testing.T) {
	n := newCookieNet(map[netip.Addr]string{exA: "echo", ex2A: "echo"})
	r := newCookieTest(t, n, true)
	resolveAgain(t, r, "www.example.com", 3)
	for _, a := range []netip.Addr{rootA, comA} {
		for i, c := range n.sent[a] {
			if len(c) != 8 { // these servers send no cookie back
				t.Fatalf("question %d to %s: cookie %x", i, a, c)
			}
		}
	}
	got := append(n.sent[exA], n.sent[ex2A]...)
	if len(got) < 2 || len(got[0]) != 8 || len(got[len(got)-1]) != 8+len(serverCookie) {
		t.Fatalf("cookies to example.com's servers: %x", got)
	}
	if !bytes.Equal(r.clientCookie(rootA), n.sent[rootA][0]) || bytes.Equal(r.clientCookie(rootA), r.clientCookie(comA)) {
		t.Fatal("client cookies are not per server")
	}
	if n.servers[exA].tcp.Load()+n.servers[ex2A].tcp.Load() != 0 {
		t.Fatal("TCP used with good cookies")
	}
	// off: no cookies at all
	n2 := newCookieNet(nil)
	r2 := newCookieTest(t, n2, false)
	resolveAgain(t, r2, "www.example.com", 1)
	for a, cs := range n2.sent {
		for _, c := range cs {
			if c != nil {
				t.Fatalf("cookie sent to %s with cookies off", a)
			}
		}
	}
}

// An answer with another client cookie is forged: the question goes again
// over TCP, and the right answer comes from there.
func TestCookieMismatchUsesTCP(t *testing.T) {
	n := newCookieNet(map[netip.Addr]string{exA: "wrong", ex2A: "wrong"})
	r := newCookieTest(t, n, true)
	resolveAgain(t, r, "www.example.com", 2)
	if r.Stats.CookieMismatch.Load() == 0 || n.servers[exA].tcp.Load()+n.servers[ex2A].tcp.Load() == 0 {
		t.Fatalf("mismatch %d, tcp %d", r.Stats.CookieMismatch.Load(), n.servers[exA].tcp.Load()+n.servers[ex2A].tcp.Load())
	}
}

// A server that always sent cookies answers over UDP without one: asked
// again over TCP, where its cookie is (so it keeps being insisted on).
func TestCookieMissingUsesTCP(t *testing.T) {
	n := newCookieNet(map[netip.Addr]string{exA: "udp-drop", ex2A: "udp-drop"})
	r := newCookieTest(t, n, true)
	resolveAgain(t, r, "www.example.com", 8)
	if r.Stats.CookieMissing.Load() < 2 {
		t.Fatalf("missing cookies noticed %d times, want every time after the third", r.Stats.CookieMissing.Load())
	}
}

// A server that answers without a cookie over TCP as well does not do
// cookies everywhere (anycast): after one TCP check, it is not insisted on.
func TestCookieInconsistentServerTolerated(t *testing.T) {
	n := newCookieNet(map[netip.Addr]string{exA: "never", ex2A: "never"})
	r := newCookieTest(t, n, true)
	resolveAgain(t, r, "www.example.com", 10)
	tcp := n.servers[exA].tcp.Load() + n.servers[ex2A].tcp.Load()
	if tcp == 0 || tcp > 2 {
		t.Fatalf("%d TCP questions: want one check per server, then none", tcp)
	}
}

// BADCOOKIE: the server wants its cookie; the question goes again once,
// with it, over UDP.
func TestBadCookieRetried(t *testing.T) {
	n := newCookieNet(map[netip.Addr]string{exA: "badcookie", ex2A: "badcookie"})
	r := newCookieTest(t, n, true)
	resolveAgain(t, r, "www.example.com", 2)
	if n.servers[exA].tcp.Load()+n.servers[ex2A].tcp.Load() != 0 {
		t.Fatal("TCP used after BADCOOKIE")
	}
}

// A server that cannot take the option gets questions without it.
func TestCookieFormErrServer(t *testing.T) {
	n := newCookieNet(map[netip.Addr]string{exA: "formerr", ex2A: "formerr"})
	r := newCookieTest(t, n, true)
	resolveAgain(t, r, "www.example.com", 3)
	for _, a := range []netip.Addr{exA, ex2A} {
		s := n.sent[a]
		if len(s) > 0 && s[len(s)-1] != nil {
			t.Fatalf("%s still gets cookies after FORMERR: %x", a, s)
		}
	}
}
