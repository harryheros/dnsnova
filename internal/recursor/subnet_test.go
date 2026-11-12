package recursor

import (
	"bytes"
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// geoNet answers www.example.com differently to questions that carry the
// client subnet cnNet, as a GeoDNS name server does, and records which
// questions to example.com's servers carried it.
type geoNet struct {
	*fakeNet
	mu       sync.Mutex
	withECS  int
	asked    int
	ecsTypes []uint16
}

var cnNet = netip.MustParsePrefix("203.0.113.0/24")

func (n *geoNet) send(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
	resp, err := n.fakeNet.send(ctx, addr, q, tcp)
	a := addr.Addr()
	if err != nil || (a != exA && a != ex2A) {
		return resp, err
	}
	qm, _ := parseMessage(q)
	hasECS := bytes.Contains(q, m.ClientSubnet(cnNet))
	n.mu.Lock()
	n.asked++
	if hasECS {
		n.withECS++
		n.ecsTypes = append(n.ecsTypes, qm.qtype)
	}
	n.mu.Unlock()
	if !hasECS {
		return resp, nil
	}
	msg, err := parseMessage(resp)
	if err != nil {
		return resp, nil
	}
	for i := range msg.answer {
		if msg.answer[i].typ == m.TypeA {
			msg.answer[i].data = []byte{192, 0, 2, 99} // the answer for that network
		}
	}
	return buildMessage(msg.id, msg.flags, msg.qname, msg.qtype, msg.answer, msg.authority, msg.additional, true, false, nil), nil
}

func askSubnet(t *testing.T, r *Recursor, name string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q := buildQuery(78, dotted(name), m.TypeA, true, nil)
	q[2] |= 1
	resp, err := r.ExchangeSubnet(ctx, q, m.ClientSubnet(cnNet))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	msg, err := parseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	return addrs(msg)
}

// ExchangeSubnet asks name servers for the client's network, and its
// answers never reach other clients through the cache, in either direction.
func TestExchangeSubnet(t *testing.T) {
	n := &geoNet{fakeNet: world()}
	r := newTest(t, n.fakeNet, false)
	r.send = n.send

	if got := addrs(ask(t, r, "www.example.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("ordinary answer: %v", got)
	}
	before := n.asked
	if got := askSubnet(t, r, "www.example.com"); len(got) != 1 || got[0] != "192.0.2.99" {
		t.Fatalf("answer for the network: %v (the ordinary one was cached and used?)", got)
	}
	if n.asked == before || n.withECS == 0 {
		t.Fatal("the name server was not asked with the client subnet")
	}
	for _, typ := range n.ecsTypes {
		if typ != m.TypeA {
			t.Fatalf("client subnet sent with a %s question", m.TypeString(typ))
		}
	}
	// the network's answer did not go into the cache
	if got := addrs(ask(t, r, "www.example.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("ordinary answer after a subnet lookup: %v", got)
	}
	// and every subnet lookup asks again, while the delegation is reused
	asked := n.asked
	askSubnet(t, r, "www.example.com")
	if n.asked != asked+1 {
		t.Fatalf("%d questions for a repeated subnet lookup, want 1 (to example.com's server only)", n.asked-asked)
	}
	// starting with an empty cache: the subnet answer stays out of it
	r.ClearCache()
	askSubnet(t, r, "www.example.com")
	if got := addrs(ask(t, r, "www.example.com", m.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Fatalf("ordinary answer after a first subnet lookup: %v", got)
	}
}
