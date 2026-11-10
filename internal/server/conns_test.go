package server

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestDoHConnectionsLimited: DoH connections count toward
// limits.tcp_connections like TCP and DoT ones. They were not counted at
// all, so DoH could open connections until the server ran out of file
// descriptors, which stops every other service too.
func TestDoHConnectionsLimited(t *testing.T) {
	q := startQUIC(t, "tcp_connections = 1\n")
	_, h3 := q.QUICEndpoints()
	addr := h3[0] // HTTPS listens on the same port over TCP
	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	deadline := time.Now().Add(2 * time.Second)
	for q.tcpConns.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("DoH connection not counted: %d", q.tcpConns.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("a DoH connection over limits.tcp_connections was kept open: %v", err)
	}
	first.Close()
	for q.tcpConns.Load() != 0 {
		if time.Now().After(deadline.Add(3 * time.Second)) {
			t.Fatalf("closed DoH connection still counted: %d", q.tcpConns.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// TestClientConnectionsLimited: one address (an IPv6 /56 counts as one)
// cannot open more than limits.client_connections, other addresses still
// can, and a closed connection frees its place. Behind a proxy, where every
// connection comes from the proxy, only the total counts.
func TestClientConnectionsLimited(t *testing.T) {
	q := startQUIC(t, "client_connections = 2\n")
	a := netip.MustParseAddr("198.51.100.7")
	v6a, v6b := netip.MustParseAddr("2001:db8:1:ff::1"), netip.MustParseAddr("2001:db8:1:ff:ffff::2") // same /56
	var dones []func()
	admit := func(ip netip.Addr, direct bool) bool {
		done, ok := q.admitTCP(ip, direct, direct)
		if ok {
			dones = append(dones, done)
		}
		return ok
	}
	if !admit(a, true) || !admit(a, true) {
		t.Fatal("refused within the limit")
	}
	if admit(a, true) {
		t.Fatal("third connection from one address accepted")
	}
	if !admit(netip.MustParseAddr("198.51.100.8"), true) {
		t.Fatal("another address refused")
	}
	if !admit(v6a, true) || !admit(v6b, true) || admit(v6a, true) {
		t.Fatal("an IPv6 /56 is not counted as one client")
	}
	if !admit(a, false) {
		t.Fatal("behind a proxy, the proxy's address was limited")
	}
	dones[0]()
	dones[0]() // closing twice frees one place only
	if !admit(a, true) {
		t.Fatal("a closed connection did not free its place")
	}
	if admit(a, true) {
		t.Fatal("closing twice freed two places")
	}
	if !admit(netip.MustParseAddr("127.0.0.1"), true) || !admit(netip.MustParseAddr("127.0.0.1"), true) || !admit(netip.MustParseAddr("127.0.0.1"), true) {
		t.Fatal("the machine itself was limited")
	}
	for _, d := range dones {
		d()
	}
	if n := q.tcpConns.Load(); n != 0 {
		t.Fatalf("%d connections still counted", n)
	}
}

// TestQUICRetryForBusyAddress: an address with half its connections open
// must prove it is real (QUIC Retry) before it may open more, so that
// packets with a forged source cannot use up a real client's share.
func TestQUICRetryForBusyAddress(t *testing.T) {
	q := startQUIC(t, "client_connections = 4\n")
	ip := netip.MustParseAddr("198.51.100.9")
	ua := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 4444))
	if q.quicVerifySource(ua) {
		t.Fatal("Retry for an idle address on an idle server")
	}
	q.clientConns.acquire(ip, 4)
	q.clientConns.acquire(ip, 4)
	if !q.quicVerifySource(ua) {
		t.Fatal("no Retry for an address with half its connections open")
	}
}

// TestDoHAdmitsCertificateChecks: in private mode a DoH connection from
// outside the access list is still accepted (the handler refuses its
// queries), because Let's Encrypt checks the domain on the same port.
func TestDoHAdmitsCertificateChecks(t *testing.T) {
	q := startQUIC(t, "\n[access]\nallow = [\"203.0.113.0/24\"]\n")
	q.edit(t, `mode = "public"`, `mode = "private"`)
	_, h3 := q.QUICEndpoints()
	c, err := net.Dial("tcp", h3[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for q.tcpConns.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("connection from outside the access list closed before TLS")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
