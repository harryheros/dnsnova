package server

import (
	"net"
	"testing"
)

// TestFreeAddrBothProtocols: the addresses freeAddr hands out are used for
// plain DNS, which binds UDP and TCP on the same port. With many UDP ports
// taken by other tests running at the same time (the recursor's socket pool
// alone opens hundreds), a port that is only free for TCP failed tests at
// random with "address already in use".
func TestFreeAddrBothProtocols(t *testing.T) {
	var held []net.PacketConn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for range 2000 {
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			break
		}
		held = append(held, c)
	}
	for range 200 {
		a := freeAddr(t)
		u, err := net.ListenPacket("udp", a)
		if err != nil {
			t.Fatalf("%s is not free for UDP: %v", a, err)
		}
		l, err := net.Listen("tcp", a)
		u.Close()
		if err != nil {
			t.Fatalf("%s is not free for TCP: %v", a, err)
		}
		l.Close()
	}
}
