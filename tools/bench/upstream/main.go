// Command upstream is a stand-in upstream resolver for benchmarks. It
// answers every query at once (or after -delay): A and AAAA with one
// address, names starting with "x" with NXDOMAIN. With an upstream that
// costs nothing, a benchmark measures the DNS server itself.
package main

import (
	"flag"
	"log"
	"net"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5301", "address to answer on")
	delay := flag.Duration("delay", 0, "wait this long before answering")
	flag.Parse()
	c, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		buf := make([]byte, 1500)
		n, a, err := c.ReadFrom(buf)
		if err != nil || n < 12 {
			continue
		}
		if *delay == 0 {
			reply(c, buf[:n], a)
		} else {
			go func() { time.Sleep(*delay); reply(c, buf[:n], a) }()
		}
	}
}

func reply(c net.PacketConn, q []byte, a net.Addr) {
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	end := i + 5 // the root label, type and class
	if end > len(q) {
		return
	}
	// header: same ID, a response with RD and RA, one question, one answer
	r := append([]byte{q[0], q[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, q[12:end]...)
	switch {
	case q[13] == 'x':
		r[3], r[7] = 0x83, 0 // NXDOMAIN, no answer
	case q[i+2] == 28: // AAAA 2001:db8::1, TTL 3600
		r = append(r, 0xC0, 12, 0, 28, 0, 1, 0, 0, 14, 16, 0, 16, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	default: // A 192.0.2.1, TTL 3600
		r = append(r, 0xC0, 12, 0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 192, 0, 2, 1)
	}
	c.WriteTo(r, a)
}
