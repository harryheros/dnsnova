package server

import (
	"net"
	"runtime"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// UDP in batches: on Linux, recvmmsg and sendmmsg move many datagrams per
// system call. Answering from the cache takes about a microsecond; the
// system calls around it took most of the time (one to read, one to send
// for every query), so a busy server reads what has arrived in one call
// and sends the answers it could give at once in one call. A quiet server
// gets one query per call, as before; nothing waits for a batch to fill.

// udpBatch is how many datagrams one call moves at most.
const udpBatch = 32

// udpSlot is the receive buffer per datagram. A query has no reason to be
// larger (with a PROXY header in front, a few hundred bytes more); a longer
// one arrives truncated and is dropped.
const udpSlot = 4096

// batchConn is ipv4.PacketConn or ipv6.PacketConn: both move
// ipv4.Message (the same type as ipv6.Message).
type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

// newBatchConn returns c for batched reads and writes, or nil where the
// system has no such calls (then serveUDP reads one datagram at a time).
func newBatchConn(c *net.UDPConn) batchConn {
	if runtime.GOOS != "linux" {
		return nil
	}
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok && a.IP.To4() != nil {
		return ipv4.NewPacketConn(c)
	}
	return ipv6.NewPacketConn(c)
}

// msgTrunc is MSG_TRUNC on Linux: the datagram was longer than the slot.
const msgTrunc = 0x20

func (s *Server) serveUDPBatch(l *udpListener, conn *net.UDPConn, bc batchConn) {
	in := make([]ipv4.Message, udpBatch)
	mem := make([]byte, udpBatch*udpSlot)
	for i := range in {
		in[i].Buffers = [][]byte{mem[i*udpSlot : (i+1)*udpSlot : (i+1)*udpSlot]}
	}
	out := make([]ipv4.Message, 0, udpBatch)
	outBufs := make([][1][]byte, udpBatch)
	for {
		n, err := bc.ReadBatch(in, 0)
		if err != nil {
			if isClosed(err) {
				return
			}
			continue
		}
		out = out[:0]
		for i := range in[:n] {
			msg := &in[i]
			ua, ok := msg.Addr.(*net.UDPAddr)
			if !ok || msg.Flags&msgTrunc != 0 {
				continue
			}
			addr := ua.AddrPort()
			if resp := s.udpPacket(l, conn, msg.Buffers[0][:msg.N], addr); resp != nil {
				k := len(out)
				outBufs[k][0] = resp
				out = append(out, ipv4.Message{Buffers: outBufs[k][:], Addr: msg.Addr})
			}
		}
		sendBatch(bc, conn, out)
		for k := range out { // let the answers be collected
			outBufs[k][0] = nil
		}
	}
}

// sendBatch sends every message in out. A message the kernel refuses (an
// unreachable address, say) is skipped rather than retried.
func sendBatch(bc batchConn, conn *net.UDPConn, out []ipv4.Message) {
	for len(out) > 0 {
		n, err := bc.WriteBatch(out, 0)
		if err != nil || n == 0 {
			if isClosed(err) {
				return
			}
			// the first message failed: send it alone (for its error) and go on
			if ua, ok := out[0].Addr.(*net.UDPAddr); ok {
				conn.WriteToUDPAddrPort(out[0].Buffers[0], ua.AddrPort())
			}
			n = 1
		}
		out = out[n:]
	}
}
