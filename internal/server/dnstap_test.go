package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/dnstap"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// TestDnstap: an answered query reaches a collector on a Unix socket.
func TestDnstap(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "tap.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	frames := make(chan []byte, 10)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		control := func() {
			var h [8]byte
			io.ReadFull(c, h[:])
			io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(h[4:])))
		}
		control() // READY
		ct := dnstap.ContentType
		accept := binary.BigEndian.AppendUint32(nil, 0)
		accept = binary.BigEndian.AppendUint32(accept, uint32(12+len(ct)))
		accept = binary.BigEndian.AppendUint32(accept, 1)
		accept = binary.BigEndian.AppendUint32(accept, 1)
		accept = binary.BigEndian.AppendUint32(accept, uint32(len(ct)))
		c.Write(append(accept, ct...))
		control() // START
		for {
			var n [4]byte
			if _, err := io.ReadFull(c, n[:]); err != nil || binary.BigEndian.Uint32(n[:]) == 0 {
				return
			}
			b := make([]byte, binary.BigEndian.Uint32(n[:]))
			io.ReadFull(c, b)
			frames <- b
		}
	}()
	s, _, _ := start(t, fmt.Sprintf("\n[dnstap]\ntarget = %q\nqueries = false\n", "unix:"+sock))
	for deadline := time.Now().Add(5 * time.Second); !s.Tap.State().Connected; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not connected: %+v", s.Tap.State())
		}
	}
	udp, _, _, _ := s.Addrs()
	if _, err := udpAsk(t, udp[0], dnstest.Query(1, "tapped.test", 1, false, false), 2*time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-frames:
		if !bytes.Contains(f, []byte("\x06tapped\x04test")) || !bytes.Contains(f, []byte{127, 0, 0, 0}) {
			t.Fatalf("frame without the name or the shortened address: % x", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no dnstap frame")
	}
	if info := s.PublicStatus(); !info.QueryExport {
		t.Fatal("the status page does not say queries are sent on")
	}
}
