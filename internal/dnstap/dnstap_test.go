package dnstap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

// collector accepts Frame Streams connections as fstrm readers do and
// hands over the decoded Dnstap messages.
type collector struct {
	ln   net.Listener
	msgs chan map[uint64][]any
	ct   chan string // content type of each READY
}

func listen(t *testing.T, network string) *collector {
	t.Helper()
	addr := "127.0.0.1:0"
	if network == "unix" {
		addr = filepath.Join(t.TempDir(), "dnstap.sock")
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{ln: ln, msgs: make(chan map[uint64][]any, 100), ct: make(chan string, 10)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.serve(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *collector) target() string {
	return c.ln.Addr().Network() + ":" + c.ln.Addr().String()
}

func (c *collector) serve(conn net.Conn) {
	defer conn.Close()
	typ, ct, err := readControl(conn)
	if err != nil || typ != ctrlReady {
		return
	}
	c.ct <- ct
	writeControl(conn, ctrlAccept, ContentType)
	if typ, _, err := readControl(conn); err != nil || typ != ctrlStart {
		return
	}
	for {
		var n [4]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return
		}
		l := binary.BigEndian.Uint32(n[:])
		if l == 0 { // a control frame: STOP
			readRest(conn)
			writeControl(conn, ctrlFinish, "")
			return
		}
		b := make([]byte, l)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		c.msgs <- decode(b)
	}
}

func readRest(r io.Reader) {
	var n [4]byte
	io.ReadFull(r, n[:])
	io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint32(n[:])))
}

// decode reads a protobuf message into field -> values (uint64 or []byte;
// field 14 of a Dnstap is decoded as a nested message).
func decode(b []byte) map[uint64][]any {
	out := map[uint64][]any{}
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		b = b[n:]
		field, wire := key>>3, key&7
		switch wire {
		case 0:
			v, n := binary.Uvarint(b)
			b = b[n:]
			out[field] = append(out[field], v)
		case 2:
			l, n := binary.Uvarint(b)
			b = b[n:]
			out[field] = append(out[field], b[:l])
			b = b[l:]
		case 5:
			out[field] = append(out[field], uint64(binary.LittleEndian.Uint32(b)))
			b = b[4:]
		default:
			return out
		}
	}
	return out
}

func (c *collector) next(t *testing.T) (top, msg map[uint64][]any) {
	t.Helper()
	select {
	case top = <-c.msgs:
		return top, decode(top[14][0].([]byte))
	case <-time.After(5 * time.Second):
		t.Fatal("no dnstap message arrived")
	}
	return nil, nil
}

func run(t *testing.T, s *Sender) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

var (
	query    = []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 0, 0, 1, 0, 1}
	response = []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 0, 0, 1, 0, 1}
	t0       = time.Unix(1_800_000_000, 123_000_000)
)

func event(proto, client string) Event {
	return Event{Proto: proto, Client: netip.MustParseAddrPort(client), Query: query, Response: response, Start: t0, End: t0.Add(2 * time.Millisecond)}
}

func TestQueriesAndResponses(t *testing.T) {
	for _, network := range []string{"unix", "tcp"} {
		t.Run(network, func(t *testing.T) {
			c := listen(t, network)
			s := New()
			s.Configure(Settings{Target: c.target(), Queries: true, Responses: true, FullIP: true, Identity: "fra-1", Version: "DNSNova 1.6.0"})
			run(t, s)
			if ct := <-c.ct; ct != ContentType {
				t.Fatalf("content type %q", ct)
			}
			waitConnected(t, s)
			s.Add(event("dot", "192.0.2.10:5353"))

			top, q := c.next(t)
			if string(top[1][0].([]byte)) != "fra-1" || string(top[2][0].([]byte)) != "DNSNova 1.6.0" || top[15][0] != uint64(1) {
				t.Fatalf("Dnstap: %v", top)
			}
			if q[1][0] != uint64(msgClientQuery) || q[2][0] != uint64(1) || q[3][0] != uint64(3) ||
				!bytes.Equal(q[4][0].([]byte), []byte{192, 0, 2, 10}) || q[6][0] != uint64(5353) ||
				q[8][0] != uint64(t0.Unix()) || q[9][0] != uint64(123_000_000) || !bytes.Equal(q[10][0].([]byte), query) || q[14] != nil {
				t.Fatalf("CLIENT_QUERY: %v", q)
			}
			_, r := c.next(t)
			if r[1][0] != uint64(msgClientResponse) || !bytes.Equal(r[14][0].([]byte), response) || r[13][0] != uint64(125_000_000) {
				t.Fatalf("CLIENT_RESPONSE: %v", r)
			}
		})
	}
}

func TestShortenedAddressesAndChoices(t *testing.T) {
	c := listen(t, "unix")
	s := New()
	s.Configure(Settings{Target: c.target(), Responses: true})
	run(t, s)
	waitConnected(t, s)
	s.Add(event("doh3", "[2001:db8:1:2::77]:443"))
	_, r := c.next(t)
	if r[1][0] != uint64(msgClientResponse) || r[2][0] != uint64(2) || r[3][0] != uint64(4) || r[16][0] != uint64(3) {
		t.Fatalf("message: %v", r)
	}
	if got, _ := netip.AddrFromSlice(r[4][0].([]byte)); got != netip.MustParseAddr("2001:db8:1::") || r[6] != nil {
		t.Fatalf("address not shortened (or port sent): %v %v", got, r[6])
	}
	select {
	case m := <-c.msgs:
		t.Fatalf("a query was sent with queries off: %v", decode(m[14][0].([]byte)))
	case <-time.After(200 * time.Millisecond):
	}
}

func TestCollectorDownNeverBlocks(t *testing.T) {
	s := New()
	s.Configure(Settings{Target: "unix:" + filepath.Join(t.TempDir(), "none.sock"), Queries: true, Responses: true})
	run(t, s)
	start := time.Now()
	for i := 0; i < queueSize; i++ {
		s.Add(event("udp", "192.0.2.1:53"))
	}
	if time.Since(start) > 2*time.Second || s.State().Dropped == 0 {
		t.Fatalf("dropped %d in %v", s.State().Dropped, time.Since(start))
	}
	waitFor(t, func() bool { return s.State().Errors > 0 && s.State().LastError != "" })
}

func TestReconnects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnstap.sock")
	s := New()
	s.Configure(Settings{Target: "unix:" + path, Responses: true})
	run(t, s)
	waitFor(t, func() bool { return s.State().Errors > 0 })

	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{ln: ln, msgs: make(chan map[uint64][]any, 10), ct: make(chan string, 10)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.serve(conn)
		}
	}()
	defer ln.Close()
	s.Configure(Settings{Target: "unix:" + path, Responses: true}) // as a reload would: retry now
	waitConnected(t, s)
	s.Add(event("udp", "192.0.2.1:53"))
	c.next(t)
}

func TestTurnedOff(t *testing.T) {
	c := listen(t, "unix")
	s := New()
	s.Configure(Settings{Target: c.target(), Responses: true})
	run(t, s)
	waitConnected(t, s)
	s.Configure(Settings{})
	waitFor(t, func() bool { return !s.State().Connected })
	s.Add(event("udp", "192.0.2.1:53"))
	if s.On() || s.State().Dropped != 0 {
		t.Fatal("still sending while off")
	}
}

func TestParseTarget(t *testing.T) {
	for _, ok := range []string{"unix:/run/dnstap.sock", "tcp:10.0.0.5:6000", "tcp:[2001:db8::5]:6000", "tcp:collector.example:6000"} {
		if _, _, err := ParseTarget(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/run/dnstap.sock", "unix:relative.sock", "tcp:10.0.0.5", "udp:10.0.0.5:6000", "tcp:"} {
		if _, _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestReadControlRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{
		{0, 0, 0, 1, 0, 0, 0, 4},    // a data frame, not control
		{0, 0, 0, 0, 0, 0, 0x10, 0}, // too long
		{0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0xff}, // field longer than the frame
	} {
		if _, _, err := readControl(bytes.NewReader(b)); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
}

func waitConnected(t *testing.T, s *Sender) {
	t.Helper()
	waitFor(t, func() bool { return s.State().Connected })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var _ = errors.New
