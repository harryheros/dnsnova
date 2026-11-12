package proxyproto

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// v2 builds a version 2 header.
func v2(cmd, fam byte, src, dst netip.AddrPort, tlv []byte) []byte {
	var body []byte
	if src.Addr().Is4() {
		a, b := src.Addr().As4(), dst.Addr().As4()
		body = append(append(body, a[:]...), b[:]...)
	} else if src.IsValid() {
		a, b := src.Addr().As16(), dst.Addr().As16()
		body = append(append(body, a[:]...), b[:]...)
	}
	if src.IsValid() {
		body = binary.BigEndian.AppendUint16(body, src.Port())
		body = binary.BigEndian.AppendUint16(body, dst.Port())
	}
	body = append(body, tlv...)
	out := append(bytes.Clone(sigV2), 0x20|cmd, fam)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

var (
	src4 = netip.MustParseAddrPort("198.51.100.7:40000")
	dst4 = netip.MustParseAddrPort("203.0.113.10:53")
	src6 = netip.MustParseAddrPort("[2001:db8::7]:40000")
	dst6 = netip.MustParseAddrPort("[2001:db8::53]:853")
)

func TestV2(t *testing.T) {
	tlv := []byte{0x04, 0, 2, 'h', 'i'} // a NOOP TLV, ignored
	for _, c := range []struct {
		name string
		b    []byte
		want Header
	}{
		{"udp4", v2(1, 0x12, src4, dst4, nil), Header{Source: src4, Dest: dst4}},
		{"tcp4 with TLV", v2(1, 0x11, src4, dst4, tlv), Header{Source: src4, Dest: dst4}},
		{"udp6", v2(1, 0x22, src6, dst6, nil), Header{Source: src6, Dest: dst6}},
		{"local", v2(0, 0x00, netip.AddrPort{}, netip.AddrPort{}, nil), Header{Local: true}},
		{"proxy, unspec", v2(1, 0x00, netip.AddrPort{}, netip.AddrPort{}, nil), Header{Local: true}},
	} {
		pkt := append(c.b, "DNS"...)
		h, n, err := ParseV2(pkt)
		if err != nil || h != c.want || string(pkt[n:]) != "DNS" {
			t.Errorf("%s: %+v %d %v", c.name, h, n, err)
		}
		h, err = Read(bytes.NewReader(c.b))
		if err != nil || h != c.want {
			t.Errorf("%s (stream): %+v %v", c.name, h, err)
		}
	}
	good := v2(1, 0x12, src4, dst4, nil)
	for name, b := range map[string][]byte{
		"short":         good[:20],
		"bad signature": append([]byte("\r\n\r\n\x00\r\nQUIX\n"), good[12:]...),
		"version 1":     append(append(bytes.Clone(good[:12]), 0x11), good[13:]...),
		"command 2":     append(append(bytes.Clone(good[:12]), 0x22), good[13:]...),
		"unix":          append(append(bytes.Clone(good[:13]), 0x31), good[14:]...),
		"proto 3":       append(append(bytes.Clone(good[:13]), 0x13), good[14:]...),
		"too long":      append(append(bytes.Clone(good[:14]), 0xff, 0xff), make([]byte, 70000)...),
		"inet6 cut":     v2(1, 0x22, src4, dst4, nil),
		"empty":         nil,
	} {
		if _, _, err := ParseV2(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := Read(bytes.NewReader(b)); err == nil {
			t.Errorf("%s (stream): accepted", name)
		}
	}
}

func TestV1(t *testing.T) {
	for line, want := range map[string]Header{
		"PROXY TCP4 198.51.100.7 203.0.113.10 40000 53\r\n": {Source: src4, Dest: dst4},
		"PROXY TCP6 2001:db8::7 2001:db8::53 40000 853\r\n": {Source: src6, Dest: dst6},
		"PROXY UNKNOWN\r\n": {Local: true},
		"PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 1 2\r\n": {Local: true},
	} {
		r := strings.NewReader(line + "rest")
		h, err := Read(r)
		rest, _ := io.ReadAll(r)
		if err != nil || h != want || string(rest) != "rest" {
			t.Errorf("%q: %+v %v, rest %q", line, h, err, rest)
		}
	}
	for _, line := range []string{
		"PROXY TCP4 198.51.100.7 203.0.113.10 40000 53\n",    // no CR
		"PROXY TCP4 2001:db8::7 203.0.113.10 40000 53\r\n",   // family mismatch
		"PROXY TCP6 198.51.100.7 203.0.113.10 40000 53\r\n",  // family mismatch
		"PROXY TCP4 198.51.100.7 203.0.113.10 040000 53\r\n", // leading zero
		"PROXY TCP4 198.51.100.7 203.0.113.10 70000 53\r\n",  // port range
		"PROXY TCP4 198.51.100.7 203.0.113.10 -1 53\r\n",
		"PROXY UDP4 198.51.100.7 203.0.113.10 40000 53\r\n",
		"PROXY TCP4 198.51.100.7  203.0.113.10 40000 53\r\n",
		"PROXY TCP4 198.51.100.7 203.0.113.10 40000\r\n",
		"PROXY " + strings.Repeat("x", 200) + "\r\n",
		"GET / HTTP/1.1\r\n",
		"\x00\x1c\x12\x34", // a DNS-over-TCP query without header
	} {
		if h, err := Read(strings.NewReader(line)); err == nil {
			t.Errorf("%q accepted: %+v", line, h)
		}
	}
}

func listen(t *testing.T, trusted bool) (*Listener, chan netip.Addr) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewListener(ln, func(netip.Addr) bool { return trusted })
	t.Cleanup(func() { l.Close() })
	got := make(chan netip.Addr, 10)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
			b := make([]byte, 4)
			io.ReadFull(c, b)
			if string(b) == "data" {
				got <- ap.Addr()
			}
			c.Close()
		}
	}()
	return l, got
}

func dial(t *testing.T, l *Listener, b []byte) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Write(b)
	return c
}

func want(t *testing.T, got chan netip.Addr, addr string) {
	t.Helper()
	select {
	case a := <-got:
		if a.String() != addr {
			t.Fatalf("remote %s, want %s", a, addr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("no connection for %s", addr)
	}
}

func TestListener(t *testing.T) {
	l, got := listen(t, true)
	// a trusted proxy that sends nothing yet holds up no one else
	slow := dial(t, l, nil)
	dial(t, l, append(v2(1, 0x11, src4, dst4, nil), "data"...))
	want(t, got, "198.51.100.7")
	dial(t, l, []byte("PROXY TCP6 2001:db8::7 2001:db8::53 40000 853\r\ndata"))
	want(t, got, "2001:db8::7")
	dial(t, l, append(v2(0, 0, netip.AddrPort{}, netip.AddrPort{}, nil), "data"...))
	want(t, got, "127.0.0.1") // LOCAL: the proxy's own address
	// no header from a trusted proxy: closed
	c := dial(t, l, []byte("\x00\x1c\x12\x34data"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection without header still open")
	}
	slow.Close()

	// untrusted: no header is read, a header is just data
	l2, got2 := listen(t, false)
	dial(t, l2, []byte("data"))
	want(t, got2, "127.0.0.1")
	dial(t, l2, append([]byte("PROXY TCP4 198.51.100.7 203.0.113.10 40000 53\r\n"), "data"...))
	select {
	case a := <-got2:
		t.Fatalf("untrusted header believed: %s", a)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestListenerClose(t *testing.T) {
	l, _ := listen(t, true)
	l.Close()
	l.Close()
	if _, err := l.Accept(); err == nil {
		t.Fatal("Accept after Close")
	}
}

// Any datagram: ParseV2 and the stream reader agree, a header never claims
// more bytes than it has, and every accepted address is usable.
func FuzzParseV2(f *testing.F) {
	f.Add(v2(1, 0x12, src4, dst4, nil))
	f.Add(v2(1, 0x22, src6, dst6, []byte{4, 0, 1, 0}))
	f.Add(v2(0, 0, netip.AddrPort{}, netip.AddrPort{}, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, n, err := ParseV2(b)
		hs, errs := Read(bytes.NewReader(b))
		if (err == nil) != (errs == nil) || (err == nil && h != hs) {
			t.Fatalf("datagram %+v %v, stream %+v %v", h, err, hs, errs)
		}
		if err != nil {
			return
		}
		if n < v2Fixed || n > len(b) {
			t.Fatalf("length %d of %d", n, len(b))
		}
		if !h.Local && (!h.Source.Addr().IsValid() || !h.Dest.Addr().IsValid() || h.Source.Addr().Is4In6()) {
			t.Fatalf("unusable address: %+v", h)
		}
	})
}

// Any stream start: what is accepted as version 1 is read exactly to its
// line end, and nothing more.
func FuzzReadV1(f *testing.F) {
	f.Add("PROXY TCP4 198.51.100.7 203.0.113.10 40000 53\r\n")
	f.Add("PROXY TCP6 2001:db8::7 2001:db8::53 40000 853\r\n")
	f.Add("PROXY UNKNOWN\r\n")
	f.Fuzz(func(t *testing.T, s string) {
		r := strings.NewReader(s + "\x00TAIL")
		h, err := Read(r)
		if err != nil {
			return
		}
		rest, _ := io.ReadAll(r)
		if !bytes.HasSuffix(rest, []byte("\x00TAIL")) {
			t.Fatalf("read past the header: rest %q", rest)
		}
		if strings.HasPrefix(s, "PROXY ") && !h.Local && (h.Source.Addr().Is4() != h.Dest.Addr().Is4()) {
			t.Fatalf("mixed families: %+v", h)
		}
	})
}
