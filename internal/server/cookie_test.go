package server

import (
	"bytes"
	"encoding/binary"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/stats"
)

// cookieQuery is an EDNS query carrying a COOKIE option with data.
func cookieQuery(id uint16, name string, qtype uint16, data []byte) []byte {
	q := dnstest.Query(id, name, qtype, true, false)
	opt := binary.BigEndian.AppendUint16(nil, m.OptCookie)
	opt = binary.BigEndian.AppendUint16(opt, uint16(len(data)))
	return m.AddOptions(q, append(opt, data...))
}

// respCookie returns the COOKIE option data and the full (extended) rcode
// of a response.
func respCookie(t *testing.T, b []byte) (data []byte, rcode int) {
	t.Helper()
	r := dnstest.Parse(t, b)
	rcode = r.Rcode
	off := m.HeaderLen
	if m.U16(b, 4) == 1 {
		end, _ := m.SkipName(b, off)
		off = end + 4
	}
	m.WalkRRs(b, off, r.AN+r.NS+r.AR, func(rr m.RR) error {
		if rr.Type != m.TypeOPT {
			return nil
		}
		rcode |= int(b[rr.TTLOff]) << 4
		rd := b[rr.RDOff:rr.End]
		for i := 0; i+4 <= len(rd); {
			code, n := m.U16(rd, i), int(m.U16(rd, i+2))
			if code == m.OptCookie {
				data = rd[i+4 : i+4+n]
			}
			i += 4 + n
		}
		return nil
	})
	return data, rcode
}

func TestCookiesUDP(t *testing.T) {
	s, _, _ := start(t, "")
	udp, _, _, _ := s.Addrs()
	ask := func(q []byte) []byte {
		t.Helper()
		resp, err := udpAsk(t, udp[0], q, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	cc := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// first contact: the client cookie comes back with a server cookie
	got, rc := respCookie(t, ask(cookieQuery(1, "c.test", m.TypeA, cc)))
	if rc != m.RcodeNoError || len(got) != 24 || !bytes.Equal(got[:8], cc) {
		t.Fatalf("first answer: rcode %d, cookie %x", rc, got)
	}
	// sent back: recognised as valid, and a fresh one is returned
	got2, rc := respCookie(t, ask(cookieQuery(2, "c.test", m.TypeA, got)))
	if rc != m.RcodeNoError || len(got2) != 24 || !bytes.Equal(got2[:8], cc) {
		t.Fatalf("second answer: rcode %d, cookie %x", rc, got2)
	}
	// a server cookie from elsewhere: answered normally, with ours
	foreign := append(bytes.Clone(cc), bytes.Repeat([]byte{9}, 16)...)
	got3, rc := respCookie(t, ask(cookieQuery(3, "c.test", m.TypeA, foreign)))
	if rc != m.RcodeNoError || len(got3) != 24 || bytes.Equal(got3[8:], foreign[8:]) {
		t.Fatalf("foreign server cookie: rcode %d, cookie %x", rc, got3)
	}
	if n := [3]uint64{s.Stats.Cookies[stats.CookieClientOnly].Load(), s.Stats.Cookies[stats.CookieBad].Load(), s.Stats.Cookies[stats.CookieGood].Load()}; n != [3]uint64{1, 1, 1} {
		t.Fatalf("cookie counts (client only, bad, good) = %v, want 1 each", n)
	}
	// a malformed cookie is FORMERR (RFC 7873 5.2.2)
	for _, n := range []int{5, 9, 15, 41} {
		if r := dnstest.Parse(t, ask(cookieQuery(4, "c.test", m.TypeA, make([]byte, n)))); r.Rcode != m.RcodeFormErr {
			t.Errorf("%d-byte cookie: rcode %d, want FORMERR", n, r.Rcode)
		}
	}
	// no cookie, no COOKIE option
	if got, _ := respCookie(t, ask(dnstest.Query(5, "c.test", m.TypeA, true, false))); got != nil {
		t.Fatalf("COOKIE without one asked: %x", got)
	}
	// a truncated answer still carries it, so the TCP retry can use it
	tr := ask(cookieQuery(6, "huge.test", 16, cc))
	if got, _ := respCookie(t, tr); !dnstest.Parse(t, tr).TC() || len(got) != 24 {
		t.Fatalf("truncated answer: TC %v, cookie %x", dnstest.Parse(t, tr).TC(), got)
	}
	// error answers too (REFUSED: no recursion asked)
	norec := cookieQuery(7, "c.test", m.TypeA, cc)
	norec[2] &^= 0x01
	if got, rc := respCookie(t, ask(norec)); rc != m.RcodeRefused || len(got) != 24 {
		t.Fatalf("REFUSED: rcode %d, cookie %x", rc, got)
	}
}

// RRL is for forged sources; a client that returns a valid cookie cannot be
// one, so it is never limited. When RRL slips, a client that sent a cookie
// gets BADCOOKIE with a fresh one instead of a truncated answer.
func TestCookiesAndRRL(t *testing.T) {
	s, _, path := start(t, "")
	src, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(src), "rrl_rate = 0", "rrl_rate = 1\nrrl_slip = 1", 1)), 0o640)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	udp, _, _, _ := s.Addrs()
	ask := func(q []byte) []byte {
		t.Helper()
		resp, err := udpAsk(t, udp[0], q, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	cc := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	good, _ := respCookie(t, ask(cookieQuery(1, "valid.test", m.TypeA, cc)))
	if len(good) != 24 {
		t.Fatalf("no server cookie: %x", good)
	}
	for i := range 10 {
		r := ask(cookieQuery(uint16(10+i), "valid.test", m.TypeA, good))
		if p := dnstest.Parse(t, r); p.TC() || p.AN != 1 {
			t.Fatalf("query %d with a valid cookie was limited: %+v", i, p)
		}
	}

	// no cookie: limited (slip = every limited answer is truncated)
	limited := false
	for i := range 5 {
		if dnstest.Parse(t, ask(dnstest.Query(uint16(30+i), "plain.test", m.TypeA, true, false))).TC() {
			limited = true
		}
	}
	if !limited {
		t.Fatal("RRL never limited a client without a cookie")
	}

	// client cookie only: BADCOOKIE with a fresh cookie instead of TC
	var bad []byte
	for i := range 5 {
		got, rc := respCookie(t, ask(cookieQuery(uint16(40+i), "fresh.test", m.TypeA, cc)))
		if rc == m.RcodeBadCookie {
			bad = got
			break
		}
	}
	if len(bad) != 24 || !bytes.Equal(bad[:8], cc) {
		t.Fatalf("no BADCOOKIE with a cookie when RRL slipped: %x", bad)
	}
	if s.Stats.BadCookies.Load() == 0 {
		t.Fatal("BADCOOKIE not counted")
	}
	// retrying with that cookie gets the answer, past the limit
	if p := dnstest.Parse(t, ask(cookieQuery(50, "fresh.test", m.TypeA, bad))); p.Rcode != m.RcodeNoError || p.AN != 1 {
		t.Fatalf("retry with the new cookie: %+v", p)
	}
}

// server.cookies = false: the option is ignored, as by a server without
// cookies; turning them on again works without a restart.
func TestCookiesOff(t *testing.T) {
	s, _, path := start(t, "")
	udp, _, _, _ := s.Addrs()
	cc := []byte{1, 1, 2, 3, 5, 8, 13, 21}
	setCookies := func(on bool) {
		t.Helper()
		src, _ := os.ReadFile(path)
		text := regexp.MustCompile(`\ncookies = \w+`).ReplaceAllString(string(src), "")
		text = strings.Replace(text, "[server]\n", "[server]\ncookies = "+map[bool]string{true: "true", false: "false"}[on]+"\n", 1)
		os.WriteFile(path, []byte(text), 0o640)
		if err := s.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	setCookies(false)
	resp, err := udpAsk(t, udp[0], cookieQuery(1, "off.test", m.TypeA, cc), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got, rc := respCookie(t, resp); got != nil || rc != m.RcodeNoError {
		t.Fatalf("cookies off: rcode %d, cookie %x", rc, got)
	}
	setCookies(true)
	resp, err = udpAsk(t, udp[0], cookieQuery(2, "off.test", m.TypeA, cc), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := respCookie(t, resp); len(got) != 24 {
		t.Fatalf("cookies on again: %x", got)
	}
}
