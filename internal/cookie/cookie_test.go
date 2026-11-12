package cookie

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The reference vector of the SipHash paper (appendix A): key 00..0f,
// message 00..0e.
func TestSipHashReference(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	msg := make([]byte, 15)
	for i := range msg {
		msg[i] = byte(i)
	}
	if got := sipHash24(key, msg); got != 0xa129ca6149be45e5 {
		t.Fatalf("SipHash-2-4 = %016x, want a129ca6149be45e5", got)
	}
}

// RFC 9018 appendix A.1: a server cookie made by any implementation of the
// RFC must match, so all nodes of a mixed anycast service agree.
func TestRFC9018Vector(t *testing.T) {
	var secret [16]byte
	copy(secret[:], unhex(t, "e5e973e5a6b2a43f48e7dc849e37bfcf"))
	j := NewJar(secret)
	j.Now = func() time.Time { return time.Unix(1559731985, 0) }
	client := netip.MustParseAddr("198.51.100.100")
	cc := unhex(t, "2464c4abcf10c957")
	opt := j.Answer(cc, client)
	want := unhex(t, "000a0018"+"2464c4abcf10c957"+"010000005cf79f111f8130c3eee29480")
	if !bytes.Equal(opt, want) {
		t.Fatalf("COOKIE option\n got %x\nwant %x", opt, want)
	}
	if !j.Verify(opt[4:], client) {
		t.Fatal("its own cookie does not verify")
	}
}

func TestVerify(t *testing.T) {
	var secret [16]byte
	secret[0] = 7
	now := time.Unix(1_800_000_000, 0)
	j := NewJar(secret)
	j.Now = func() time.Time { return now }
	client := netip.MustParseAddr("2001:db8::53")
	data := j.Answer(unhex(t, "0102030405060708"), client)[4:]
	if Check(data) != Bad || !j.Verify(data, client) {
		t.Fatal("a fresh cookie does not verify")
	}
	if !j.Verify(data, netip.MustParseAddr("2001:db8::53")) {
		t.Fatal("same address")
	}
	if j.Verify(data, netip.MustParseAddr("2001:db8::54")) {
		t.Fatal("verified for another address")
	}
	other := NewJar([16]byte{1})
	other.Now = j.Now
	if other.Verify(data, client) {
		t.Fatal("verified with another secret")
	}
	bad := bytes.Clone(data)
	bad[0] ^= 1 // another client cookie
	if j.Verify(bad, client) {
		t.Fatal("verified with another client cookie")
	}
	for _, d := range []time.Duration{-maxFuture * time.Second, maxAge * time.Second} {
		now = time.Unix(1_800_000_000, 0).Add(d)
		if !j.Verify(data, client) {
			t.Errorf("rejected %v from issue", d)
		}
	}
	for _, d := range []time.Duration{-(maxFuture + 1) * time.Second, (maxAge + 1) * time.Second} {
		now = time.Unix(1_800_000_000, 0).Add(d)
		if j.Verify(data, client) {
			t.Errorf("accepted %v from issue", d)
		}
	}
	// IPv4-mapped and plain IPv4 are the same client
	now = time.Unix(1_800_000_000, 0)
	v4 := j.Answer(unhex(t, "0102030405060708"), netip.MustParseAddr("::ffff:192.0.2.1"))[4:]
	if !j.Verify(v4, netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("mapped address")
	}
}

func TestCheckLengths(t *testing.T) {
	for n, want := range map[int]State{0: Malformed, 7: Malformed, 8: ClientOnly, 9: Malformed, 15: Malformed, 16: Bad, 24: Bad, 40: Bad, 41: Malformed} {
		if got := Check(make([]byte, n)); got != want {
			t.Errorf("%d bytes: %v, want %v", n, got, want)
		}
	}
	if Check(nil) != None {
		t.Error("nil")
	}
	j := NewJar([16]byte{})
	if j.Answer(nil, netip.MustParseAddr("192.0.2.1")) != nil || j.Answer(make([]byte, 9), netip.MustParseAddr("192.0.2.1")) != nil {
		t.Error("answered without a usable client cookie")
	}
	// a client that sends another server's cookie gets ours, same client cookie
	in := append(unhex(t, "0102030405060708"), make([]byte, 24)...)
	out := j.Answer(in, netip.MustParseAddr("192.0.2.1"))
	if len(out) != 4+24 || !bytes.Equal(out[4:12], in[:8]) {
		t.Fatalf("answer to a foreign server cookie: %x", out)
	}
}

func TestLoadSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "cookie-secret")
	a, err := LoadSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("secret file: %v %v", fi, err)
	}
	b, err := LoadSecret(path)
	if err != nil || a != b {
		t.Fatal("the secret changed on reload")
	}
	if a == ([16]byte{}) {
		t.Fatal("zero secret")
	}
	os.WriteFile(path, []byte("zz\n"), 0o600)
	if _, err := LoadSecret(path); err == nil {
		t.Fatal("accepted a broken secret")
	}
}

// The cost per query with a cookie: verify the one sent, make a fresh one.
func BenchmarkVerifyAndAnswer(b *testing.B) {
	j := NewJar([16]byte{1, 2, 3})
	client := netip.MustParseAddr("192.0.2.1")
	data := j.Answer([]byte{1, 2, 3, 4, 5, 6, 7, 8}, client)[4:]
	b.ReportAllocs()
	for b.Loop() {
		if !j.Verify(data, client) {
			b.Fatal("does not verify")
		}
		j.Answer(data, client)
	}
}

// Any COOKIE option data from any client: a cookie this server made for the
// client verifies; one made for another client, or altered, does not; and
// nothing panics.
func FuzzCookie(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{192, 0, 2, 1}, uint32(0))
	f.Add(make([]byte, 40), make([]byte, 16), uint32(1<<31))
	f.Fuzz(func(t *testing.T, data, ip []byte, now uint32) {
		client, ok := netip.AddrFromSlice(ip)
		if !ok {
			return
		}
		j := NewJar([16]byte{9, 9, 9})
		j.Now = func() time.Time { return time.Unix(int64(now), 0) }
		s := Check(data)
		j.Verify(data, client)
		opt := j.Answer(data, client)
		if (opt != nil) != (s == ClientOnly || s == Bad) {
			t.Fatalf("state %v, answer %x", s, opt)
		}
		if opt == nil {
			return
		}
		mine := opt[4:]
		if !bytes.Equal(mine[:8], data[:8]) || !j.Verify(mine, client) {
			t.Fatalf("own cookie %x for %s does not verify", mine, client)
		}
		other := client.Next()
		if other.IsValid() && other.Unmap() != client.Unmap() && j.Verify(mine, other) {
			t.Fatalf("cookie for %s verified for %s", client, other)
		}
		bad := bytes.Clone(mine)
		bad[len(bad)-1] ^= 1
		if j.Verify(bad, client) {
			t.Fatal("altered cookie verified")
		}
	})
}
