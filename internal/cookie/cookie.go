// Package cookie implements the server side of DNS Cookies (RFC 7873) with
// the interoperable server cookie of RFC 9018, as BIND, Knot and Unbound
// make it.
//
// A client sends a random client cookie; the server answers with a server
// cookie made from the client cookie, the client's address, a timestamp
// and a secret. A client that sends it back proves that it receives answers
// at its address: its queries are not spoofed, so it need not be rate
// limited like possibly spoofed UDP traffic (see guard's RRL).
//
// Every server that shares the secret (the file under data_dir/secrets)
// accepts the cookies of the others: copy it to all nodes of an anycast
// address.
package cookie

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Option is the EDNS option code of COOKIE (RFC 7873).
const Option = 10

const (
	clientLen = 8
	// serverLen is the length of an RFC 9018 server cookie: version (1),
	// reserved (3), timestamp (4) and hash (8).
	serverLen = 16
	version   = 1
	// A server cookie is accepted for an hour, and up to five minutes from
	// the future (clocks of nodes sharing the secret differ) (RFC 9018 4.3).
	maxAge    = 3600
	maxFuture = 300
)

// State is what a query's COOKIE option shows.
type State int

const (
	None       State = iota // no COOKIE option
	Malformed               // a COOKIE option of an impossible length: FORMERR (RFC 7873 5.2.2)
	ClientOnly              // a client cookie only (the first query)
	Bad                     // a server cookie that is not ours, too old, or for another address
	Good                    // a server cookie made here for this client: not spoofed
)

func (s State) String() string {
	return [...]string{"none", "malformed", "client-only", "bad", "good"}[s]
}

// Check classifies the data of a COOKIE option (nil if the query had none).
func Check(data []byte) State {
	switch n := len(data); {
	case data == nil:
		return None
	case n == clientLen:
		return ClientOnly
	case n >= clientLen+8 && n <= clientLen+32:
		return Bad // until Verify says otherwise
	default:
		return Malformed
	}
}

// Jar makes and verifies server cookies with one secret.
type Jar struct {
	key [16]byte
	// Now is the clock (tests).
	Now func() time.Time
}

// NewJar returns a jar with the given 16-byte secret.
func NewJar(secret [16]byte) *Jar { return &Jar{key: secret, Now: time.Now} }

// Verify reports whether data (a COOKIE option's data: client cookie and
// server cookie) carries a server cookie this jar made for client.
func (j *Jar) Verify(data []byte, client netip.Addr) bool {
	if len(data) != clientLen+serverLen || data[clientLen] != version {
		return false
	}
	sc := data[clientLen:]
	ts := binary.BigEndian.Uint32(sc[4:8])
	// serial number arithmetic (RFC 1982): the timestamp wraps in 2106
	now := uint32(j.Now().Unix())
	if age := int32(now - ts); age > maxAge || age < -maxFuture {
		return false
	}
	want := j.hash(data[:clientLen], sc[:8], client)
	return subtle.ConstantTimeCompare(sc[8:16], want[:]) == 1
}

// Answer returns the COOKIE option for the response to a query whose
// option data is data: the client's cookie and a fresh server cookie for
// client. Nil when the query sent no usable client cookie.
func (j *Jar) Answer(data []byte, client netip.Addr) []byte {
	if s := Check(data); s == None || s == Malformed {
		return nil
	}
	out := make([]byte, 4, 4+clientLen+serverLen)
	binary.BigEndian.PutUint16(out, Option)
	binary.BigEndian.PutUint16(out[2:], clientLen+serverLen)
	out = append(out, data[:clientLen]...)
	head := [8]byte{version}
	binary.BigEndian.PutUint32(head[4:], uint32(j.Now().Unix()))
	out = append(out, head[:]...)
	h := j.hash(data[:clientLen], head[:], client)
	return append(out, h[:]...)
}

// hash is SipHash-2-4 over client cookie | version | reserved | timestamp |
// client address (RFC 9018 4.4).
func (j *Jar) hash(cc, head []byte, client netip.Addr) [8]byte {
	var buf [clientLen + 8 + 16]byte
	b := append(append(buf[:0], cc...), head...)
	if client = client.Unmap(); client.Is4() {
		a := client.As4()
		b = append(b, a[:]...)
	} else {
		a := client.As16()
		b = append(b, a[:]...)
	}
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], sipHash24(j.key, b))
	return out
}

// LoadSecret reads the hex secret from path, or creates the file with a new
// random one (mode 0600).
func LoadSecret(path string) ([16]byte, error) {
	var s [16]byte
	b, err := os.ReadFile(path)
	if err == nil {
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != len(s) {
			return s, fmt.Errorf("%s: want %d bytes in hex (as written by dnsnova)", path, len(s))
		}
		copy(s[:], raw)
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	if _, err := rand.Read(s[:]); err != nil {
		return s, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return s, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(s[:])+"\n"), 0o600); err != nil {
		return s, err
	}
	return s, os.Rename(tmp, path)
}

// sipHash24 is SipHash-2-4 (Aumasson and Bernstein) with a 128-bit key.
func sipHash24(key [16]byte, m []byte) uint64 {
	k0 := binary.LittleEndian.Uint64(key[0:])
	k1 := binary.LittleEndian.Uint64(key[8:])
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573
	round := func() {
		v0 += v1
		v1 = v1<<13 | v1>>51
		v1 ^= v0
		v0 = v0<<32 | v0>>32
		v2 += v3
		v3 = v3<<16 | v3>>48
		v3 ^= v2
		v0 += v3
		v3 = v3<<21 | v3>>43
		v3 ^= v0
		v2 += v1
		v1 = v1<<17 | v1>>47
		v1 ^= v2
		v2 = v2<<32 | v2>>32
	}
	n := len(m)
	for len(m) >= 8 {
		w := binary.LittleEndian.Uint64(m)
		v3 ^= w
		round()
		round()
		v0 ^= w
		m = m[8:]
	}
	var last [8]byte
	copy(last[:], m)
	last[7] = byte(n)
	w := binary.LittleEndian.Uint64(last[:])
	v3 ^= w
	round()
	round()
	v0 ^= w
	v2 ^= 0xff
	round()
	round()
	round()
	round()
	return v0 ^ v1 ^ v2 ^ v3
}
