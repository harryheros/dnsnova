package resolver

import (
	"strconv"
	"strings"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Names answered locally and never sent upstream:
//   - reverse zones of private, loopback, link-local and documentation
//     networks (RFC 6303, RFC 7793), so internal addresses don't leak;
//   - "localhost." (RFC 6761), "invalid." and "resolver.arpa." (RFC 9462).
var localZones = func() map[string]bool {
	z := map[string]bool{}
	add := func(dotted string) { z[toWire(dotted)] = true }
	for _, s := range []string{
		"10.in-addr.arpa", "168.192.in-addr.arpa", "127.in-addr.arpa", "0.in-addr.arpa",
		"254.169.in-addr.arpa", "2.0.192.in-addr.arpa", "100.51.198.in-addr.arpa",
		"113.0.203.in-addr.arpa", "255.255.255.255.in-addr.arpa",
		"d.f.ip6.arpa", "c.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa",
		"b.e.f.ip6.arpa", "8.b.d.0.1.0.0.2.ip6.arpa",
		"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
		"localhost", "invalid", "resolver.arpa",
	} {
		add(s)
	}
	for i := 16; i <= 31; i++ {
		add(strconv.Itoa(i) + ".172.in-addr.arpa")
	}
	for i := 64; i <= 127; i++ { // 100.64.0.0/10, shared address space
		add(strconv.Itoa(i) + ".100.in-addr.arpa")
	}
	return z
}()

func toWire(dotted string) string { return m.WireName(strings.Split(dotted, ".")...) }

const localTTL = 10800

var (
	wireLocalhost = toWire("localhost")
	wireArpa      = "\x04arpa"
	wireInvalid   = "\x07invalid"
)

// localAnswer returns a locally built response for q, or nil if q should be
// resolved upstream. Local answers never carry the AD bit.
func localAnswer(req []byte, q *m.Query) []byte {
	n := q.Name
	if !strings.HasSuffix(n, wireArpa) && !strings.HasSuffix(n, wireLocalhost) && !strings.HasSuffix(n, wireInvalid) {
		return nil
	}
	zone, ok := matchZone(n)
	if !ok {
		return nil
	}
	if zone == wireLocalhost {
		switch q.Type {
		case m.TypeA:
			return m.Answer(req, q, localTTL, []byte{127, 0, 0, 1})
		case m.TypeAAAA:
			return m.Answer(req, q, localTTL, []byte{15: 1})
		}
		return m.NegativeSOA(req, q, zone, localTTL, m.RcodeNoError)
	}
	if n == zone {
		return m.NegativeSOA(req, q, zone, localTTL, m.RcodeNoError) // the apex exists
	}
	return m.NegativeSOA(req, q, zone, localTTL, m.RcodeNXDomain)
}

// matchZone finds the local zone that n (wire format) is in.
func matchZone(n string) (string, bool) {
	for i := 0; i < len(n); {
		if localZones[n[i:]] {
			return n[i:], true
		}
		i += 1 + int(n[i])
	}
	return "", false
}
