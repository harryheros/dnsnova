package recursor

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// sigExpiry is the earliest RRSIG expiry among sets.
func sigExpiry(t *testing.T, sets ...*rrset) time.Time {
	t.Helper()
	var least time.Time
	for _, s := range sets {
		for _, raw := range s.sigs {
			sg, ok := parseSig(raw)
			if !ok {
				t.Fatal("signature does not parse")
			}
			e := time.Unix(int64(sg.exp), 0)
			if least.IsZero() || e.Before(least) {
				least = e
			}
		}
	}
	return least
}

// A validated negative answer must not be cached, or served as secure,
// beyond the expiry of the signatures that proved it.
func TestNegativeCacheCappedBySignatureExpiry(t *testing.T) {
	f := loadFixture(t)
	zone := dotted("example.com.")
	soa := f.set(t, "example.com.", "example.com.", m.TypeSOA)
	proof := f.proofs("example.com.")
	expiry := sigExpiry(t, append([]*rrset{soa}, proof...)...)
	name := dotted("nope.example.com.")

	for _, left := range []time.Duration{5 * time.Second, 0} {
		now := expiry.Add(-left)
		r := New(Config{DNSSEC: true, CacheSize: 1000}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		r.now = func() time.Time { return now }
		r.keys.set(zone, &keyEntry{sec: secSecure, keys: f.keys(t, "example.com.")}, now.Add(time.Hour))
		ne := &negEntry{rcode: m.RcodeNXDomain, soa: soa, proof: proof, zone: zone, orig: 300}
		ans := &answer{sec: secSecure}
		if err := r.addNeg(context.Background(), newTask(), ans, ne, now.Add(300*time.Second), name, m.TypeA, true); err != nil {
			t.Fatal(err)
		}
		if left > 0 && ans.sec != secSecure {
			t.Fatalf("%v left: fixture did not validate: %v %s", left, ans.sec, ans.why)
		}
		if ans.negUntil.After(expiry) {
			t.Errorf("%v left: answer valid until %v, after the signatures expire at %v", left, ans.negUntil, expiry)
		}
		if _, exp, ok := r.negs.get(tkey(name, 0)); ok && exp.After(expiry) {
			t.Errorf("%v left: cached until %v, after the signatures expire at %v", left, exp, expiry)
		}
		now = expiry.Add(time.Second)
		if c, exp, ok := r.negs.get(tkey(name, 0)); ok && now.Before(exp) && c.sec == secSecure {
			t.Errorf("%v left: expired signatures still served as secure from the cache", left)
		}
	}
}
