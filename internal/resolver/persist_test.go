package resolver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/netip"
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/stats"
)

// restarted is a second resolver on the same clock, as after a restart.
func restarted(c *clock, s Settings) (*Resolver, *dnstest.Auth) {
	auth := dnstest.NewAuth()
	r := New(s, dnstest.Exchanger{Auth: auth}, stats.New())
	r.now = c.now
	return r, auth
}

// Answers saved at shutdown are served from the cache after a restart, with
// their remaining TTL, the AD flag of validated answers and negative
// answers, and without asking any upstream.
func TestCachePersistsAcrossRestart(t *testing.T) {
	r, _, c := newTest(t)
	r.Resolve(dnstest.Query(1, "a.test", m.TypeA, false, false), true)
	r.Resolve(dnstest.Query(2, "nx.test", m.TypeA, false, false), true)
	r.Resolve(dnstest.Query(3, "signed.test", m.TypeA, true, true), true)
	var buf bytes.Buffer
	n, err := r.SaveCache(&buf)
	if err != nil || n != 3 {
		t.Fatalf("saved %d entries (%v), want 3", n, err)
	}

	c.add(100 * time.Second)
	r2, auth2 := restarted(c, settings())
	if n, err := r2.LoadCache(bytes.NewReader(buf.Bytes())); err != nil || n != 3 {
		t.Fatalf("loaded %d entries (%v), want 3", n, err)
	}
	res := r2.Resolve(dnstest.Query(7, "A.test", m.TypeA, false, false), true)
	if p := dnstest.Parse(t, res.Resp); res.Status != "hit" || p.ID != 7 || p.AN != 1 || p.TTLs[0] != 200 {
		t.Fatalf("a.test after restart: %s %+v", res.Status, p)
	}
	if res := r2.Resolve(dnstest.Query(8, "nx.test", m.TypeA, false, false), true); res.Status != "hit" || m.Rcode(res.Resp) != m.RcodeNXDomain {
		t.Fatalf("nx.test after restart: %s rcode %d", res.Status, m.Rcode(res.Resp))
	}
	res = r2.Resolve(dnstest.Query(9, "signed.test", m.TypeA, true, true), true)
	if p := dnstest.Parse(t, res.Resp); res.Status != "hit" || !p.AD() {
		t.Fatalf("signed.test after restart: %s AD=%v", res.Status, p.AD())
	}
	if auth2.Count("a.test.")+auth2.Count("nx.test.")+auth2.Count("signed.test.") != 0 {
		t.Fatal("an upstream was asked for an answer that was loaded")
	}
}

// Expired entries come back only within serve_stale (and are then served
// stale and refreshed); beyond it they are left out.
func TestCacheLoadExpiry(t *testing.T) {
	r, auth, c := newTest(t)
	auth.SetTTL(60)
	r.Resolve(dnstest.Query(1, "old.test", m.TypeA, false, false), true)
	var buf bytes.Buffer
	if _, err := r.SaveCache(&buf); err != nil {
		t.Fatal(err)
	}

	c.add(10 * time.Minute) // expired, within serve_stale
	r2, auth2 := restarted(c, settings())
	if n, _ := r2.LoadCache(bytes.NewReader(buf.Bytes())); n != 1 {
		t.Fatalf("loaded %d, want 1 (stale but servable)", n)
	}
	if res := r2.Resolve(dnstest.Query(2, "old.test", m.TypeA, false, false), true); res.Status != "stale" {
		t.Fatalf("status %s, want stale", res.Status)
	}
	waitFor(t, func() bool { return auth2.Count("old.test.") == 1 })

	c.add(25 * time.Hour) // past serve_stale
	r3, _ := restarted(c, settings())
	if n, _ := r3.LoadCache(bytes.NewReader(buf.Bytes())); n != 0 {
		t.Fatalf("loaded %d entries past serve_stale", n)
	}
	noStale := settings()
	noStale.ServeStale = 0
	c.add(-25 * time.Hour)
	r4, _ := restarted(c, noStale)
	if n, _ := r4.LoadCache(bytes.NewReader(buf.Bytes())); n != 0 {
		t.Fatalf("loaded %d expired entries with serve_stale off", n)
	}
}

// The limits in force apply to loaded answers: a lower max_ttl shortens
// them as for a new answer.
func TestCacheLoadAppliesCurrentLimits(t *testing.T) {
	r, auth, c := newTest(t)
	auth.SetTTL(3600)
	r.Resolve(dnstest.Query(1, "long.test", m.TypeA, false, false), true)
	var buf bytes.Buffer
	r.SaveCache(&buf)
	s := settings()
	s.MaxTTL = 600
	r2, _ := restarted(c, s)
	r2.LoadCache(bytes.NewReader(buf.Bytes()))
	if p := dnstest.Parse(t, r2.Resolve(dnstest.Query(2, "long.test", m.TypeA, false, false), true).Resp); p.TTLs[0] != 600 {
		t.Fatalf("TTL %d after load, want max_ttl 600", p.TTLs[0])
	}
}

// A damaged file loads nothing; a file saved for another client subnet
// loads nothing either (its answers were for another network).
func TestCacheLoadRejects(t *testing.T) {
	r, _, c := newTest(t)
	r.Resolve(dnstest.Query(1, "a.test", m.TypeA, false, false), true)
	var buf bytes.Buffer
	r.SaveCache(&buf)
	good := buf.Bytes()

	for i := 0; i < len(good); i += 7 {
		bad := bytes.Clone(good)
		bad[i] ^= 0x40
		r2, _ := restarted(c, settings())
		if n, err := r2.LoadCache(bytes.NewReader(bad)); err == nil || n != 0 {
			t.Fatalf("byte %d changed: loaded %d, err %v", i, n, err)
		}
	}
	for _, cut := range []int{0, 5, len(good) / 2, len(good) - 1} {
		r2, _ := restarted(c, settings())
		if n, err := r2.LoadCache(bytes.NewReader(good[:cut])); !errors.Is(err, ErrCacheFile) || n != 0 {
			t.Fatalf("cut at %d: loaded %d, err %v", cut, n, err)
		}
	}
	s := settings()
	s.ECS = m.ClientSubnet(netip.MustParsePrefix("198.51.100.0/24"))
	r3, _ := restarted(c, s)
	if n, err := r3.LoadCache(bytes.NewReader(good)); err != nil || n != 0 {
		t.Fatalf("other ECS: loaded %d, err %v", n, err)
	}
}

// restore accepts only a response for the question its key names: a
// saved key cannot make an answer serve another name, type or class.
func TestRestoreChecksKey(t *testing.T) {
	r, _, _ := newTest(t)
	r.Resolve(dnstest.Query(1, "a.test", m.TypeA, false, false), true)
	q, _, _ := m.ParseQuery(dnstest.Query(1, "a.test", m.TypeA, false, false))
	e := r.cache.get(q.CacheKey())
	if e == nil {
		t.Fatal("not cached")
	}
	s := settings()
	if _, ok := restore(q.CacheKey(), e.msg, nil, e.stored, &s); !ok {
		t.Fatal("own key refused")
	}
	other, _, _ := m.ParseQuery(dnstest.Query(1, "b.test", m.TypeA, false, false))
	aaaa, _, _ := m.ParseQuery(dnstest.Query(1, "a.test", m.TypeAAAA, false, false))
	// (The key's DO and CD bits cannot be checked: a response does not
	// show them. The file is dnsnova's own and checksummed.)
	for _, k := range []string{other.CacheKey(), aaaa.CacheKey(), ""} {
		if _, ok := restore(k, e.msg, nil, e.stored, &s); ok {
			t.Errorf("answer for a.test/A restored under key %q", k)
		}
	}
	if _, ok := restore(q.CacheKey(), e.msg[:20], nil, e.stored, &s); ok {
		t.Error("cut-off response restored")
	}
}

// Any cache file content (with a correct checksum, so the parser is
// reached): loading never panics, and whatever loads is served as a valid
// response.
func FuzzLoadCache(f *testing.F) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	seed, _ := restarted(c, settings())
	for _, n := range []string{"a.test", "nx.test", "signed.test"} {
		seed.Resolve(dnstest.Query(1, n, m.TypeA, true, true), true)
	}
	var buf bytes.Buffer
	seed.SaveCache(&buf)
	f.Add(buf.Bytes()[:buf.Len()-4])
	f.Fuzz(func(t *testing.T, body []byte) {
		file := binary.BigEndian.AppendUint32(bytes.Clone(body), crc32.ChecksumIEEE(body))
		r2, _ := restarted(c, settings())
		n, err := r2.LoadCache(bytes.NewReader(file))
		if err != nil || n == 0 {
			return
		}
		for i := range r2.cache.shards {
			for k, e := range r2.cache.shards[i].m {
				q := &m.Query{ID: 1, Name: k[:len(k)-5], Type: m.U16([]byte(k), len(k)-5), Class: m.U16([]byte(k), len(k)-3)}
				req := dnstest.Query(1, "x", 1, false, false)
				s := settings()
				if out := r2.build(e, req, q, c.now(), false, &s); len(out) < m.HeaderLen || m.U16(out, 0) != 1 {
					t.Fatal("bad response from a loaded entry")
				}
			}
		}
	})
}
