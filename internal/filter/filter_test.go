package filter

import (
	"strings"
	"testing"
)

func wireOf(t testing.TB, d string) string {
	t.Helper()
	w, ok := wire(d)
	if !ok {
		t.Fatalf("bad test name %q", d)
	}
	return w
}

const sample = `! Title: ShieldNova-style list
[Adblock Plus 2.0]
||ads.example.com^                       ! an ad network
||tracker.test^$important
||page-only.test^$third-party
||wild*.test^
/regex\.test/
example.org/path
@@||good.ads.example.com^
# hosts section
0.0.0.0 exact.test also.exact.test   # trailing comment
127.0.0.1 localhost
:: ip6-localhost
plain.example.net
not a rule at all
`

func TestParseAndMatch(t *testing.T) {
	b := NewBuilder()
	c, err := Parse(strings.NewReader(sample), b)
	if err != nil {
		t.Fatal(err)
	}
	s := b.Set()
	if c.Block != 5 || c.Allow != 1 {
		t.Fatalf("counts %+v, want 5 block and 1 allow", c)
	}
	if c.Skipped < 4 {
		t.Fatalf("page, wildcard, regex and path rules must be skipped: %+v", c)
	}
	cases := map[string]bool{
		"ads.example.com":        true,
		"x.y.ads.example.com":    true,  // everything under a ||rule
		"good.ads.example.com":   false, // @@ exception wins
		"a.good.ads.example.com": false,
		"example.com":            false, // the parent is not blocked
		"tracker.test":           true,  // $important is fine
		"page-only.test":         false, // $third-party: not a DNS rule
		"exact.test":             true,
		"sub.exact.test":         false, // hosts entries are exact
		"also.exact.test":        true,
		"plain.example.net":      true,
		"www.plain.example.net":  true,
		"localhost.test":         false,
	}
	for name, want := range cases {
		if got := s.Blocked(wireOf(t, name)); got != want {
			t.Errorf("Blocked(%s) = %v, want %v", name, got, want)
		}
	}
	if s.Rules() != 5 {
		t.Fatalf("Rules() = %d", s.Rules())
	}
}

func TestCaseAndTrailingDot(t *testing.T) {
	b := NewBuilder()
	b.Block("Ads.Example.COM.")
	if !b.Set().Blocked(wireOf(t, "ads.example.com")) {
		t.Fatal("rules must be case-insensitive and accept a trailing dot")
	}
}

func TestInvalidNames(t *testing.T) {
	for _, d := range []string{"", "com", "a..b", "-ok-.com" + strings.Repeat("x", 300), "spa ce.com", "uniçode.com"} {
		if ValidDomain(d) {
			t.Errorf("%q accepted", d)
		}
	}
	for _, d := range []string{"example.com", "_dmarc.example.com", "xn--bcher-kva.example", "a-b.c-d.e"} {
		if !ValidDomain(d) {
			t.Errorf("%q refused", d)
		}
	}
}

func TestNilSet(t *testing.T) {
	var s *Set
	if s.Blocked(wireOf(t, "ads.example.com")) || s.Rules() != 0 {
		t.Fatal("a nil set blocks nothing")
	}
}

func BenchmarkBlocked(b *testing.B) {
	bl := NewBuilder()
	for i := range 200000 {
		bl.Block("d" + strings.Repeat("x", i%7) + "-" + string(rune('a'+i%26)) + ".example" + string(rune('a'+i%13)) + ".com")
	}
	s := bl.Set()
	name := wireOf(b, "www.static.cdn.something.example.net")
	b.ReportAllocs()
	for b.Loop() {
		s.Blocked(name)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Fuzz(func(t *testing.T, list string) {
		b := NewBuilder()
		Parse(strings.NewReader(list), b)
		s := b.Set()
		s.Blocked(wireOf(t, "ads.example.com"))
	})
}
