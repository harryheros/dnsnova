package resolver

import (
	"testing"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

func TestLocalNames(t *testing.T) {
	recs, err := config.ParseLocalRecords([]string{
		"nas.home 192.168.1.5", "nas.home fd00::5", "*.dev.home 192.168.1.9", "api.dev.home 192.168.1.10", "Blocked.Example. 0.0.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	l := NewLocalNames(recs)
	ask := func(name string, qt uint16) (dnstest.Resp, bool) {
		t.Helper()
		req := dnstest.Query(1, name, qt, false, false)
		q, _, err := m.ParseQuery(req)
		if err != nil {
			t.Fatal(err)
		}
		resp := l.answer(req, q)
		if resp == nil {
			return dnstest.Resp{}, false
		}
		return dnstest.Parse(t, resp), true
	}
	for _, c := range []struct {
		name string
		qt   uint16
		an   int
		ok   bool
	}{
		{"nas.home", 1, 1, true}, {"NAS.home", 28, 1, true}, {"nas.home", 16, 0, true}, // TXT: no data
		{"x.dev.home", 1, 1, true}, {"a.b.dev.home", 1, 1, true}, {"dev.home", 1, 0, false},
		{"api.dev.home", 1, 1, true}, {"blocked.example", 1, 1, true}, {"other.home", 1, 0, false},
	} {
		p, ok := ask(c.name, c.qt)
		if ok != c.ok || p.AN != c.an || (ok && p.Rcode != 0) {
			t.Errorf("%s type %d: ok=%v an=%d rcode=%d", c.name, c.qt, ok, p.AN, p.Rcode)
		}
	}
	if _, err := config.ParseLocalRecords([]string{"nas.home"}); err == nil {
		t.Error("an entry without an address was accepted")
	}
	if _, err := config.ParseLocalRecords([]string{"bad name 1.2.3.4"}); err == nil {
		t.Error("three fields accepted")
	}
	if _, err := config.ParseLocalRecords([]string{"a*.home 1.2.3.4"}); err == nil {
		t.Error("a misplaced wildcard was accepted")
	}
}
