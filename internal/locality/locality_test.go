package locality

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseExits(t *testing.T) {
	exits, err := ParseExits([]string{
		"exit-a 10.66.1.2 XA xb",
		"Exit-B 10.66.2.2,fd66:2::2 XC,XD, XE 198.51.100.0/24",
		"office 10.66.3.2 10.20.0.0/16 10.30.0.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(exits) != 3 || exits[1].Name != "exit-b" || len(exits[1].Local) != 2 ||
		strings.Join(exits[1].Countries, ",") != "XC,XD,XE" || exits[1].Networks[0].String() != "198.51.100.0/24" ||
		exits[2].Networks[1].String() != "10.30.0.7/32" || strings.Join(exits[0].Countries, ",") != "XA,XB" {
		t.Fatalf("%+v", exits)
	}
	if l, ok := exits[1].LocalFor(netip.MustParseAddr("2001:db8::1")); !ok || l.String() != "fd66:2::2" {
		t.Fatalf("IPv6 source %v %v", l, ok)
	}
	if _, ok := exits[0].LocalFor(netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("an IPv4-only exit has no IPv6 source")
	}
	for _, bad := range [][]string{
		{"exit-a 10.66.1.2"},                                 // serves nobody
		{"exit-a notanaddress XA"},                           // bad source
		{"exit-a 0.0.0.0 XA"},                                // unspecified
		{"exit-a 10.66.1.2,10.66.1.3 XA"},                    // two IPv4 sources
		{"exit-a 10.66.1.2 XA", "exit-a 10.66.2.2 XC"},       // name twice
		{"exit-a 10.66.1.2 XA", "exit-b 10.66.1.2 XC"},       // source twice
		{"exit-a 10.66.1.2 XA", "exit-b 10.66.2.2 XA"},       // country twice
		{"exit-a 10.66.1.2 JPN"},                             // not a code
		{"server 10.66.1.2 XA"},                              // reserved name
		{"exit_a! 10.66.1.2 XA"},                             // bad name
		{"a 10.66.1.2 10.0.0.0/8", "b 10.66.2.2 10.0.0.0/8"}, // network twice
	} {
		if _, err := ParseExits(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	var many []string
	for i := 0; i <= MaxExits; i++ {
		many = append(many, fmt.Sprintf("e%d 10.66.%d.2 10.%d.0.0/16", i, i, i))
	}
	if _, err := ParseExits(many); err == nil {
		t.Errorf("%d exits accepted", len(many))
	}
}

const registryFile = `2|apnic|20261124|3|19830613|20261123|+1000
apnic|*|ipv4|*|2|summary
apnic|*|ipv6|*|1|summary
apnic|XA|ipv4|203.0.113.0|256|20100101|allocated|A1
apnic|XB|ipv4|198.51.100.0|384|20100101|assigned|A2
apnic||ipv4|192.0.2.0|256||available|
apnic|ZZ|ipv4|100.0.0.0|256||reserved|
apnic|XA|ipv6|2001:db8::|32|20100101|allocated|A3
apnic|XA|asn|64500|1|20100101|allocated|A4
`

func TestCountriesLookup(t *testing.T) {
	c, err := ParseCountries(strings.NewReader(registryFile), strings.NewReader(
		"ripencc|XC|ipv4|198.51.101.128|128|20100101|allocated|R1\n"))
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]string{
		"203.0.113.0":        "XA",
		"203.0.113.255":      "XA",
		"203.0.114.0":        "",
		"198.51.100.0":       "XB",
		"198.51.101.127":     "XB", // 384 addresses: not a CIDR block
		"198.51.101.128":     "XC",
		"198.51.101.255":     "XC",
		"192.0.2.1":          "", // available
		"100.0.0.1":          "", // ZZ
		"2001:db8:1::5":      "XA",
		"2001:db9::1":        "",
		"::ffff:203.0.113.9": "XA",
		"10.0.0.1":           "",
	} {
		if got := c.Lookup(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %q, want %q", addr, got, want)
		}
	}
	if c.Len() != 4 {
		t.Errorf("%d blocks, want 4", c.Len())
	}
	var nilTable *Countries
	if nilTable.Lookup(netip.MustParseAddr("203.0.113.1")) != "" {
		t.Fatal("no table: no country")
	}
}

func TestMapperNetworkWinsOverCountry(t *testing.T) {
	exits, err := ParseExits([]string{
		"exit-a 10.66.1.2 XA",
		"office 10.66.3.2 203.0.113.128/25 10.20.0.0/16",
		"narrow 10.66.4.2 10.20.5.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	m := NewMapper(exits)
	c, _ := ParseCountries(strings.NewReader(registryFile))
	if got := m.View(netip.MustParseAddr("203.0.113.5")); got != 0 {
		t.Fatalf("no country table yet: view %d, want 0 (the server)", got)
	}
	m.SetCountries(c)
	for addr, want := range map[string]int{
		"203.0.113.5":   1, // XA
		"203.0.113.200": 2, // a network of office, inside XA
		"10.20.1.1":     2,
		"10.20.5.9":     3, // the narrowest network wins
		"198.51.100.1":  0, // XB: no exit
		"192.168.1.1":   0,
	} {
		if got := m.View(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: view %d (%s), want %d", addr, got, m.ViewName(got), want)
		}
	}
	if v, by := m.Explain(netip.MustParseAddr("203.0.113.5")); v != 1 || by != "XA" {
		t.Errorf("explain: %d %q", v, by)
	}
	if m.ViewName(0) != ServerName || m.ViewName(3) != "narrow" || m.Views() != 4 || !m.NeedsCountries() {
		t.Fatal("names")
	}
	var none *Mapper
	if none.View(netip.MustParseAddr("203.0.113.5")) != 0 {
		t.Fatal("nil mapper: the server")
	}
}

func TestContextCarriesViewAndVariants(t *testing.T) {
	ctx := context.Background()
	if ViewFrom(ctx) != 0 || VariantsFrom(ctx) != nil {
		t.Fatal("defaults")
	}
	x := &Variants{}
	ctx = WithVariants(WithView(ctx, 2), x)
	if ViewFrom(ctx) != 2 || VariantsFrom(ctx) != x {
		t.Fatal("not carried")
	}
	x.Set([][]byte{{1}, nil})
	if got := x.Get(); len(got) != 2 || got[1] != nil {
		t.Fatal("variants")
	}
}

func TestReportCountsOnly(t *testing.T) {
	var r Report
	r.Add("XA", true)
	r.Add("XA", false)
	r.Add("", true)
	r.Add("XC", false)
	r.Add("XC", false)
	r.Add("XC", false)
	rows := r.Rows()
	if len(rows) != 3 || rows[0] != (ReportRow{"XC", 3, 0}) || rows[1] != (ReportRow{"--", 1, 1}) && rows[1] != (ReportRow{"XA", 2, 1}) {
		t.Fatalf("%+v", rows)
	}
	for i := 0; i < maxReportRows+50; i++ {
		r.Add(fmt.Sprintf("%c%c", 'A'+i/26%26, 'A'+i%26), false)
	}
	if n := len(r.Rows()); n > maxReportRows {
		t.Fatalf("%d rows kept", n)
	}
}

// big returns a registry file with n blocks of country cc.
func big(cc string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "apnic|%s|ipv4|10.%d.%d.0|256|20100101|allocated|X\n", cc, i/256, i%256)
	}
	return b.String()
}

func TestUpdaterKeepsTheCopyInUse(t *testing.T) {
	var body atomic.Value
	body.Store(big("XA", minBlocks))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body.Load().(string))
	}))
	defer srv.Close()
	dir := t.TempDir()
	var got atomic.Pointer[Countries]
	u := &Updater{Dir: dir, Sources: []string{srv.URL + "/apnic"}, HTTP: srv.Client(), Publish: func(c *Countries) { got.Store(c) }}
	u.refresh(context.Background())
	if c := got.Load(); c.Lookup(netip.MustParseAddr("10.0.1.1")) != "XA" || u.Status().Blocks == 0 {
		t.Fatalf("first download not published: %+v", u.Status())
	}
	// a broken download (an error page): the copy in use stays
	body.Store("<html>maintenance</html>")
	got.Store(nil)
	u.refresh(context.Background())
	if got.Load() != nil || u.Status().Error == "" {
		t.Fatalf("a broken file replaced the table: %+v", u.Status())
	}
	// after a restart, the stored copy is used before any download
	u2 := &Updater{Dir: dir, Sources: u.Sources}
	if c, _ := u2.load(); c.Lookup(netip.MustParseAddr("10.0.1.1")) != "XA" {
		t.Fatal("stored copy not loaded")
	}
	// a file path works too, and a missing one is an error, not a crash
	path := dir + "/local.txt"
	os.WriteFile(path, []byte(big("XC", minBlocks)), 0o600)
	u3 := &Updater{Dir: t.TempDir(), Sources: []string{path, "/nonexistent"}, Publish: func(c *Countries) { got.Store(c) }}
	u3.refresh(context.Background())
	if got.Load().Lookup(netip.MustParseAddr("10.0.1.1")) != "XC" || !strings.Contains(u3.Status().Error, "nonexistent") {
		t.Fatalf("file source: %+v", u3.Status())
	}
	// Run publishes the stored copies at once
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	got.Store(nil)
	u4 := &Updater{Dir: dir, Sources: u.Sources, Every: time.Hour, Publish: func(c *Countries) { got.Store(c); close(done) }}
	go u4.Run(ctx)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stored copy not published at start")
	}
	cancel()
}
