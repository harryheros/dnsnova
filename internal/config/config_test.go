package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExampleConfigLoads(t *testing.T) {
	src, err := os.ReadFile("../../dnsnova.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	c, _, warns, err := Load(src)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Mode != ModePublic || len(c.Server.Listen) != 2 || c.Upstream.FallbackDelay != 1500*time.Millisecond ||
		c.Cache.MaxTTL != 86400 || c.Cache.MaxNegativeTTL != 3600 || c.Limits.RRLSlip != 2 {
		t.Fatalf("unexpected values: %+v", c)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "ignored in public mode") {
		t.Fatalf("warnings: %v", warns)
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	src := `[server]
mode = "privte"
listen = ["nonsense"]

[upstream]
primary = ["ftp://x"]
timeot = "3s"

[limits]
udp_max_size = 100
`
	_, _, _, err := Load([]byte(src))
	var es Errors
	if !errors.As(err, &es) {
		t.Fatalf("want Errors, got %v", err)
	}
	got := es.Error()
	for _, want := range []string{
		"line 2: server.mode", "line 3: server.listen", "line 6: upstream.primary",
		"line 7: upstream.timeot: unknown setting (did you mean upstream.timeout?)", "line 10: limits.udp_max_size",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if es[0].Line != 2 || es[len(es)-1].Line != 10 {
		t.Fatalf("errors not in line order:\n%s", got)
	}
}

func TestPrivateModeNeedsAllowList(t *testing.T) {
	src := "[server]\nmode = \"private\"\nlisten = [\"127.0.0.1:53\"]\n[upstream]\nprimary = [\"1.1.1.1\"]\n"
	if _, _, _, err := Load([]byte(src)); err == nil || !strings.Contains(err.Error(), "access.allow") {
		t.Fatalf("want access.allow error, got %v", err)
	}
	src += "[access]\nallow = [\"10.0.0.0/8\", \"192.0.2.7\", \"::ffff:172.16.0.0/108\"]\n"
	c, _, _, err := Load([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Access.Allow) != 3 || c.Access.Allow[1].Bits() != 32 || c.Access.Allow[2].String() != "172.16.0.0/12" {
		t.Fatalf("prefixes: %v", c.Access.Allow)
	}
}

func minimal() []byte {
	return []byte("# my comment\n[server]\nmode = \"public\"\nlisten = [\"127.0.0.1:53\"]\n\n[upstream]\nprimary = [\"1.1.1.1\"]\n")
}

func TestStoreWriteConflictHistoryRestore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	if err := os.WriteFile(path, minimal(), 0o640); err != nil {
		t.Fatal(err)
	}
	s := NewStore(path)
	snap, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Changed() {
		t.Fatal("unchanged file reported as changed")
	}

	// a web edit: change one value, keep the comment
	out, err := snap.Doc.Set("server", "mode", Str("private"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(out, snap.Hash); err == nil {
		t.Fatal("invalid config (private without allow) must not be written")
	}
	out, _ = snap.Doc.Set("upstream", "parallel", IntV(1))
	snap2, err := s.Write(out, snap.Hash)
	if err != nil {
		t.Fatal(err)
	}
	disk, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(disk), "# my comment\n") || !strings.Contains(string(disk), "parallel = 1") {
		t.Fatalf("written file:\n%s", disk)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("permissions changed to %v", fi.Mode().Perm())
	}

	// someone edits the file by hand: an edit based on the old hash conflicts
	time.Sleep(10 * time.Millisecond)
	hand := append(disk, []byte("\n[cache]\nsize = 10\n")...)
	os.WriteFile(path, hand, 0o640)
	if !s.Changed() {
		t.Fatal("manual edit not detected")
	}
	if _, err := s.Write(out, snap2.Hash); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}

	hist, err := s.History()
	if err != nil || len(hist) != 1 {
		t.Fatalf("history: %v %v", hist, err)
	}
	cur, _ := s.Load()
	restored, err := s.Restore(hist[0].Name, cur.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Config.Upstream.Parallel != 2 {
		t.Fatal("restore did not bring back the original file")
	}
	if _, err := s.Restore("../../etc/passwd", restored.Hash); err == nil {
		t.Fatal("path traversal accepted")
	}

	// history is capped
	for i := 0; i < HistoryLimit+5; i++ {
		cur, _ := s.Load()
		out, _ := cur.Doc.Set("cache", "size", IntV(int64(100+i)))
		if _, err := s.Write(out, cur.Hash); err != nil {
			t.Fatal(err)
		}
	}
	if hist, _ := s.History(); len(hist) != HistoryLimit {
		t.Fatalf("history has %d entries, want %d", len(hist), HistoryLimit)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".dnsnova.toml.tmp-*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
}

func TestTLSValidation(t *testing.T) {
	base := "[server]\nmode = \"public\"\nlisten = [\"192.0.2.10:53\", \"[2001:db8::10]:53\", \"10.0.0.1:53\"]\n[upstream]\nprimary = [\"1.1.1.1\"]\n"
	cases := []struct {
		extra, want string
	}{
		{"[dot]\nlisten = [\"192.0.2.10:853\"]\n", "needs a certificate"},
		{"[doq]\nlisten = [\"192.0.2.10:853\"]\n", "needs a certificate"},
		{"[doq]\nlisten = [\"dns.example:853\"]\n", "must be an IP address"},
		{"[limits]\nquic_connections = 0\n", "quic_connections"},
		{"[tls]\ncertificate = \"files\"\n", "cert_file"},
		{"[tls]\ncertificate = \"acme\"\n", "at least one domain"},
		{"[tls]\ncertificate = \"acme\"\ndomains = [\"bad_name\"]\n", "not a valid domain"},
		{"[tls]\ncertificate = \"acme\"\ndomains = [\"dns.example.com\"]\nacme_directory = \"http://ca.example/dir\"\n", "https URL"},
		{"[tls]\ncertificate = \"acme\"\ndomains = [\"dns.example.com\"]\nchallenge = \"tls-alpn-01\"\n", "port 443"},
		{"[tls]\ncertificate = \"magic\"\n", "must be"},
	}
	for _, c := range cases {
		_, _, _, err := Load([]byte(base + c.extra))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: want error containing %q, got %v", c.extra, c.want, err)
		}
	}

	ok := base + "[dot]\nlisten = [\"192.0.2.10:853\"]\n[doh]\nhttps_listen = [\"192.0.2.10:443\"]\n" +
		"[tls]\ncertificate = \"acme\"\ndomains = [\"dns.example.com\"]\nip_addresses = true\n"
	c, _, warns, err := Load([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if !c.DoH.HTTP3 || c.Limits.QUICConnections != 1000 {
		t.Fatalf("HTTP/3 should be on by default with a 1000-connection cap: %v %d", c.DoH.HTTP3, c.Limits.QUICConnections)
	}
	if c.TLS.Challenge != "tls-alpn-01" {
		t.Fatalf("with a listener on 443 the challenge should default to tls-alpn-01, got %q", c.TLS.Challenge)
	}
	if ips := c.PublicListenIPs(); len(ips) != 2 || ips[0].String() != "192.0.2.10" || ips[1].String() != "2001:db8::10" {
		t.Fatalf("public listen IPs: %v", ips) // 10.0.0.1 is private and excluded
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	noIP := strings.Replace(ok, "ip_addresses = true\n", "", 1)
	if _, _, warns, _ := Load([]byte(noIP)); len(warns) != 1 || !strings.Contains(warns[0], "verify") {
		t.Fatalf("expected a DDR verification warning, got %v", warns)
	}
	// DoQ alone is enough to listen on, and UDP-only it cannot answer tls-alpn-01
	doqOnly := strings.Replace(base, "listen = [\"192.0.2.10:53\", \"[2001:db8::10]:53\", \"10.0.0.1:53\"]", "listen = []", 1) +
		"[doq]\nlisten = [\"192.0.2.10:853\"]\n[tls]\ncertificate = \"acme\"\ndomains = [\"dns.example.com\"]\n"
	if c, _, _, err := Load([]byte(doqOnly)); err != nil || c.TLS.Challenge != "http-01" || len(c.DoQ.Listen) != 1 {
		t.Fatalf("DoQ-only configuration: %v %v", c, err)
	}
	httpChal := strings.Replace(ok, "https_listen = [\"192.0.2.10:443\"]", "https_listen = [\"192.0.2.10:8443\"]", 1)
	if c, _, _, err := Load([]byte(httpChal)); err != nil || c.TLS.Challenge != "http-01" {
		t.Fatalf("without 443 the challenge should be http-01: %v %v", c, err)
	}
}

// Every setting reads back in a form the file accepts, and writing that
// value into a file loads to the same value.
func TestGetRoundTrip(t *testing.T) {
	base := "[server]\nmode = \"private\"\nlisten = [\"127.0.0.1:53\"]\n\n[access]\nallow = [\"10.0.0.0/8\", \"192.0.2.1\"]\n\n[upstream]\nprimary = [\"udp://192.0.2.53\"]\nbootstrap = []\n\n[limits]\nclient_qps = 2.5\nrrl_rate = 7\n"
	cfg, doc, _, err := Load([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := cfg.Get("access.allow"); Format(v) != `["10.0.0.0/8", "192.0.2.1"]` {
		t.Fatalf("access.allow reads back as %s", Format(v))
	}
	if v, _ := cfg.Get("upstream.timeout"); v.Str != "3s" {
		t.Fatalf("durations read back as %q", v.Str)
	}
	for _, key := range Keys() {
		v, ok := cfg.Get(key)
		if !ok {
			t.Fatalf("%s: no getter", key)
		}
		table, k := SplitKey(key)
		src, err := doc.Set(table, k, v)
		if err != nil {
			t.Fatalf("%s = %s: %v", key, Format(v), err)
		}
		cfg2, _, _, err := Load(src)
		if err != nil {
			t.Fatalf("%s = %s does not load back: %v", key, Format(v), err)
		}
		if v2, _ := cfg2.Get(key); Format(v2) != Format(v) {
			t.Fatalf("%s: %s became %s", key, Format(v), Format(v2))
		}
	}
	if _, ok := cfg.Get("no.such"); ok {
		t.Fatal("unknown key has a value")
	}
	for _, c := range []struct {
		d time.Duration
		s string
	}{{0, "0s"}, {90 * time.Second, "90s"}, {2 * time.Hour, "2h"}, {1500 * time.Millisecond, "1.5s"}, {250 * time.Millisecond, "250ms"}, {10 * time.Minute, "10m"}} {
		if got := FormatDuration(c.d); got != c.s {
			t.Fatalf("FormatDuration(%v) = %q, want %q", c.d, got, c.s)
		}
	}
}

func TestFilterDefaultsAndValidation(t *testing.T) {
	c, _, _, err := Load(minimal())
	if err != nil {
		t.Fatal(err)
	}
	if c.Filter.Enabled || c.Filter.DoHPath != "/filtered" || c.Filter.UpdateInterval != 24*time.Hour ||
		len(c.Filter.Lists) != 1 || c.Filter.Lists[0] != DefaultFilterList {
		t.Fatalf("filter defaults: %+v", c.Filter)
	}
	bad := string(minimal()) + `
[filter]
enabled = true
lists = ["ftp://x/list", "relative/path.txt"]
block = ["not a domain"]
allow = ["ok.example"]
names = ["filtered.dns.example.com"]
update_interval = "5m"
doh_path = "/dns-query"
listen = ["127.0.0.1:53", "nonsense"]
`
	_, _, _, err = Load([]byte(bad))
	var es Errors
	if !errors.As(err, &es) {
		t.Fatalf("errors expected, got %v", err)
	}
	got := map[string]int{}
	for _, e := range es {
		got[e.Key]++
	}
	for key, n := range map[string]int{"filter.lists": 2, "filter.block": 1, "filter.update_interval": 1, "filter.doh_path": 1, "filter.listen": 2} {
		if got[key] != n {
			t.Errorf("%s: %d errors, want %d (%v)", key, got[key], n, es)
		}
	}
	if got["filter.allow"] != 0 || got["filter.names"] != 0 {
		t.Errorf("valid values refused: %v", es)
	}

	// on, but no address uses it: a warning, not an error
	_, _, warns, err := Load(append(minimal(), "\n[filter]\nenabled = true\n"...))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(warns, "\n"), "no address uses filtering") {
		t.Fatalf("warnings: %v", warns)
	}
}
