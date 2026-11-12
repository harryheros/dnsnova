package server

import (
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harryheros/dnsnova/internal/config"
)

func checkConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	mode := "public"
	if strings.Contains(extra, "[access]") {
		mode = "private"
	}
	proxy := ""
	if extra == "proxy_protocol_marker" {
		extra, proxy = "", "proxy_protocol=[\"0.0.0.0/0\"]\n"
	}
	src := "[server]\n" + proxy + "mode=\"" + mode + "\"\nlisten=[\"127.0.0.1:53\"]\ndata_dir=\"" + dir + "\"\n[upstream]\nprimary=[\"udp://192.0.2.53\"]\nbootstrap=[]\n" + extra
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := config.NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	return snap.Config
}

func hasFinding(found []string, sub string) bool {
	for _, f := range found {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func TestSecurityFindings(t *testing.T) {
	safe := hostFacts{euid: 1000, account: true, totp: true}
	for _, c := range []struct {
		name, cfg string
		facts     hostFacts
		want      string // "" = no findings at all
	}{
		{"defaults, admin on loopback", "[admin]\nlisten=\"127.0.0.1:7000\"\n", safe, ""},
		{"admin open without a certificate", "[admin]\nlisten=\":7000\"\n", safe, "ssh -L 7000:127.0.0.1:7000"},
		{"admin on a LAN address without a certificate", "[admin]\nlisten=\"192.168.1.10:7000\"\n", safe, "no certificate"},
		{"admin open, no two-step", "[admin]\nlisten=\"127.0.0.1:7000\"\n[tls]\ncertificate=\"acme\"\ndomains=[\"dns.example.com\"]\nip_addresses=false\n", hostFacts{euid: 1000, account: true}, ""},
		{"admin open with certificate, no two-step", "[admin]\nlisten=\":7000\"\n[tls]\ncertificate=\"acme\"\ndomains=[\"dns.example.com\"]\n", hostFacts{euid: 1000, account: true}, "two-step verification is off"},
		{"home network: admin open without a certificate", "[access]\nallow=[\"192.168.0.0/16\"]\n[admin]\nlisten=\":7000\"\n", hostFacts{euid: 1000, account: true}, ""},
		{"PROXY protocol from anywhere", "proxy_protocol_marker", safe, "anyone in it can claim"},
		{"metrics open", "[metrics]\nlisten=\":9153\"\n", safe, "metrics.listen"},
		{"no RRL", "[limits]\nrrl_rate=0\n", safe, "rrl_rate = 0"},
		{"no client limits", "[limits]\nclient_qps=0\nprefix_qps=0\n", safe, "per-client limits"},
		{"ANY answered", "[limits]\nblock_any=false\n", safe, "block_any"},
		{"root", "", hostFacts{euid: 0}, "running as root"},
		{"secrets readable", "", hostFacts{euid: 1000, secrets: map[string]fs.FileMode{"/d/secrets": 0o755}}, "/d/secrets can be read"},
		{"secret file readable", "", hostFacts{euid: 1000, secrets: map[string]fs.FileMode{"/d/secrets": 0o700, "/d/secrets/admin.json": 0o640}}, "admin.json can be read"},
		{"config world-writable", "", hostFacts{euid: 1000, configPath: "/etc/dnsnova/dnsnova.toml", configMode: 0o666}, "world-writable"},
	} {
		found := securityFindings(checkConfig(t, c.cfg), c.facts)
		if c.want == "" {
			if len(found) > 0 {
				t.Errorf("%s: unexpected findings %q", c.name, found)
			}
			continue
		}
		if !hasFinding(found, c.want) {
			t.Errorf("%s: no finding with %q in %q", c.name, c.want, found)
		}
	}
}

// Started with an open admin port and no certificate, the server says so in
// its log and in the admin interface's events; a later change logs only
// what is new.
func TestSelfCheckAtStartup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	src := "[server]\nmode=\"public\"\nlisten=[]\ndata_dir=\"" + dir + "\"\n[upstream]\nprimary=[]\nbootstrap=[]\n[admin]\nlisten=\"0.0.0.0:0\"\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	count := func(sub string) int {
		n := 0
		for _, e := range s.EventLog.Recent(500) {
			if e.Level == "warn" && strings.Contains(e.Msg, sub) {
				n++
			}
		}
		return n
	}
	if count("admin interface listens on 0.0.0.0:0 with no certificate") != 1 {
		t.Fatalf("no startup warning about the open admin port: %+v", s.EventLog.Recent(50))
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if n := count("with no certificate"); n != 1 {
		t.Fatalf("unchanged finding logged %d times after a reload, want once", n)
	}
	os.Chmod(filepath.Join(dir, "secrets"), 0o755)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if count("can be read by other users") != 1 {
		t.Fatal("a new finding after a reload was not logged")
	}
}
