package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harryheros/dnsnova/internal/admin"
	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/tlsmgr"
)

// plainAdmin is the admin port's plain-HTTP handler over a real admin API,
// with a certificate for dns.test and 127.0.0.1 when withCert.
func plainAdmin(t *testing.T, withCert bool, extra ...string) http.Handler {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	mode := "public"
	if len(extra) > 0 {
		mode = "private"
	}
	src := "[server]\nmode=\"" + mode + "\"\nlisten=[\"127.0.0.1:53\"]\ndata_dir=\"" + dir + "\"\n[upstream]\nprimary=[\"udp://192.0.2.53\"]\nbootstrap=[]\n[tls]\ndomains=[\"dns.test\"]\n" + strings.Join(extra, "")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := config.NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Server{Log: log}
	s.snap.Store(snap)
	if s.admin, err = admin.New(s, dir, log); err != nil {
		t.Fatal(err)
	}
	s.Certs = tlsmgr.NewManager(dir, log)
	if withCert {
		writeCert(t, dir, "admin")
		if err := s.Certs.Configure(tlsmgr.Settings{Mode: "files", CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}); err != nil {
			t.Fatal(err)
		}
		if !s.Certs.Ready() {
			t.Fatal("precondition: certificate not loaded")
		}
	}
	return s.adminPlain("7000")
}

type plainReq struct {
	remote, host, path string
	hdr                []string
}

func (p plainReq) do(h http.Handler) *httptest.ResponseRecorder {
	if p.path == "" {
		p.path = "/api/v1/setup"
	}
	r := httptest.NewRequest("GET", "http://"+p.host+p.path, nil)
	r.RemoteAddr = p.remote
	for i := 0; i+1 < len(p.hdr); i += 2 {
		r.Header.Set(p.hdr[i], p.hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Plain HTTP on the admin port carries the password in the clear, so it is
// answered only on this machine: other machines are refused with
// directions, or sent to HTTPS when the certificate covers their name.
func TestAdminPlainHTTPOnlyLocal(t *testing.T) {
	noCert := plainAdmin(t, false)
	for _, c := range []struct {
		name string
		req  plainReq
		want int
	}{
		{"loopback", plainReq{remote: "127.0.0.1:5000", host: "127.0.0.1:7000"}, 200},
		{"loopback v6", plainReq{remote: "[::1]:5000", host: "[::1]:7000"}, 200},
		{"private network", plainReq{remote: "192.168.1.20:5000", host: "192.168.1.10:7000"}, 403},
		{"internet", plainReq{remote: "203.0.113.9:5000", host: "198.51.100.1:7000"}, 403},
		{"internet claims https", plainReq{remote: "203.0.113.9:5000", host: "198.51.100.1:7000", hdr: []string{"X-Forwarded-Proto", "https"}}, 403},
		{"local proxy, http", plainReq{remote: "127.0.0.1:5000", host: "dns.test", hdr: []string{"X-Forwarded-For", "203.0.113.9"}}, 403},
		{"local proxy, https", plainReq{remote: "127.0.0.1:5000", host: "dns.test", hdr: []string{"X-Forwarded-For", "203.0.113.9", "X-Forwarded-Proto", "https"}}, 200},
	} {
		if w := c.req.do(noCert); w.Code != c.want {
			t.Errorf("%s: %d, want %d: %s", c.name, w.Code, c.want, w.Body)
		}
	}

	// The refusal says what to do instead: JSON for the API, text otherwise.
	w := plainReq{remote: "203.0.113.9:5000", host: "198.51.100.1:7000"}.do(noCert)
	var e struct{ Error string }
	if json.Unmarshal(w.Body.Bytes(), &e); !strings.Contains(e.Error, "ssh -L 7000:127.0.0.1:7000 user@198.51.100.1") {
		t.Errorf("API refusal lacks the tunnel command: %s", w.Body)
	}
	w = plainReq{remote: "203.0.113.9:5000", host: "198.51.100.1:7000", path: "/"}.do(noCert)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") || !strings.Contains(w.Body.String(), "SSH tunnel") {
		t.Errorf("page refusal: %s %s", ct, w.Body)
	}
	w = plainReq{remote: "127.0.0.1:5000", host: "dns.test", hdr: []string{"X-Forwarded-Proto", "http"}}.do(noCert)
	if !strings.Contains(w.Body.String(), "X-Forwarded-Proto: https") {
		t.Errorf("proxy refusal does not say what the proxy must send: %s", w.Body)
	}

	// With a certificate: its names go to HTTPS on the same port; other
	// names are refused and pointed at the domain.
	withCert := plainAdmin(t, true)
	w = plainReq{remote: "203.0.113.9:5000", host: "dns.test:7000", path: "/api/v1/setup?x=1"}.do(withCert)
	if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "https://dns.test:7000/api/v1/setup?x=1" {
		t.Errorf("certified name: %d %q, want 308 to the same path over HTTPS", w.Code, w.Header().Get("Location"))
	}
	w = plainReq{remote: "203.0.113.9:5000", host: "198.51.100.1:7000"}.do(withCert)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "https://dns.test:7000/") {
		t.Errorf("uncertified address: %d %s", w.Code, w.Body)
	}
	if w := (plainReq{remote: "127.0.0.1:5000", host: "dns.test:7000"}).do(withCert); w.Code != 200 {
		t.Errorf("loopback with a certificate: %d", w.Code)
	}
}

// A server installed for a home or office network (private mode) serves
// its admin interface to that network over plain HTTP; public mode does not,
// and says how to change that when the visitor is on a private network.
func TestAdminPlainHTTPOnLAN(t *testing.T) {
	lan := plainAdmin(t, false, "[access]\nallow=[\"192.168.0.0/16\", \"100.64.0.0/10\", \"198.51.100.0/24\"]\n")
	for _, c := range []struct {
		name string
		req  plainReq
		want int
	}{
		{"home network", plainReq{remote: "192.168.1.20:5000", host: "192.168.1.10:7000"}, 200},
		{"VPN (shared address space)", plainReq{remote: "100.100.1.2:5000", host: "192.168.1.10:7000"}, 200},
		{"loopback", plainReq{remote: "127.0.0.1:5000", host: "127.0.0.1:7000"}, 200},
		{"private but not allowed", plainReq{remote: "10.1.2.3:5000", host: "192.168.1.10:7000"}, 403},
		{"allowed but public", plainReq{remote: "198.51.100.7:5000", host: "192.168.1.10:7000"}, 403},
		{"internet", plainReq{remote: "203.0.113.9:5000", host: "192.168.1.10:7000"}, 403},
		{"through a proxy", plainReq{remote: "192.168.1.20:5000", host: "192.168.1.10:7000", hdr: []string{"X-Forwarded-For", "203.0.113.9"}}, 403},
	} {
		if w := c.req.do(lan); w.Code != c.want {
			t.Errorf("%s: %d, want %d: %s", c.name, w.Code, c.want, w.Body)
		}
	}
	w := plainReq{remote: "192.168.1.20:5000", host: "192.168.1.10:7000"}.do(plainAdmin(t, false))
	if w.Code != 403 || !strings.Contains(w.Body.String(), "My network") {
		t.Errorf("public mode, visitor on a private network: %d %s", w.Code, w.Body)
	}
	if w := (plainReq{remote: "203.0.113.9:5000", host: "198.51.100.1:7000"}).do(plainAdmin(t, false)); strings.Contains(w.Body.String(), "My network") {
		t.Errorf("visitor from the internet told about home networks: %s", w.Body)
	}
}

func TestCertCovers(t *testing.T) {
	names := []string{"dns.test", "*.wild.test", "192.0.2.1", "2001:db8::1"}
	for host, want := range map[string]bool{
		"dns.test": true, "DNS.test.:7000": true, "a.wild.test": true, "a.b.wild.test": false, "wild.test": false,
		"192.0.2.1:7000": true, "[2001:db8::1]:7000": true, "192.0.2.2": false, "other.test": false, "": false,
	} {
		if got := certCovers(names, host); got != want {
			t.Errorf("certCovers(%q) = %v, want %v", host, got, want)
		}
	}
}
