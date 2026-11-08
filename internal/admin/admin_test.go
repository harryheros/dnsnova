package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/events"
	"github.com/harryheros/dnsnova/internal/insight"
	"github.com/harryheros/dnsnova/internal/stats"
	"github.com/harryheros/dnsnova/internal/tlsmgr"
)

func TestMain(m *testing.M) {
	hashParams.time, hashParams.memory, hashParams.threads = 1, 64, 1 // fast hashes for tests
	os.Exit(m.Run())
}

// fake is a Backend over a real configuration file.
type fake struct {
	mu        sync.Mutex
	store     *config.Store
	snap      *config.Snapshot
	failApply error
	cleared   int
	qlog      *insight.QueryLog
}

func (f *fake) Version() string                   { return "test" }
func (f *fake) Started() time.Time                { return time.Unix(1_700_000_000, 0) }
func (f *fake) Report(time.Duration) stats.Report { return stats.Report{} }
func (f *fake) Tops(time.Duration) Tops {
	return Tops{Domains: []insight.Entry{{Name: "example.com", Count: 9}}}
}
func (f *fake) QueryLog() *insight.QueryLog { return f.qlog }
func (f *fake) Upstreams() []Upstream {
	return []Upstream{{Address: "udp://192.0.2.53", Role: "primary", Healthy: true}}
}
func (f *fake) Certificate() tlsmgr.Status                    { return tlsmgr.Status{Mode: "none"} }
func (f *fake) Events(int) []events.Event                     { return nil }
func (f *fake) Cache() (int, int)                             { return 3, 1 }
func (f *fake) ClearCache()                                   { f.mu.Lock(); f.cleared++; f.mu.Unlock() }
func (f *fake) Listeners() map[string][]string                { return map[string][]string{"udp": {"127.0.0.1:53"}} }
func (f *fake) ConfigHistory() ([]config.HistoryEntry, error) { return f.store.History() }
func (f *fake) ConfigHistoryFile(name string) ([]byte, error) {
	if name != filepath.Base(name) {
		return nil, errors.New("bad name")
	}
	return os.ReadFile(filepath.Join(f.store.HistoryDir, name))
}
func (f *fake) Addresses() []HostAddress {
	return []HostAddress{{Address: "192.0.2.10", Interface: "eth0", Public: true}}
}
func (f *fake) Lookup(_ context.Context, name string, qt uint16, specs []string) []LookupResult {
	return []LookupResult{{Upstream: strings.Join(specs, ","), Rcode: "NOERROR", Answers: []string{fmt.Sprintf("%q %d", name, qt)}}}
}
func (f *fake) Snapshot() *config.Snapshot { f.mu.Lock(); defer f.mu.Unlock(); return f.snap }
func (f *fake) ApplyConfig(src []byte, expected string) (*config.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.snap
	snap, err := f.store.Write(src, expected)
	if err != nil {
		return nil, err
	}
	if f.failApply != nil {
		f.store.Write(old.Doc.Src, snap.Hash)
		return nil, f.failApply
	}
	f.snap = snap
	return snap, nil
}

const testConfig = `# DNSNova test configuration
[server]
mode = "public"  # who may query
listen = ["127.0.0.1:53"]
data_dir = "%DIR%"

[upstream]
primary = ["udp://192.0.2.53"]
bootstrap = []

[tls]
domains = ["dns.example.com"]
`

type env struct {
	t    *testing.T
	a    *Admin
	b    *fake
	srv  *httptest.Server
	dir  string
	now  time.Time
	csrf string
	c    *http.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsnova.toml")
	os.WriteFile(path, []byte(strings.ReplaceAll(testConfig, "%DIR%", dir)), 0o640)
	st := config.NewStore(path)
	snap, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	b := &fake{store: st, snap: snap, qlog: insight.NewQueryLog()}
	a, err := New(b, dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, a: a, b: b, dir: dir, now: time.Unix(1_800_000_000, 0)}
	a.Now = func() time.Time { return e.now }
	e.srv = httptest.NewServer(a)
	t.Cleanup(e.srv.Close)
	e.c = e.client()
	return e
}

func (e *env) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

type resp struct {
	code int
	hdr  http.Header
	body map[string]any
	raw  string
}

// do sends a JSON request; body nil sends none. The env's CSRF token is
// added to state-changing requests.
func (e *env) do(c *http.Client, method, path string, body any, hdr ...string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != "GET" && e.csrf != "" {
		req.Header.Set("X-CSRF-Token", e.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	r, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	out := resp{code: r.StatusCode, hdr: r.Header, raw: string(raw)}
	json.Unmarshal(raw, &out.body)
	return out
}

func (e *env) setup() {
	e.t.Helper()
	r := e.do(e.c, "POST", "/api/v1/setup", map[string]string{"code": e.a.SetupCode(), "username": "ops", "password": "correct horse battery"})
	if r.code != 201 {
		e.t.Fatalf("setup: %d %s", r.code, r.raw)
	}
	e.csrf = r.body["csrf"].(string)
}

func TestSetupLoginAndLockout(t *testing.T) {
	e := newEnv(t)
	if r := e.do(e.c, "GET", "/api/v1/setup", nil); r.code != 200 || r.body["needed"] != true {
		t.Fatalf("setup state: %d %s", r.code, r.raw)
	}
	code := e.a.SetupCode()
	if len(code) != 32 {
		t.Fatalf("setup code %q", code)
	}
	if fi, err := os.Stat(filepath.Join(e.dir, "secrets", "setup-code")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("setup code file: %v %v", fi, err)
	}
	if r := e.do(e.c, "GET", "/api/v1/status", nil); r.code != 401 {
		t.Fatalf("status before setup: %d", r.code)
	}
	if r := e.do(e.c, "POST", "/api/v1/setup", map[string]string{"code": "0123", "username": "ops", "password": "correct horse battery"}); r.code != 403 {
		t.Fatalf("wrong code: %d", r.code)
	}
	if r := e.do(e.c, "POST", "/api/v1/setup", map[string]string{"code": code, "username": "ops", "password": "short"}); r.code != 400 {
		t.Fatalf("short password: %d", r.code)
	}
	e.setup()
	if _, err := os.Stat(filepath.Join(e.dir, "secrets", "setup-code")); !os.IsNotExist(err) {
		t.Fatal("setup code left behind")
	}
	acc, _ := os.ReadFile(filepath.Join(e.dir, "secrets", "admin.json"))
	if !strings.Contains(string(acc), "$argon2id$v=19$") || strings.Contains(string(acc), "correct horse") {
		t.Fatalf("stored account: %s", acc)
	}
	if fi, _ := os.Stat(filepath.Join(e.dir, "secrets", "admin.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("account file mode %v", fi.Mode())
	}
	if r := e.do(e.c, "POST", "/api/v1/setup", map[string]string{"code": code, "username": "x", "password": "correct horse battery"}); r.code != 409 {
		t.Fatalf("second setup: %d", r.code)
	}

	// the session works; state-changing calls need the CSRF header
	if r := e.do(e.c, "GET", "/api/v1/status", nil); r.code != 200 || r.body["version"] != "test" {
		t.Fatalf("status: %d %s", r.code, r.raw)
	}
	csrf := e.csrf
	e.csrf = ""
	if r := e.do(e.c, "POST", "/api/v1/cache/clear", nil); r.code != 403 {
		t.Fatalf("without CSRF token: %d", r.code)
	}
	e.csrf = "wrong" + csrf[5:]
	if r := e.do(e.c, "POST", "/api/v1/cache/clear", nil); r.code != 403 {
		t.Fatalf("with a wrong CSRF token: %d", r.code)
	}
	e.csrf = csrf
	if r := e.do(e.c, "POST", "/api/v1/cache/clear", nil); r.code != 204 || e.b.cleared != 1 {
		t.Fatalf("clear cache: %d", r.code)
	}
	if r := e.do(e.c, "POST", "/api/v1/logout", nil); r.code != 204 {
		t.Fatalf("logout: %d", r.code)
	}
	if r := e.do(e.c, "GET", "/api/v1/session", nil); r.code != 401 {
		t.Fatalf("after logout: %d", r.code)
	}

	// five wrong passwords lock the address out for 15 minutes
	other := e.client()
	for i := 0; i < 5; i++ {
		if r := e.do(other, "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "wrong password!"}); r.code != 401 {
			t.Fatalf("wrong password %d: %d", i, r.code)
		}
	}
	r := e.do(other, "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "correct horse battery"})
	if r.code != 429 || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("locked out: %d %s", r.code, r.raw)
	}
	e.now = e.now.Add(16 * time.Minute)
	if r := e.do(other, "POST", "/api/v1/login", map[string]string{"username": "nobody", "password": "correct horse battery"}); r.code != 401 {
		t.Fatalf("wrong user: %d", r.code)
	}
	r = e.do(other, "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "correct horse battery"})
	if r.code != 200 || r.body["csrf"] == "" {
		t.Fatalf("login after the lock: %d %s", r.code, r.raw)
	}
	setCookie := r.hdr.Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Strict", "dnsnova_session="} {
		if !strings.Contains(setCookie, want) {
			t.Fatalf("cookie %q lacks %s", setCookie, want)
		}
	}
	// sessions expire after 12 idle hours
	e.now = e.now.Add(13 * time.Hour)
	if r := e.do(other, "GET", "/api/v1/session", nil); r.code != 401 {
		t.Fatalf("idle session: %d", r.code)
	}
}

func TestHostOriginAndContentType(t *testing.T) {
	e := newEnv(t)
	e.setup()
	for host, want := range map[string]int{"evil.example": 421, "dns.example.com": 200, "DNS.Example.com.:7000": 200, "localhost:7000": 200, "[::1]:7000": 200} {
		if r := e.do(e.c, "GET", "/api/v1/setup", nil, "Host", host); r.code != want {
			t.Fatalf("Host %s: %d, want %d", host, r.code, want)
		}
	}
	if r := e.do(e.c, "POST", "/api/v1/cache/clear", map[string]any{}, "Origin", "https://evil.example"); r.code != 403 {
		t.Fatalf("cross-origin: %d", r.code)
	}
	if r := e.do(e.c, "POST", "/api/v1/cache/clear", map[string]any{}, "Origin", e.srv.URL); r.code != 204 {
		t.Fatalf("same origin: %d %s", r.code, r.raw)
	}
	if r := e.do(e.c, "POST", "/api/v1/cache/clear", map[string]any{}, "Content-Type", "text/plain"); r.code != 415 {
		t.Fatalf("form body: %d", r.code)
	}
	if r := e.do(e.c, "POST", "/api/v1/login", map[string]any{"username": "ops", "password": "x", "extra": 1}); r.code != 400 {
		t.Fatalf("unknown field: %d", r.code)
	}
	r := e.do(e.c, "GET", "/api/v1/status", nil)
	for k, v := range map[string]string{"X-Frame-Options": "DENY", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"} {
		if r.hdr.Get(k) != v {
			t.Fatalf("%s: %q", k, r.hdr.Get(k))
		}
	}
	if r := e.do(e.c, "GET", "/api/v1/nope", nil); r.code != 404 {
		t.Fatalf("unknown endpoint: %d", r.code)
	}
}

func TestTOTP(t *testing.T) {
	e := newEnv(t)
	e.setup()
	r := e.do(e.c, "POST", "/api/v1/account/totp", nil)
	secret, _ := r.body["secret"].(string)
	if r.code != 200 || len(secret) != 32 || !strings.HasPrefix(r.body["uri"].(string), "otpauth://totp/DNSNova:ops?") {
		t.Fatalf("begin: %d %s", r.code, r.raw)
	}
	code := func(at time.Time) string { c, _ := totpAt(secret, uint64(at.Unix()/30)); return c }
	if r := e.do(e.c, "POST", "/api/v1/account/totp/confirm", map[string]string{"code": "000000"}); r.code != 400 {
		t.Fatalf("wrong code: %d", r.code)
	}
	if r := e.do(e.c, "POST", "/api/v1/account/totp/confirm", map[string]string{"code": code(e.now)}); r.code != 204 {
		t.Fatalf("confirm: %d %s", r.code, r.raw)
	}
	e.now = e.now.Add(time.Minute)

	other := e.client()
	r = e.do(other, "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "correct horse battery"})
	if r.code != 401 || r.body["totp_required"] != true {
		t.Fatalf("login without code: %d %s", r.code, r.raw)
	}
	cur := code(e.now)
	if r := e.do(other, "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "correct horse battery", "totp": cur}); r.code != 200 {
		t.Fatalf("login with code: %d %s", r.code, r.raw)
	}
	if r := e.do(e.client(), "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "correct horse battery", "totp": cur}); r.code != 401 {
		t.Fatalf("the same code twice: %d", r.code)
	}
	if r := e.do(e.c, "DELETE", "/api/v1/account/totp", map[string]string{"password": "wrong password!"}); r.code != 403 {
		t.Fatalf("disable with a wrong password: %d", r.code)
	}
	if r := e.do(e.c, "DELETE", "/api/v1/account/totp", map[string]string{"password": "correct horse battery"}); r.code != 204 {
		t.Fatalf("disable: %d", r.code)
	}
	if r := e.do(e.client(), "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "correct horse battery"}); r.code != 200 {
		t.Fatalf("login after disabling: %d", r.code)
	}
	// RFC 6238 test vector (SHA-1, T = 59 s): 94287082, last 6 digits
	if c, _ := totpAt(b32.EncodeToString([]byte("12345678901234567890")), 1); c != "287082" {
		t.Fatalf("RFC 6238 vector: %s", c)
	}
}

func TestPasswordChangeLogsOthersOut(t *testing.T) {
	e := newEnv(t)
	e.setup()
	other := e.client()
	if r := e.do(other, "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "correct horse battery"}); r.code != 200 {
		t.Fatal(r.raw)
	}
	if r := e.do(e.c, "POST", "/api/v1/account/password", map[string]string{"current": "nope nope nope", "new": "another long password"}); r.code != 403 {
		t.Fatalf("wrong current password: %d", r.code)
	}
	if r := e.do(e.c, "POST", "/api/v1/account/password", map[string]string{"current": "correct horse battery", "new": "another long password"}); r.code != 204 {
		t.Fatalf("change: %d %s", r.code, r.raw)
	}
	if r := e.do(other, "GET", "/api/v1/session", nil); r.code != 401 {
		t.Fatalf("other session survived: %d", r.code)
	}
	if r := e.do(e.c, "GET", "/api/v1/session", nil); r.code != 200 {
		t.Fatalf("own session: %d", r.code)
	}
	if r := e.do(e.client(), "POST", "/api/v1/login", map[string]string{"username": "ops", "password": "another long password"}); r.code != 200 {
		t.Fatalf("new password: %d", r.code)
	}
}

func TestConfigEditing(t *testing.T) {
	e := newEnv(t)
	e.setup()
	r := e.do(e.c, "GET", "/api/v1/config", nil)
	hash, _ := r.body["hash"].(string)
	if r.code != 200 || hash == "" {
		t.Fatalf("config: %d %s", r.code, r.raw)
	}
	byKey := map[string]map[string]any{}
	for _, s := range r.body["settings"].([]any) {
		m := s.(map[string]any)
		byKey[m["key"].(string)] = m
	}
	if m := byKey["server.mode"]; m["value"] != "public" || m["in_file"] != true || m["line"].(float64) != 3 {
		t.Fatalf("server.mode: %v", m)
	}
	if m := byKey["upstream.timeout"]; m["value"] != "3s" || m["in_file"] != false {
		t.Fatalf("a default: %v", m)
	}

	edit := map[string]any{"hash": hash, "set": map[string]any{"metrics.listen": "127.0.0.1:9153", "server.mode": "private", "access.allow": []string{"10.0.0.0/8"}, "limits.client_qps": 12.5}}
	r = e.do(e.c, "POST", "/api/v1/config/preview", edit)
	if r.code != 200 || len(r.body["changes"].([]any)) != 4 {
		t.Fatalf("preview: %d %s", r.code, r.raw)
	}
	if !strings.Contains(r.raw, `"text": "mode = \"private\"  # who may query"`) || !strings.Contains(r.raw, `"op": "+"`) {
		t.Fatalf("preview diff keeps the comment: %s", r.raw)
	}
	if cur, _ := os.ReadFile(e.b.store.Path); strings.Contains(string(cur), "private") {
		t.Fatal("preview wrote the file")
	}

	if r := e.do(e.c, "PATCH", "/api/v1/config", map[string]any{"hash": "stale", "set": map[string]any{"server.mode": "private"}}); r.code != 409 || r.body["hash"] != hash {
		t.Fatalf("stale hash: %d %s", r.code, r.raw)
	}
	r = e.do(e.c, "PATCH", "/api/v1/config", map[string]any{"hash": hash, "set": map[string]any{"server.mode": "privat"}})
	if r.code != 422 || !strings.Contains(r.raw, `"key": "server.mode"`) || !strings.Contains(r.raw, `"line": 3`) {
		t.Fatalf("invalid value: %d %s", r.code, r.raw)
	}
	if r := e.do(e.c, "PATCH", "/api/v1/config", map[string]any{"hash": hash, "set": map[string]any{"server.nope": 1}}); r.code != 400 {
		t.Fatalf("unknown key: %d", r.code)
	}
	if r := e.do(e.c, "PATCH", "/api/v1/config", map[string]any{"hash": hash, "set": map[string]any{"server.listen": []any{"a", 1}}}); r.code != 400 {
		t.Fatalf("mixed array: %d", r.code)
	}

	r = e.do(e.c, "PATCH", "/api/v1/config", edit)
	if r.code != 200 || r.body["hash"] == hash {
		t.Fatalf("patch: %d %s", r.code, r.raw)
	}
	hash2 := r.body["hash"].(string)
	file, _ := os.ReadFile(e.b.store.Path)
	for _, want := range []string{"# DNSNova test configuration", `mode = "private"  # who may query`, "[metrics]\nlisten = \"127.0.0.1:9153\"", "client_qps = 12.5", "allow = [\"10.0.0.0/8\"]"} {
		if !strings.Contains(string(file), want) {
			t.Fatalf("file lacks %q:\n%s", want, file)
		}
	}

	// unset puts the default back
	r = e.do(e.c, "PATCH", "/api/v1/config", map[string]any{"hash": hash2, "unset": []string{"limits.client_qps"}})
	if r.code != 200 || !strings.Contains(r.raw, `"key": "limits.client_qps"`) {
		t.Fatalf("unset: %d %s", r.code, r.raw)
	}
	hash3 := r.body["hash"].(string)

	// a change that cannot be applied leaves the file as it was
	e.b.failApply = errors.New("listen udp 127.0.0.1:5353: address already in use")
	r = e.do(e.c, "PATCH", "/api/v1/config", map[string]any{"hash": hash3, "set": map[string]any{"server.listen": []string{"127.0.0.1:53", "127.0.0.1:5353"}}})
	if r.code != 422 || r.body["reverted"] != true {
		t.Fatalf("failed apply: %d %s", r.code, r.raw)
	}
	if cur, _ := os.ReadFile(e.b.store.Path); config.HashOf(cur) != hash3 {
		t.Fatal("the file was not restored")
	}
	e.b.failApply = nil

	// history: restore the original file
	r = e.do(e.c, "GET", "/api/v1/config/history", nil)
	versions := r.body["versions"].([]any)
	if r.code != 200 || len(versions) < 3 {
		t.Fatalf("history: %d %s", r.code, r.raw)
	}
	oldest := versions[len(versions)-1].(map[string]any)["name"].(string)
	if r := e.do(e.c, "GET", "/api/v1/config/history/"+oldest, nil); r.code != 200 || !strings.Contains(r.body["content"].(string), `mode = "public"`) {
		t.Fatalf("history file: %d %s", r.code, r.raw)
	}
	if r := e.do(e.c, "GET", "/api/v1/config/history/..%2fdnsnova.toml", nil); r.code != 404 {
		t.Fatalf("path traversal: %d", r.code)
	}
	cur := e.b.Snapshot().Hash
	r = e.do(e.c, "POST", "/api/v1/config/history/"+oldest+"/restore", map[string]string{"hash": cur})
	if r.code != 200 {
		t.Fatalf("restore: %d %s", r.code, r.raw)
	}
	if e.b.Snapshot().Config.Server.Mode != "public" {
		t.Fatal("restore did not apply")
	}

	// whole-file editing
	r = e.do(e.c, "GET", "/api/v1/config/file", nil)
	content := r.body["content"].(string)
	h := r.body["hash"].(string)
	r = e.do(e.c, "PUT", "/api/v1/config/file", map[string]any{"hash": h, "content": content + "\n[cache]\nsize = 5000\n", "preview": true})
	if r.code != 200 || !strings.Contains(r.raw, `"key": "cache.size"`) {
		t.Fatalf("file preview: %d %s", r.code, r.raw)
	}
	if r := e.do(e.c, "PUT", "/api/v1/config/file", map[string]any{"hash": h, "content": "[server\n"}); r.code != 422 || !strings.Contains(r.raw, `"line": 1`) {
		t.Fatalf("broken file: %d %s", r.code, r.raw)
	}
	if r := e.do(e.c, "PUT", "/api/v1/config/file", map[string]any{"hash": h, "content": content + "\n[cache]\nsize = 5000\n"}); r.code != 200 || e.b.Snapshot().Config.Cache.Size != 5000 {
		t.Fatalf("file write: %d %s", r.code, r.raw)
	}
}

func TestToolsEndpoints(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if r := e.do(e.c, "GET", "/api/v1/system/addresses", nil); r.code != 200 || !strings.Contains(r.raw, "192.0.2.10") {
		t.Fatalf("addresses: %d %s", r.code, r.raw)
	}
	r := e.do(e.c, "POST", "/api/v1/tools/lookup", map[string]any{"name": "Example.COM.", "type": "aaaa", "upstreams": []string{"tls://9.9.9.9"}})
	if r.code != 200 || r.body["name"] != "example.com." || !strings.Contains(r.raw, `\"\\aexample\\x03com\" 28`) || !strings.Contains(r.raw, "tls://9.9.9.9") {
		t.Fatalf("lookup: %d %s", r.code, r.raw)
	}
	for _, bad := range []map[string]any{{"name": "a..b"}, {"name": "exa mple.com"}, {"name": "example.com", "type": "AXFR"}, {"name": ""}} {
		if r := e.do(e.c, "POST", "/api/v1/tools/lookup", bad); r.code != 400 {
			t.Fatalf("%v: %d", bad, r.code)
		}
	}
}

func TestLineDiff(t *testing.T) {
	old := "a\nb\nc\nd\ne\nf\ng\nh\n"
	d := lineDiff([]byte(old), []byte("a\nb\nc\nD\ne\nf\ng\nh\ni\n"))
	var got []string
	for _, l := range d {
		got = append(got, l.Op+l.Text)
	}
	want := " b, c,-d,+D, e, f, g, h,+i"
	if strings.Join(got, ",") != want {
		t.Fatalf("diff:\n%s\nwant\n%s", strings.Join(got, ","), want)
	}
	if len(lineDiff([]byte(old), []byte(old))) != 0 {
		t.Fatal("no change, no lines")
	}
}

func TestWebInterface(t *testing.T) {
	e := newEnv(t)
	r := e.do(e.c, "GET", "/", nil)
	if r.code != 200 || !strings.Contains(r.raw, `src="/assets/app.js"`) {
		t.Fatalf("GET /: %d %.200s", r.code, r.raw)
	}
	csp := r.hdr.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP allows inline code: %q", csp)
	}
	for path, ctype := range map[string]string{
		"/assets/app.js":   "javascript",
		"/assets/app.css":  "text/css",
		"/assets/theme.js": "javascript",
		"/assets/logo.svg": "image/svg+xml",
	} {
		r := e.do(e.c, "GET", path, nil)
		if r.code != 200 || !strings.Contains(r.hdr.Get("Content-Type"), ctype) {
			t.Errorf("GET %s: %d %s", path, r.code, r.hdr.Get("Content-Type"))
		}
	}
	for _, path := range []string{"/assets/", "/assets/index.html", "/assets/nope.js", "/index.html"} {
		if r := e.do(e.c, "GET", path, nil); r.code == 200 {
			t.Errorf("GET %s: want an error, got 200", path)
		}
	}
	// The page carries no inline script or style the CSP would block.
	if strings.Contains(r.raw, "<script>") || strings.Contains(r.raw, "style=") {
		t.Error("index.html has inline script or style")
	}
}

func TestQueryLogEndpoints(t *testing.T) {
	e := newEnv(t)
	e.setup()
	if r := e.do(e.c, "GET", "/api/v1/status", nil); r.body["privacy"].(map[string]any)["query_log"] != false {
		t.Fatalf("status: %s", r.raw)
	}
	if r := e.do(e.c, "GET", "/api/v1/stats?range=24h", nil); r.body["top_domains"].([]any)[0].(map[string]any)["name"] != "example.com" || r.body["from"] == nil {
		t.Fatalf("stats: %s", r.raw)
	}
	if r := e.do(e.c, "POST", "/api/v1/querylog", map[string]any{"minutes": 7}); r.code != 400 {
		t.Fatalf("odd length accepted: %d", r.code)
	}
	r := e.do(e.c, "POST", "/api/v1/querylog", map[string]any{"minutes": 15})
	if r.code != 200 || r.body["state"].(map[string]any)["on"] != true {
		t.Fatalf("start: %d %s", r.code, r.raw)
	}
	e.b.qlog.Add(insight.Query{Time: e.now, Name: "a.example"}, netip.MustParseAddr("203.0.113.9"))
	r = e.do(e.c, "GET", "/api/v1/querylog?q=a.ex", nil)
	if en := r.body["entries"].([]any); len(en) != 1 || en[0].(map[string]any)["client"] != "203.0.113.x" {
		t.Fatalf("entries: %s", r.raw)
	}
	if r := e.do(e.c, "GET", "/api/v1/status", nil); r.body["privacy"].(map[string]any)["query_log"] != true {
		t.Fatalf("status while on: %s", r.raw)
	}
	if r := e.do(e.c, "DELETE", "/api/v1/querylog", nil); r.code != 204 {
		t.Fatalf("stop: %d", r.code)
	}
	if r := e.do(e.c, "GET", "/api/v1/querylog", nil); len(r.body["entries"].([]any)) != 0 {
		t.Fatalf("after stop: %s", r.raw)
	}
	// Without a session nothing is shown.
	if r := e.do(e.client(), "GET", "/api/v1/querylog", nil); r.code != 401 {
		t.Fatalf("anonymous: %d", r.code)
	}
}
