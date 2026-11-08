// Package admin is DNSNova's management API (and, later, the web interface
// built on it). Every action the interface can take is an HTTP API call
// documented in docs/api.md, so scripts can do the same; the interface has no
// privileges of its own.
//
// Protection, in order: only Host headers that name this server are served
// (DNS rebinding), state-changing requests must be JSON with a matching
// Origin and, once logged in, an X-CSRF-Token header; sessions are random
// tokens in HttpOnly, SameSite=Strict cookies; passwords are Argon2id hashes;
// repeated failures lock the client out for a while; two-step verification
// (TOTP) is optional.
package admin

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/events"
	"github.com/harryheros/dnsnova/internal/insight"
	"github.com/harryheros/dnsnova/internal/stats"
	"github.com/harryheros/dnsnova/internal/tlsmgr"
)

// Backend is what the API reads and changes. The server implements it.
type Backend interface {
	Version() string
	Started() time.Time
	// Snapshot is the configuration in force.
	Snapshot() *config.Snapshot
	// ApplyConfig validates src, writes it if the file still has hash
	// expected, and applies it. If applying fails the previous file is put
	// back and the error is returned.
	ApplyConfig(src []byte, expected string) (*config.Snapshot, error)
	ConfigHistory() ([]config.HistoryEntry, error)
	ConfigHistoryFile(name string) ([]byte, error)
	Report(span time.Duration) stats.Report
	// Tops lists popular domains, domains that do not exist and networks
	// that hit the limits over span.
	Tops(span time.Duration) Tops
	// QueryLog is the in-memory query log.
	QueryLog() *insight.QueryLog
	Upstreams() []Upstream
	Certificate() tlsmgr.Status
	Events(limit int) []events.Event
	Cache() (positive, negative int)
	ClearCache()
	Listeners() map[string][]string
	// Addresses lists the host's IP addresses.
	Addresses() []HostAddress
	// Lookup asks each upstream (the configured ones when specs is empty)
	// for name (wire format) and type, bypassing the cache.
	Lookup(ctx context.Context, name string, qtype uint16, specs []string) []LookupResult
}

// Tops are the lists shown beside the statistics.
type Tops struct {
	Domains   []insight.Entry `json:"top_domains"`
	NXDomains []insight.Entry `json:"top_nxdomains"`
	Limited   []insight.Entry `json:"top_limited_networks"` // at most the last 24 hours
}

// HostAddress is one of the server's IP addresses.
type HostAddress struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Public    bool   `json:"public"`
	Loopback  bool   `json:"loopback"`
}

// LookupResult is one upstream's answer to a test query.
type LookupResult struct {
	Upstream string   `json:"upstream"`
	Rcode    string   `json:"rcode,omitempty"`
	Answers  []string `json:"answers,omitempty"`
	MS       float64  `json:"ms"`
	Error    string   `json:"error,omitempty"`
}

// Upstream is one upstream's health.
type Upstream struct {
	Address   string    `json:"address"`
	Role      string    `json:"role"` // primary or fallback
	Healthy   bool      `json:"healthy"`
	LatencyMS float64   `json:"latency_ms"`
	Queries   uint64    `json:"queries"`
	Errors    uint64    `json:"errors"`
	LastOK    time.Time `json:"last_ok,omitzero"`
	LastError time.Time `json:"last_error,omitzero"`
}

// Admin serves the API.
type Admin struct {
	b    Backend
	log  *slog.Logger
	sec  *secrets
	sess sessions
	lock lockout
	mux  *http.ServeMux

	// Now is the clock (tests).
	Now func() time.Time

	totpMu   sync.Mutex
	totpLast uint64 // last accepted TOTP counter: a code works once
}

// New opens the account store under dataDir. When no administrator exists
// yet it creates the one-time setup code (see SetupCode).
func New(b Backend, dataDir string, log *slog.Logger) (*Admin, error) {
	sec, err := openSecrets(dataDir)
	if err != nil {
		return nil, err
	}
	a := &Admin{b: b, log: log, sec: sec, Now: time.Now}
	if code, err := sec.setupCode(); err != nil {
		return nil, err
	} else if code != "" {
		log.Info("admin: no administrator yet; finish setup with the code in " + sec.dir + "/setup-code")
	}
	a.routes()
	return a, nil
}

// SetupCode returns the one-time setup code, or "" once setup is done.
func (a *Admin) SetupCode() string {
	c, _ := a.sec.setupCode()
	return c
}

func (a *Admin) routes() {
	m := http.NewServeMux()
	pub, auth := a.public, a.authed
	m.Handle("GET /api/v1/setup", pub(a.getSetup))
	m.Handle("POST /api/v1/setup", pub(a.postSetup))
	m.Handle("POST /api/v1/login", pub(a.login))
	m.Handle("POST /api/v1/logout", auth(a.logout))
	m.Handle("GET /api/v1/session", auth(a.getSession))

	m.Handle("GET /api/v1/status", auth(a.status))
	m.Handle("GET /api/v1/stats", auth(a.stats))
	m.Handle("GET /api/v1/upstreams", auth(a.upstreams))
	m.Handle("GET /api/v1/events", auth(a.events))
	m.Handle("POST /api/v1/cache/clear", auth(a.clearCache))
	m.Handle("GET /api/v1/querylog", auth(a.getQueryLog))
	m.Handle("POST /api/v1/querylog", auth(a.startQueryLog))
	m.Handle("DELETE /api/v1/querylog", auth(a.stopQueryLog))
	m.Handle("GET /api/v1/system/addresses", auth(a.addresses))
	m.Handle("POST /api/v1/tools/lookup", auth(a.lookup))

	m.Handle("GET /api/v1/config", auth(a.getConfig))
	m.Handle("POST /api/v1/config/preview", auth(a.previewConfig))
	m.Handle("PATCH /api/v1/config", auth(a.patchConfig))
	m.Handle("GET /api/v1/config/file", auth(a.getConfigFile))
	m.Handle("PUT /api/v1/config/file", auth(a.putConfigFile))
	m.Handle("GET /api/v1/config/history", auth(a.listHistory))
	m.Handle("GET /api/v1/config/history/{name}", auth(a.getHistory))
	m.Handle("POST /api/v1/config/history/{name}/restore", auth(a.restoreHistory))

	m.Handle("POST /api/v1/account/password", auth(a.changePassword))
	m.Handle("POST /api/v1/account/totp", auth(a.beginTOTP))
	m.Handle("POST /api/v1/account/totp/confirm", auth(a.confirmTOTP))
	m.Handle("DELETE /api/v1/account/totp", auth(a.disableTOTP))

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such API endpoint")
	})
	m.HandleFunc("GET /{$}", a.home)
	m.Handle("GET /assets/", a.assets())
	a.mux = m
}

// ServeHTTP checks the Host header and serves the API.
func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("Cache-Control", "no-store")
	if !a.allowedHost(r.Host) {
		writeError(w, http.StatusMisdirectedRequest, "unknown host name; open this page by its IP address or one of the configured domains")
		return
	}
	a.mux.ServeHTTP(w, r)
}

// allowedHost accepts IP literals, localhost and the configured domains. A
// name anyone could point at this server (DNS rebinding) is refused, so a
// web page elsewhere can never read this API through the victim's browser.
func (a *Admin) allowedHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil || host == "localhost" {
		return true
	}
	if snap := a.b.Snapshot(); snap != nil {
		for _, d := range snap.Config.TLS.Domains {
			if strings.EqualFold(strings.TrimSuffix(d, "."), host) {
				return true
			}
		}
	}
	return false
}

type handler func(w http.ResponseWriter, r *http.Request, c *call)

// call is one request's context.
type call struct {
	ip    netip.Addr
	sess  *session
	token string
}

func clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func safeMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// public serves a handler without a session. State-changing requests must
// still be same-origin JSON.
func (a *Admin) public(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !safeMethod(r.Method) && !sameOriginJSON(w, r) {
			return
		}
		h(w, r, &call{ip: clientIP(r)})
	})
}

// authed requires a session, and for state-changing requests the session's
// CSRF token in X-CSRF-Token.
func (a *Admin) authed(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := &call{ip: clientIP(r)}
		if ck, err := r.Cookie(cookieName); err == nil {
			c.token = ck.Value
			c.sess = a.sess.get(ck.Value, a.Now())
		}
		if c.sess == nil || a.sec.account() == nil {
			writeError(w, http.StatusUnauthorized, "log in first")
			return
		}
		if !safeMethod(r.Method) {
			if !sameOriginJSON(w, r) {
				return
			}
			got := r.Header.Get("X-CSRF-Token")
			if got == "" || !constEq(got, c.sess.csrf) {
				writeError(w, http.StatusForbidden, "missing or wrong X-CSRF-Token header")
				return
			}
		}
		h(w, r, c)
	})
}

// sameOriginJSON refuses bodies that are not JSON and requests whose Origin
// is another site. Browsers cannot send JSON across sites without a CORS
// preflight, which this server never approves.
func sameOriginJSON(w http.ResponseWriter, r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			writeError(w, http.StatusForbidden, "cross-origin request refused")
			return false
		}
	}
	if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
		mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mt != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "send the request body as application/json")
			return false
		}
	}
	return true
}

func constEq(a, b string) bool {
	return len(a) == len(b) && subtleEq(a, b)
}

// ---- JSON helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// decode reads a JSON body of at most limit bytes into v. Unknown fields are
// refused, so a typo is not silently ignored.
func decode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		msg := "invalid JSON: " + err.Error()
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			msg = "request body too large"
		} else if errors.Is(err, io.EOF) {
			msg = "empty request body"
		}
		writeError(w, http.StatusBadRequest, msg)
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON: more than one value")
		return false
	}
	return true
}

func (a *Admin) setCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

//go:embed ui
var uiFiles embed.FS

// home serves the web interface's page; the interface itself is plain
// JavaScript that calls this API.
func (a *Admin) home(w http.ResponseWriter, r *http.Request) {
	b, err := uiFiles.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "web interface missing from this build", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func (a *Admin) assets() http.Handler {
	sub, _ := fs.Sub(uiFiles, "ui")
	fsrv := http.StripPrefix("/assets/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") || strings.HasSuffix(r.URL.Path, ".html") {
			http.NotFound(w, r) // no directory listings; the page is served at /
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		fsrv.ServeHTTP(w, r)
	})
}
