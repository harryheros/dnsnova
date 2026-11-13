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
	"github.com/harryheros/dnsnova/internal/alert"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/events"
	"github.com/harryheros/dnsnova/internal/filter"
	"github.com/harryheros/dnsnova/internal/insight"
	"github.com/harryheros/dnsnova/internal/recursor"
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
	// Guide describes the server for the setup guide.
	Guide() GuideInfo
	// ClearStats forgets the statistics and the domain lists.
	ClearStats()
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
	// FilterStatus describes the filtered service's lists; UpdateFilter
	// downloads them now.
	FilterStatus() filter.Status
	UpdateFilter(ctx context.Context)
	// FilterWhy says which lists block or allow name (wire format).
	FilterWhy(name string) filter.Why
	// RecursionStatus describes resolving from the root servers.
	RecursionStatus() Recursion
	// Cluster describes this node's place in a cluster (Role "" alone).
	Cluster() Cluster
	// Trace resolves name (wire format) and type from scratch and records
	// each step.
	Trace(ctx context.Context, name string, qtype uint16) *recursor.TraceResult
	// DNSSEC describes validation: counts, failures, negative trust anchors.
	DNSSEC() DNSSEC
	// ClearDNSSECFailures forgets the failures listed.
	ClearDNSSECFailures()
	// Alerts describes notifications: where they go (never the secrets),
	// what is wrong now, what was sent.
	Alerts() Alerts
	// SetAlertDestination sets where notifications go (empty: nowhere).
	SetAlertDestination(name string, fields map[string]string) error
	// TestAlerts sends a test notification to every destination now.
	TestAlerts(ctx context.Context) (map[string]string, error)
}

// Alerts is the state of notifications, for the Alerts page.
type Alerts struct {
	Enabled bool   `json:"enabled"`
	Role    string `json:"role"` // the cluster role: a follower's primary notifies for it
	// Destinations: whether each is set up, and a hint (never the secret)
	Destinations map[string]alert.Shown `json:"destinations"`
	Channels     []string               `json:"channels"` // in use
	Active       []alert.Active         `json:"active"`
	History      []alert.Sent           `json:"history"`
}

// DNSSEC is the state of validation, for the DNSSEC page.
type DNSSEC struct {
	Recursion bool               `json:"recursion"` // resolving from the root servers
	Enabled   bool               `json:"enabled"`   // validating
	Secure    int64              `json:"secure"`    // answers by result, since start
	Insecure  int64              `json:"insecure"`
	Bogus     int64              `json:"bogus"`
	Failures  []recursor.Failure `json:"failures"`
	NTAs      []string           `json:"negative_trust_anchors"`
}

// Cluster is this node's view of its cluster.
type Cluster struct {
	Role   string `json:"role"` // "", "primary" or "follower"
	Name   string `json:"name"`
	Region string `json:"region,omitempty"`
	// Follower: the primary's address and name, the last sync and its
	// outcome.
	Primary     string    `json:"primary,omitempty"`
	PrimaryName string    `json:"primary_name,omitempty"`
	LastSync    time.Time `json:"last_sync,omitzero"`
	SyncError   string    `json:"sync_error,omitempty"`
	ConfigHash  string    `json:"config_hash,omitempty"` // of the shared configuration
	Overrides   []string  `json:"overrides,omitempty"`
	// Primary: every node, itself first.
	Nodes []Node `json:"nodes,omitempty"`
}

// Node is one node as its primary last heard of it.
type Node struct {
	Name        string    `json:"name"`
	Region      string    `json:"region,omitempty"`
	Address     string    `json:"address,omitempty"`
	Self        bool      `json:"self,omitempty"`
	Online      bool      `json:"online"`
	LastSeen    time.Time `json:"last_seen,omitzero"`
	Version     string    `json:"version"`
	Status      string    `json:"status"` // ok, unhealthy, setup
	Anycast     string    `json:"anycast,omitempty"`
	InSync      bool      `json:"in_sync"` // runs the current shared configuration
	ConfigError string    `json:"config_error,omitempty"`
	CertUntil   time.Time `json:"cert_until,omitzero"`
	Uptime      int64     `json:"uptime_seconds"`
	Overrides   []string  `json:"overrides,omitempty"`
}

// Recursion is the state of resolving from the root servers.
type Recursion struct {
	Enabled           bool           `json:"enabled"`
	DNSSEC            bool           `json:"dnssec"`
	QNameMinimisation bool           `json:"qname_minimisation"`
	Fallback          bool           `json:"fallback"` // upstreams are asked when no authoritative server answers
	Healthy           bool           `json:"healthy"`
	Queries           int64          `json:"queries"` // sent to authoritative servers
	Timeouts          int64          `json:"timeouts"`
	TCP               int64          `json:"tcp"`
	Secure            int64          `json:"secure"` // answers by DNSSEC result
	Insecure          int64          `json:"insecure"`
	Bogus             int64          `json:"bogus"`
	Fallbacks         int64          `json:"fallbacks"`
	Spoofed           int64          `json:"spoofed"`     // queries that drew forged answers and were asked again over TCP
	Forged            int64          `json:"forged"`      // UDP answers dropped as forged by a censor on the path
	Rewritten         int64          `json:"rewritten"`   // answers no name server sends: the network answers for them
	Intercepted       bool           `json:"intercepted"` // the network answers DNS in place of the name servers now
	Cache             map[string]int `json:"cache"`
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
	setupFails atomic.Int32 // wrong setup codes since the code was made
	setupMu    sync.Mutex   // one administrator, even if two setups race
	b          Backend
	log        *slog.Logger
	sec        *secrets
	sess       sessions
	lock       lockout
	mux        *http.ServeMux

	// Now is the clock (tests).
	Now func() time.Time

	totpMu   sync.Mutex
	totpLast uint64 // last accepted TOTP counter: a code works once

	traceMu sync.Mutex // one trace at a time: each asks dozens of servers
}

// New opens the account store under dataDir. When no administrator exists
// yet it creates the one-time setup code (see SetupCode).
func New(b Backend, dataDir string, log *slog.Logger) (*Admin, error) {
	sec, err := openSecrets(dataDir)
	if err != nil {
		return nil, err
	}
	a := &Admin{b: b, log: log, sec: sec, Now: time.Now}
	if sec.dropLegacyTrust() {
		log.Warn("security: removed " + sec.dir + "/setup-trust from an earlier installer; setup without the code now works only on this server itself (or through an SSH tunnel)")
	}
	if code, err := sec.setupCode(); err != nil {
		return nil, err
	} else if code != "" {
		log.Info("admin: no administrator yet; finish setup with the code in " + sec.dir + "/setup-code")
	}
	a.routes()
	return a, nil
}

// SetupCode returns the one-time setup code, or "" once setup is done.
// setupFailLimit is how many wrong setup codes, from any address, replace
// the code with a new one.
const setupFailLimit = 20

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
	m.Handle("POST /api/v1/stats/clear", auth(a.clearStats))
	m.Handle("GET /api/v1/guide", auth(func(w http.ResponseWriter, r *http.Request, c *call) { writeJSON(w, http.StatusOK, a.b.Guide()) }))
	m.Handle("GET /api/v1/querylog", auth(a.getQueryLog))
	m.Handle("POST /api/v1/querylog", auth(a.startQueryLog))
	m.Handle("DELETE /api/v1/querylog", auth(a.stopQueryLog))
	m.Handle("GET /api/v1/system/addresses", auth(a.addresses))
	m.Handle("GET /api/v1/cluster", auth(func(w http.ResponseWriter, r *http.Request, c *call) { writeJSON(w, http.StatusOK, a.b.Cluster()) }))
	m.Handle("POST /api/v1/tools/lookup", auth(a.lookup))
	m.Handle("POST /api/v1/tools/trace", auth(a.trace))
	m.Handle("GET /api/v1/dnssec", auth(func(w http.ResponseWriter, r *http.Request, c *call) { writeJSON(w, http.StatusOK, a.b.DNSSEC()) }))
	m.Handle("DELETE /api/v1/dnssec/failures", auth(func(w http.ResponseWriter, r *http.Request, c *call) {
		a.b.ClearDNSSECFailures()
		writeJSON(w, http.StatusOK, a.b.DNSSEC())
	}))
	m.Handle("GET /api/v1/alerts", auth(func(w http.ResponseWriter, r *http.Request, c *call) { writeJSON(w, http.StatusOK, a.b.Alerts()) }))
	m.Handle("PUT /api/v1/alerts/destinations/{name}", auth(a.putAlertDestination))
	m.Handle("POST /api/v1/alerts/test", auth(func(w http.ResponseWriter, r *http.Request, c *call) {
		res, err := a.b.TestAlerts(r.Context())
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": res})
	}))
	m.Handle("POST /api/v1/filter/why", auth(func(w http.ResponseWriter, r *http.Request, c *call) {
		var req struct {
			Name string `json:"name"`
		}
		if !decode(w, r, 4<<10, &req) {
			return
		}
		wire, err := wireName(req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, a.b.FilterWhy(wire))
	}))
	m.Handle("POST /api/v1/filter/update", auth(func(w http.ResponseWriter, r *http.Request, c *call) {
		a.b.UpdateFilter(r.Context())
		a.log.Info("admin: filter lists updated by hand", "from", c.ip.String())
		writeJSON(w, http.StatusOK, a.b.FilterStatus())
	}))

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
	// proxied: the request came through a reverse proxy, so ip is the
	// proxy's address (often 127.0.0.1), not the visitor's.
	proxied bool
}

func clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// viaProxy reports whether a reverse proxy forwarded the request. Such a
// request may come from anywhere on the internet even though the connection
// is from the server itself, so it is never trusted as local.
func viaProxy(r *http.Request) bool {
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Real-Ip", "X-Forwarded-Host", "X-Forwarded-Proto", "Via"} {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// Local reports whether the request comes from this machine itself: a
// loopback connection (an SSH tunnel ends there too) that no reverse proxy
// forwarded.
func Local(r *http.Request) bool { return clientIP(r).IsLoopback() && !viaProxy(r) }

// ForwardedHTTPS reports whether a reverse proxy on this machine forwarded
// the request and says the visitor reached it over HTTPS (X-Forwarded-Proto
// or Forwarded proto=, the value the nearest proxy added, which is the
// last). Only a loopback connection is believed: anyone else could send the
// header. Every such header present must say https.
func ForwardedHTTPS(r *http.Request) bool {
	if !clientIP(r).IsLoopback() {
		return false
	}
	seen := false
	if v := lastListItem(r.Header.Values("X-Forwarded-Proto")); v != "" {
		if !strings.EqualFold(v, "https") {
			return false
		}
		seen = true
	}
	if v := lastListItem(r.Header.Values("Forwarded")); v != "" {
		proto := ""
		for _, pair := range strings.Split(v, ";") {
			if k, val, ok := strings.Cut(strings.TrimSpace(pair), "="); ok && strings.EqualFold(k, "proto") {
				proto = strings.Trim(val, `"`)
			}
		}
		if !strings.EqualFold(proto, "https") {
			return false
		}
		seen = true
	}
	return seen
}

// lastListItem is the last element of a comma-separated header, over all
// its lines.
func lastListItem(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	items := strings.Split(vals[len(vals)-1], ",")
	return strings.TrimSpace(items[len(items)-1])
}

// secureConn reports whether the browser's connection is encrypted: HTTPS
// to this server, or to a reverse proxy on this machine that says so.
func secureConn(r *http.Request) bool { return r.TLS != nil || ForwardedHTTPS(r) }

func newCall(r *http.Request) *call { return &call{ip: clientIP(r), proxied: viaProxy(r)} }

// trusted reports whether this request may create the administrator
// without the setup code: from the server itself, or, on a server installed
// for a home or office network, from that network (see lanAddr). On a
// public server everyone else gives the code, which only someone with a
// shell on the server can read: there, a private address says nothing about
// who is on the other end (a cloud network, a carrier-grade NAT).
func (a *Admin) trusted(c *call) bool {
	return !c.proxied && (a.sec.setupTrusted(c.ip) || (trustLocalSetup && a.lanAddr(c.ip)))
}

// cgnat is the shared address space of RFC 6598, used by carrier-grade NAT
// and by VPNs such as Tailscale: never routed on the internet.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// NonPublic reports whether ip is never routed on the internet: private
// (RFC 1918, fc00::/7), link-local or shared (100.64.0.0/10).
func NonPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}

// lanAddr reports whether ip belongs to the network of a server installed
// for a home or office: server.mode = "private" (what the installer's --lan
// and the setup wizard's "My network" choose), ip among access.allow, and
// an address that is never routed on the internet, so it can only be
// someone on that network.
func (a *Admin) lanAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !NonPublic(ip) {
		return false
	}
	snap := a.b.Snapshot()
	if snap == nil || snap.Config.Server.Mode != config.ModePrivate {
		return false
	}
	for _, p := range snap.Config.Access.Allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// LAN reports whether r comes straight (no reverse proxy) from the network
// of a server installed for a home or office network. Such a server serves
// its admin interface there over plain HTTP: the network is the operator's
// own, and asking for a tunnel or a certificate at home helps no one.
func (a *Admin) LAN(r *http.Request) bool { return !viaProxy(r) && a.lanAddr(clientIP(r)) }

func safeMethod(m string) bool { return m == http.MethodGet || m == http.MethodHead }

// public serves a handler without a session. State-changing requests must
// still be same-origin JSON.
func (a *Admin) public(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !safeMethod(r.Method) && !sameOriginJSON(w, r) {
			return
		}
		h(w, r, newCall(r))
	})
}

// authed requires a session, and for state-changing requests the session's
// CSRF token in X-CSRF-Token.
func (a *Admin) authed(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := newCall(r)
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
		HttpOnly: true, Secure: secureConn(r), SameSite: http.SameSiteStrictMode,
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

// putAlertDestination sets one destination of notifications. The fields
// are write-only: nothing gives them back.
func (a *Admin) putAlertDestination(w http.ResponseWriter, r *http.Request, c *call) {
	name := r.PathValue("name")
	if !slices.Contains(alert.Names, name) {
		writeError(w, http.StatusNotFound, "no such destination")
		return
	}
	var f map[string]string
	if !decode(w, r, 8<<10, &f) {
		return
	}
	if err := a.b.SetAlertDestination(name, f); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	what := "set"
	if strings.TrimSpace(strings.Join(slices.Collect(maps.Values(f)), "")) == "" {
		what = "removed"
	}
	a.log.Info("admin: alert destination "+what, "destination", name, "from", c.ip.String())
	writeJSON(w, http.StatusOK, a.b.Alerts())
}
