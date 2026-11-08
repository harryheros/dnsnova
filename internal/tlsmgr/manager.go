// Package tlsmgr provides the TLS certificate for DNS over TLS and DNS over
// HTTPS: issued and renewed automatically through ACME (Let's Encrypt), or
// loaded from files that another program manages.
package tlsmgr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Certificate sources.
const (
	ModeOff   = "off"
	ModeACME  = "acme"
	ModeFiles = "files"
)

// Challenge types.
const (
	HTTP01    = "http-01"
	TLSALPN01 = "tls-alpn-01"
)

// Settings describe where the certificate comes from.
type Settings struct {
	Mode       string
	Domains    []string     // DNS names to certify (ACME)
	IPs        []netip.Addr // IP addresses to certify (ACME; needed for DDR)
	Email      string
	Directory  string // ACME directory URL
	Challenge  string // http-01 or tls-alpn-01
	HTTPListen string // where to answer http-01, e.g. ":80"
	CertFile   string // files mode
	KeyFile    string
}

func (s Settings) identifiers() []Identifier {
	var ids []Identifier
	for _, d := range s.Domains {
		ids = append(ids, Identifier{Type: "dns", Value: strings.ToLower(strings.TrimSuffix(d, "."))})
	}
	for _, a := range s.IPs {
		ids = append(ids, Identifier{Type: "ip", Value: a.Unmap().String()})
	}
	return ids
}

// Status describes the current certificate, for the admin API and logs.
type Status struct {
	Mode        string    `json:"mode"`
	Ready       bool      `json:"ready"`
	Names       []string  `json:"names,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`
}

// Manager keeps the current certificate. It is safe for concurrent use.
type Manager struct {
	Dir string // data directory: certificates and the ACME account
	Log *slog.Logger
	// HTTP is used to talk to the ACME server (tests set a custom one).
	HTTP *http.Client

	mu       sync.Mutex
	set      Settings
	status   Status
	backoff  time.Duration
	kick     chan struct{}
	fileMod  time.Time
	cur      atomic.Pointer[tls.Certificate]
	leaf     atomic.Pointer[x509.Certificate]
	issuing  atomic.Bool
	tokens   sync.Map // http-01 token -> key authorization
	alpn     sync.Map // server name -> *tls.Certificate
	now      func() time.Time
	pollTime time.Duration // ACME polling interval (tests)
}

// NewManager returns a manager that stores its data under dir.
func NewManager(dir string, log *slog.Logger) *Manager {
	return &Manager{Dir: dir, Log: log, kick: make(chan struct{}, 1), now: time.Now}
}

// Configure applies new settings. In files mode the files are loaded now and
// an error is returned if they are unusable; in ACME mode a stored
// certificate is loaded if it covers the requested names, and issuance or
// renewal happens in the background (see Run).
func (m *Manager) Configure(s Settings) error {
	if s.Challenge == "" {
		s.Challenge = HTTP01
	}
	if s.HTTPListen == "" {
		s.HTTPListen = ":80"
	}
	if s.Directory == "" {
		s.Directory = LetsEncrypt
	}
	m.mu.Lock()
	m.set = s
	m.status.Mode = s.Mode
	m.backoff = 0
	m.status.NextAttempt = time.Time{}
	m.mu.Unlock()

	switch s.Mode {
	case ModeOff, "":
		m.setCert(nil)
		return nil
	case ModeFiles:
		return m.loadFiles(true)
	case ModeACME:
		if len(s.identifiers()) == 0 {
			return errors.New("tls: acme needs at least one domain or IP address")
		}
		if c, err := m.loadStored(); err == nil && covers(c, s.identifiers()) {
			m.setCert(c)
		} else {
			m.setCert(nil)
		}
		select {
		case m.kick <- struct{}{}:
		default:
		}
		return nil
	}
	return fmt.Errorf("tls: unknown mode %q", s.Mode)
}

// Ready reports whether a certificate is available.
func (m *Manager) Ready() bool { return m.cur.Load() != nil }

// Status returns a snapshot of the certificate state.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.status
	st.Ready = m.cur.Load() != nil
	return st
}

func (m *Manager) setCert(c *tls.Certificate) {
	m.cur.Store(c)
	m.mu.Lock()
	defer m.mu.Unlock()
	if c == nil {
		m.leaf.Store(nil)
		m.status.Names, m.status.Issuer = nil, ""
		m.status.NotBefore, m.status.NotAfter = time.Time{}, time.Time{}
		return
	}
	leaf := c.Leaf
	m.leaf.Store(leaf)
	m.status.Names = certNames(leaf)
	m.status.Issuer = leaf.Issuer.CommonName
	m.status.NotBefore, m.status.NotAfter = leaf.NotBefore, leaf.NotAfter
}

func certNames(leaf *x509.Certificate) []string {
	names := slices.Clone(leaf.DNSNames)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}

// covers reports whether c is valid for exactly the requested identifiers.
func covers(c *tls.Certificate, ids []Identifier) bool {
	if c == nil || c.Leaf == nil {
		return false
	}
	have := map[string]bool{}
	for _, n := range c.Leaf.DNSNames {
		have["dns:"+strings.ToLower(n)] = true
	}
	for _, ip := range c.Leaf.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			have["ip:"+a.Unmap().String()] = true
		}
	}
	if len(have) != len(ids) {
		return false
	}
	for _, id := range ids {
		if !have[id.Type+":"+id.Value] {
			return false
		}
	}
	return true
}

// ---- serving ----

// TLSConfig returns a server configuration offering protos via ALPN. It
// serves the current certificate and answers tls-alpn-01 challenges.
// Session resumption works; 0-RTT is never accepted.
func (m *Manager) TLSConfig(protos ...string) *tls.Config {
	base := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     protos,
		GetCertificate: m.getCertificate,
	}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if !slices.Contains(hello.SupportedProtos, "acme-tls/1") {
			return nil, nil
		}
		v, ok := m.alpn.Load(strings.ToLower(strings.TrimSuffix(hello.ServerName, ".")))
		if !ok {
			return nil, errors.New("no pending tls-alpn-01 challenge for this name")
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"acme-tls/1"},
			Certificates: []tls.Certificate{*v.(*tls.Certificate)},
		}, nil
	}
	return base
}

var errNoCertificate = errors.New("no certificate available yet")

func (m *Manager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := m.cur.Load(); c != nil {
		return c, nil
	}
	return nil, errNoCertificate
}

// ServeHTTP answers http-01 challenges; anything else is 404.
func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	v, ok := m.tokens.Load(strings.TrimPrefix(r.URL.Path, prefix))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(v.(string)))
}

// Present implements Solver.
func (m *Manager) Present(chType string, id Identifier, token, keyAuth string) error {
	switch chType {
	case HTTP01:
		m.tokens.Store(token, keyAuth)
	case TLSALPN01:
		c, err := ALPNChallengeCert(id, keyAuth)
		if err != nil {
			return err
		}
		m.alpn.Store(ChallengeServerName(id), &tls.Certificate{Certificate: [][]byte{c.der}, PrivateKey: c.key})
	default:
		return fmt.Errorf("unsupported challenge %s", chType)
	}
	return nil
}

// CleanUp implements Solver.
func (m *Manager) CleanUp(chType string, id Identifier, token string) {
	m.tokens.Delete(token)
	m.alpn.Delete(ChallengeServerName(id))
}

// ---- background work ----

// Run issues and renews ACME certificates and reloads changed files until
// ctx is done.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.kick:
		}
	}
}

func (m *Manager) tick(ctx context.Context) {
	m.mu.Lock()
	s := m.set
	next := m.status.NextAttempt
	m.mu.Unlock()
	switch s.Mode {
	case ModeFiles:
		if err := m.loadFiles(false); err != nil {
			m.Log.Error("tls: reloading certificate files failed; keeping the current certificate", "err", err)
		}
	case ModeACME:
		now := m.now()
		if !m.dueForRenewal(now, s) || now.Before(next) {
			return
		}
		if !m.issuing.CompareAndSwap(false, true) {
			return
		}
		defer m.issuing.Store(false)
		m.issue(ctx, s)
	}
}

// dueForRenewal: no certificate, the wrong names, or less than a third of
// its lifetime left (for a 6-day certificate, about 2 days).
func (m *Manager) dueForRenewal(now time.Time, s Settings) bool {
	c := m.cur.Load()
	if !covers(c, s.identifiers()) {
		return true
	}
	life := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)
	return now.After(c.Leaf.NotBefore.Add(life * 2 / 3))
}

func (m *Manager) issue(ctx context.Context, s Settings) {
	ids := s.identifiers()
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = id.Value
	}
	m.Log.Info("tls: requesting certificate", "names", strings.Join(names, ","), "challenge", s.Challenge)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	err := m.obtain(ctx, s, ids)
	m.mu.Lock()
	m.status.LastAttempt = m.now()
	if err != nil {
		if m.backoff == 0 {
			m.backoff = 10 * time.Minute
		} else {
			m.backoff = min(m.backoff*2, 6*time.Hour)
		}
		m.status.LastError = err.Error()
		m.status.NextAttempt = m.now().Add(m.backoff)
		next := m.status.NextAttempt
		m.mu.Unlock()
		m.Log.Error("tls: certificate request failed", "err", err, "retry_at", next.Format(time.RFC3339))
		return
	}
	m.backoff = 0
	m.status.LastError = ""
	m.status.NextAttempt = time.Time{}
	m.mu.Unlock()
	leaf := m.leaf.Load()
	m.Log.Info("tls: certificate installed", "names", strings.Join(certNames(leaf), ","), "expires", leaf.NotAfter.Format(time.RFC3339))
}

func (m *Manager) obtain(ctx context.Context, s Settings, ids []Identifier) error {
	key, kid, err := m.account(s.Directory)
	if err != nil {
		return err
	}
	c := &Client{Directory: s.Directory, Key: key, KID: kid, HTTP: m.HTTP, poll: m.pollTime}
	if err := c.Register(ctx, s.Email); err != nil {
		return err
	}
	if c.KID != kid {
		m.saveAccount(s.Directory, key, c.KID)
	}
	profile := ""
	if len(s.IPs) > 0 {
		ok, err := c.SupportsProfile(ctx, "shortlived")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("the ACME server does not offer the shortlived profile needed for IP address certificates")
		}
		profile = "shortlived"
	}
	if s.Challenge == HTTP01 {
		stop, err := m.startHTTP(s.HTTPListen)
		if err != nil {
			return fmt.Errorf("http-01 needs %s: %w (use challenge = \"tls-alpn-01\" or certificate files instead)", s.HTTPListen, err)
		}
		defer stop()
	}
	chain, certKey, err := c.Obtain(ctx, ids, profile, []string{s.Challenge}, m)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return fmt.Errorf("the issued certificate is unusable: %w", err)
	}
	if !covers(&cert, ids) {
		return errors.New("the issued certificate does not cover the requested names")
	}
	if err := m.store(chain, keyPEM); err != nil {
		return err
	}
	m.setCert(&cert)
	return nil
}

func (m *Manager) startHTTP(addr string) (func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: m, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	return func() { srv.Close() }, nil
}

// ---- storage ----

func (m *Manager) path(parts ...string) string {
	return filepath.Join(append([]string{m.Dir}, parts...)...)
}

type accountFile struct {
	Directory string `json:"directory"`
	KID       string `json:"kid"`
}

// account loads or creates the ACME account key for a directory.
func (m *Manager) account(dirURL string) (*ecdsa.PrivateKey, string, error) {
	if raw, err := os.ReadFile(m.path("acme", "account.key")); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, "", errors.New("acme account key is corrupt")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("acme account key: %w", err)
		}
		var af accountFile
		if raw, err := os.ReadFile(m.path("acme", "account.json")); err == nil {
			json.Unmarshal(raw, &af)
		}
		if af.Directory != dirURL {
			af.KID = "" // same key, different CA: register again
		}
		return key, af.KID, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	if err := m.saveAccount(dirURL, key, ""); err != nil {
		return nil, "", err
	}
	return key, "", nil
}

func (m *Manager) saveAccount(dirURL string, key *ecdsa.PrivateKey, kid string) error {
	if err := os.MkdirAll(m.path("acme"), 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(m.path("acme", "account.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	raw, _ := json.Marshal(accountFile{Directory: dirURL, KID: kid})
	return writeFile(m.path("acme", "account.json"), raw, 0o600)
}

func (m *Manager) store(chain, keyPEM []byte) error {
	if err := os.MkdirAll(m.path("certs"), 0o700); err != nil {
		return err
	}
	if err := writeFile(m.path("certs", "key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	return writeFile(m.path("certs", "cert.pem"), chain, 0o644)
}

func (m *Manager) loadStored() (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(m.path("certs", "cert.pem"), m.path("certs", "key.pem"))
	if err != nil {
		return nil, err
	}
	if m.now().After(c.Leaf.NotAfter) {
		return nil, errors.New("stored certificate has expired")
	}
	return &c, nil
}

// loadFiles loads cert and key files. With force false it only reloads when
// a file changed, so it can be called every minute.
func (m *Manager) loadFiles(force bool) error {
	m.mu.Lock()
	s := m.set
	last := m.fileMod
	m.mu.Unlock()
	mod := latestMod(s.CertFile, s.KeyFile)
	if !force && !mod.After(last) {
		return nil
	}
	c, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	if m.now().After(c.Leaf.NotAfter) {
		return fmt.Errorf("tls: %s expired on %s", s.CertFile, c.Leaf.NotAfter.Format(time.DateOnly))
	}
	m.mu.Lock()
	m.fileMod = mod
	m.mu.Unlock()
	m.setCert(&c)
	if !force {
		m.Log.Info("tls: certificate files reloaded", "expires", c.Leaf.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func latestMod(paths ...string) time.Time {
	var t time.Time
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.ModTime().After(t) {
			t = fi.ModTime()
		}
	}
	return t
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// PublicIPs returns the addresses in list that a public CA can reach:
// global unicast and not private.
func PublicIPs(list []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range list {
		a = a.Unmap()
		if a.IsGlobalUnicast() && !a.IsPrivate() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}
