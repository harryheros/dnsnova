// Package config loads, validates and edits the dnsnova configuration file.
package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harryheros/dnsnova/internal/upstream"
)

// Service modes.
const (
	ModePublic  = "public"  // anyone may query; abuse is handled by limits
	ModePrivate = "private" // only clients in access.allow may query
)

// Config is the validated configuration.
type Config struct {
	Server struct {
		Mode    string
		Listen  []string
		DataDir string
	}
	DoH struct {
		Listen         string   // plain HTTP behind a reverse proxy
		HTTPSListen    []string // built-in HTTPS (HTTP/1.1 and HTTP/2 over TCP)
		HTTP3          bool     // also serve HTTP/3 on the same addresses over UDP
		Path           string
		TrustedProxies []netip.Prefix
	}
	DoT struct {
		Listen []string
	}
	DoQ struct {
		Listen []string // DNS over QUIC (RFC 9250), UDP
	}
	TLS struct {
		Certificate         string // off, acme or files
		Domains             []string
		IPAddresses         bool // also certify the public addresses in server.listen (for DDR)
		Email               string
		Challenge           string // http-01 or tls-alpn-01; empty = chosen automatically
		HTTPChallengeListen string
		ACMEDirectory       string
		CertFile            string
		KeyFile             string
	}
	DDR struct {
		Enabled bool
	}
	Upstream struct {
		Primary       []string
		Fallback      []string
		Bootstrap     []string
		Parallel      int
		Timeout       time.Duration
		FallbackDelay time.Duration
	}
	Cache struct {
		Size           int
		MinTTL         uint32
		MaxTTL         uint32
		MaxNegativeTTL uint32
		ServeStale     time.Duration
		Prefetch       bool
	}
	Access struct {
		Allow []netip.Prefix
	}
	Limits struct {
		ClientQPS           float64
		ClientBurst         float64
		PrefixQPS           float64
		PrefixBurst         float64
		GlobalQPS           float64
		UpstreamConcurrency int
		ZoneConcurrency     int
		TCPConnections      int
		QUICConnections     int
		TCPPipeline         int
		TCPIdleTimeout      time.Duration
		UDPMaxSize          int
		RRLRate             float64
		RRLSlip             int
		BlockANY            bool
	}
	Metrics struct {
		Listen string
	}
	Admin struct {
		Listen string // web interface and API; "" = off
	}
	Status struct {
		Enabled bool // public status page on the DoH addresses
	}
	Log struct {
		Queries bool // no longer used: the query log runs from the admin interface, in memory
	}
}

// Defaults returns a Config with every optional setting at its default.
func Defaults() *Config {
	c := &Config{}
	c.Server.DataDir = "/var/lib/dnsnova"
	c.DoH.Path = "/dns-query"
	c.DoH.HTTP3 = true
	c.TLS.Certificate = "off"
	c.TLS.HTTPChallengeListen = ":80"
	c.TLS.ACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	c.DDR.Enabled = true
	c.DoH.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	c.Upstream.Bootstrap = []string{"1.1.1.1:53", "8.8.8.8:53"}
	c.Upstream.Parallel = 2
	c.Upstream.Timeout = 3 * time.Second
	c.Cache.Size = 100000
	c.Cache.MaxTTL = 86400
	c.Cache.MaxNegativeTTL = 3600
	c.Cache.ServeStale = 24 * time.Hour
	c.Cache.Prefetch = true
	c.Limits.ClientQPS = 50
	c.Limits.ClientBurst = 200
	c.Limits.PrefixQPS = 500
	c.Limits.PrefixBurst = 2000
	c.Limits.GlobalQPS = 50000
	c.Limits.UpstreamConcurrency = 2000
	c.Limits.ZoneConcurrency = 50
	c.Limits.TCPConnections = 1000
	c.Limits.QUICConnections = 1000
	c.Limits.TCPPipeline = 16
	c.Limits.TCPIdleTimeout = 10 * time.Second
	c.Limits.UDPMaxSize = 1232
	c.Limits.RRLRate = 20
	c.Limits.RRLSlip = 2
	c.Limits.BlockANY = true
	return c
}

// Error is a problem with one setting.
type Error struct {
	Line int    // 0 when the setting is missing from the file
	Key  string // table.key
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s: %s", e.Line, e.Key, e.Msg)
	}
	if e.Key != "" {
		return fmt.Sprintf("%s: %s", e.Key, e.Msg)
	}
	return e.Msg
}

// Errors is a list of problems found while loading.
type Errors []*Error

func (es Errors) Error() string {
	parts := make([]string, len(es))
	for i, e := range es {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "\n")
}

// Load parses and validates src. It returns all problems at once, each with
// its line number. Warnings are returned for settings that are valid but
// probably not what the user meant.
func Load(src []byte) (cfg *Config, doc *Document, warnings []string, err error) {
	doc, err = Parse(src)
	if err != nil {
		return nil, nil, nil, err
	}
	cfg = Defaults()
	var errs Errors
	lines := map[string]int{}
	for _, e := range doc.Entries {
		name := e.Key
		if e.Table != "" {
			name = e.Table + "." + e.Key
		}
		lines[name] = e.Line
		f, ok := fields[name]
		if !ok {
			errs = append(errs, &Error{Line: e.Line, Key: name, Msg: "unknown setting" + suggest(name)})
			continue
		}
		if err := f.set(cfg, e.Value); err != nil {
			errs = append(errs, &Error{Line: e.Line, Key: name, Msg: err.Error()})
		}
	}
	for _, t := range doc.Tables {
		if !knownTables[t.Name] {
			errs = append(errs, &Error{Line: t.Line, Key: "[" + t.Name + "]", Msg: "unknown table"})
		}
	}
	// Validate the rest too, so every problem is reported in one pass; skip
	// settings that already failed to decode (they hold defaults).
	failed := map[string]bool{}
	for _, e := range errs {
		failed[e.Key] = true
	}
	verrs, warnings := cfg.validate(lines)
	for _, e := range verrs {
		if !failed[e.Key] {
			errs = append(errs, e)
		}
	}
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Line < errs[j].Line })
	if len(errs) > 0 {
		return nil, doc, warnings, errs
	}
	return cfg, doc, warnings, nil
}

func (c *Config) validate(lines map[string]int) (Errors, []string) {
	var errs Errors
	var warns []string
	bad := func(key, msg string) { errs = append(errs, &Error{Line: lines[key], Key: key, Msg: msg}) }

	switch c.Server.Mode {
	case ModePublic, ModePrivate:
	case "":
		bad("server.mode", `required: "public" or "private"`)
	default:
		bad("server.mode", fmt.Sprintf(`must be "public" or "private", got %q`, c.Server.Mode))
	}
	if len(c.Server.Listen) == 0 && c.DoH.Listen == "" && len(c.DoH.HTTPSListen) == 0 && len(c.DoT.Listen) == 0 && len(c.DoQ.Listen) == 0 {
		bad("server.listen", "nothing to listen on: set server.listen, dot.listen, doq.listen or doh.https_listen")
	}
	if !strings.HasPrefix(c.Server.DataDir, "/") {
		bad("server.data_dir", "must be an absolute path")
	}
	for _, a := range c.Server.Listen {
		if err := checkListen(a); err != nil {
			bad("server.listen", err.Error())
		} else if strings.HasPrefix(a, ":") || strings.HasPrefix(a, "0.0.0.0:") || strings.HasPrefix(a, "[::]:") {
			warns = append(warns, fmt.Sprintf("server.listen %q listens on all addresses; on hosts with several IPs, list each address so UDP replies leave from the address they were sent to", a))
		}
	}
	if c.DoH.Listen != "" {
		if err := checkListen(c.DoH.Listen); err != nil {
			bad("doh.listen", err.Error())
		}
	}
	if !strings.HasPrefix(c.DoH.Path, "/") {
		bad("doh.path", "must start with /")
	}
	if c.Admin.Listen != "" {
		if err := checkListen(c.Admin.Listen); err != nil {
			bad("admin.listen", err.Error())
		}
	}
	if c.Metrics.Listen != "" {
		if err := checkListen(c.Metrics.Listen); err != nil {
			bad("metrics.listen", err.Error())
		}
	}

	errs, warns = c.validateTLS(lines, errs, warns)

	if len(c.Upstream.Primary) == 0 {
		bad("upstream.primary", "at least one upstream is required")
	}
	for _, key := range []string{"upstream.primary", "upstream.fallback"} {
		list := c.Upstream.Primary
		if key == "upstream.fallback" {
			list = c.Upstream.Fallback
		}
		for _, s := range list {
			if _, err := upstream.ParseSpec(s); err != nil {
				bad(key, err.Error())
			}
		}
	}
	for _, s := range c.Upstream.Bootstrap {
		spec, err := upstream.ParseSpec(s)
		if err != nil {
			bad("upstream.bootstrap", err.Error())
		} else if !spec.HostIsIP() {
			bad("upstream.bootstrap", fmt.Sprintf("%q: bootstrap servers must be IP addresses", s))
		}
	}
	if c.Upstream.Parallel < 0 {
		bad("upstream.parallel", "must be 0 (all) or more")
	}
	if c.Upstream.Timeout < 100*time.Millisecond || c.Upstream.Timeout > 30*time.Second {
		bad("upstream.timeout", "must be between 100ms and 30s")
	}
	if c.Upstream.FallbackDelay == 0 {
		c.Upstream.FallbackDelay = c.Upstream.Timeout / 2
	}
	if c.Upstream.FallbackDelay < 0 || c.Upstream.FallbackDelay > c.Upstream.Timeout {
		bad("upstream.fallback_delay", "must be between 0 and upstream.timeout")
	}

	if c.Cache.Size < 0 {
		bad("cache.size", "must be 0 (disabled) or more")
	}
	if c.Cache.MaxTTL < c.Cache.MinTTL {
		bad("cache.max_ttl", "must be at least cache.min_ttl")
	}
	if c.Cache.ServeStale < 0 {
		bad("cache.serve_stale", "must not be negative")
	}

	switch c.Server.Mode {
	case ModePrivate:
		if len(c.Access.Allow) == 0 {
			bad("access.allow", "private mode needs at least one allowed address or network")
		}
	case ModePublic:
		if len(c.Access.Allow) > 0 {
			warns = append(warns, "access.allow is ignored in public mode")
		}
	}
	if c.Status.Enabled {
		if len(c.DoH.HTTPSListen) == 0 && c.DoH.Listen == "" {
			warns = append(warns, "status.enabled: the status page is served on the DNS-over-HTTPS addresses, and none is set (doh.https_listen or doh.listen)")
		}
		if len(c.TLS.Domains) == 0 {
			warns = append(warns, "status.enabled: without tls.domains the status page cannot offer encrypted addresses or the check")
		}
	}
	if c.Log.Queries {
		warns = append(warns, "log.queries no longer writes queries to the system log; start the query log in the admin interface instead (it is kept in memory and stops by itself)")
	}

	l := &c.Limits
	for key, v := range map[string]float64{
		"limits.client_qps": l.ClientQPS, "limits.client_burst": l.ClientBurst,
		"limits.prefix_qps": l.PrefixQPS, "limits.prefix_burst": l.PrefixBurst,
		"limits.global_qps": l.GlobalQPS, "limits.rrl_rate": l.RRLRate,
	} {
		if v < 0 {
			bad(key, "must be 0 (no limit) or more")
		}
	}
	for key, v := range map[string]int{
		"limits.upstream_concurrency": l.UpstreamConcurrency, "limits.zone_concurrency": l.ZoneConcurrency,
		"limits.tcp_connections": l.TCPConnections, "limits.quic_connections": l.QUICConnections,
		"limits.tcp_pipeline": l.TCPPipeline, "limits.rrl_slip": l.RRLSlip,
	} {
		if v < 0 {
			bad(key, "must be 0 or more")
		}
	}
	if l.TCPConnections == 0 {
		bad("limits.tcp_connections", "must be at least 1")
	}
	if l.QUICConnections == 0 {
		bad("limits.quic_connections", "must be at least 1")
	}
	if l.TCPPipeline == 0 {
		bad("limits.tcp_pipeline", "must be at least 1")
	}
	if l.UDPMaxSize < 512 || l.UDPMaxSize > 4096 {
		bad("limits.udp_max_size", "must be between 512 and 4096")
	}
	if l.TCPIdleTimeout < time.Second {
		bad("limits.tcp_idle_timeout", "must be at least 1s")
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].Line < errs[j].Line })
	return errs, warns
}

// PublicListenIPs returns the public addresses named in server.listen: the
// ones a certificate authority can reach and clients use for DDR.
func (c *Config) PublicListenIPs() []netip.Addr {
	var out []netip.Addr
	for _, l := range c.Server.Listen {
		ap, err := netip.ParseAddrPort(l)
		if err != nil {
			continue
		}
		a := ap.Addr().Unmap()
		if a.IsGlobalUnicast() && !a.IsPrivate() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func (c *Config) validateTLS(lines map[string]int, errs Errors, warns []string) (Errors, []string) {
	bad := func(key, msg string) { errs = append(errs, &Error{Line: lines[key], Key: key, Msg: msg}) }
	for _, l := range []struct {
		key  string
		list []string
	}{{"dot.listen", c.DoT.Listen}, {"doq.listen", c.DoQ.Listen}, {"doh.https_listen", c.DoH.HTTPSListen}} {
		for _, a := range l.list {
			if err := checkListen(a); err != nil {
				bad(l.key, err.Error())
			}
		}
		if len(l.list) > 0 && c.TLS.Certificate == "off" {
			bad(l.key, `needs a certificate: set tls.certificate to "acme" or "files"`)
		}
	}
	t := &c.TLS
	switch t.Certificate {
	case "off":
	case "files":
		if t.CertFile == "" || t.KeyFile == "" {
			bad("tls.cert_file", "files mode needs tls.cert_file and tls.key_file")
		}
	case "acme":
		for _, d := range t.Domains {
			if !validDomain(d) {
				bad("tls.domains", fmt.Sprintf("%q is not a valid domain name", d))
			}
		}
		if t.IPAddresses && len(c.PublicListenIPs()) == 0 {
			bad("tls.ip_addresses", "no public IP address is listed in server.listen")
		}
		if len(t.Domains) == 0 && !t.IPAddresses {
			bad("tls.domains", "acme needs at least one domain (or tls.ip_addresses = true)")
		}
		u, err := url.Parse(t.ACMEDirectory)
		if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
			bad("tls.acme_directory", "must be an https URL")
		}
		if t.Challenge == "" {
			t.Challenge = "http-01"
			for _, a := range append(slices.Clone(c.DoH.HTTPSListen), c.DoT.Listen...) {
				if strings.HasSuffix(a, ":443") {
					t.Challenge = "tls-alpn-01" // the CA can reach us on 443: no port 80 needed
				}
			}
		}
		switch t.Challenge {
		case "http-01":
			if err := checkListen(t.HTTPChallengeListen); err != nil {
				bad("tls.http_challenge_listen", err.Error())
			}
		case "tls-alpn-01":
			on443 := false
			for _, a := range append(slices.Clone(c.DoH.HTTPSListen), c.DoT.Listen...) {
				on443 = on443 || strings.HasSuffix(a, ":443")
			}
			if !on443 {
				bad("tls.challenge", "tls-alpn-01 needs doh.https_listen (or dot.listen) on port 443")
			}
		default:
			bad("tls.challenge", `must be "http-01" or "tls-alpn-01"`)
		}
	default:
		bad("tls.certificate", fmt.Sprintf(`must be "off", "acme" or "files", got %q`, t.Certificate))
	}
	if c.DDR.Enabled && (len(c.DoT.Listen) > 0 || len(c.DoQ.Listen) > 0 || len(c.DoH.HTTPSListen) > 0) {
		if t.Certificate == "acme" && len(t.Domains) == 0 {
			warns = append(warns, "ddr needs tls.domains to name the encrypted resolver; DDR answers are disabled")
		} else if t.Certificate == "acme" && !t.IPAddresses {
			warns = append(warns, "ddr: without tls.ip_addresses = true, clients cannot verify the upgrade and most will not use it")
		}
	}
	return errs, warns
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}

func validDomain(d string) bool {
	d = strings.TrimSuffix(d, ".")
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func checkListen(a string) error {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return fmt.Errorf("%q: expected address:port, e.g. 203.0.113.10:53 or [2001:db8::10]:53", a)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 { // 0 picks a free port (tests)
		return fmt.Errorf("%q: invalid port", a)
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("%q: the address must be an IP address", a)
		}
	}
	return nil
}

// ---- field table ----

// field decodes one setting into a Config and reads it back in the form the
// file would hold it.
type field struct {
	set func(c *Config, v Value) error
	get func(c *Config) Value
}

// Keys returns the name of every setting, sorted.
func Keys() []string {
	out := make([]string, 0, len(fields))
	for k := range fields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Get returns the effective value of a setting, its default included when
// the file does not set it.
func (c *Config) Get(key string) (Value, bool) {
	f, ok := fields[key]
	if !ok {
		return Value{}, false
	}
	return f.get(c), true
}

// SplitKey splits "table.key" into its table and key.
func SplitKey(name string) (table, key string) {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return "", name
}

var fields = map[string]field{
	"server.mode":     str(func(c *Config) *string { return &c.Server.Mode }),
	"server.listen":   strList(func(c *Config) *[]string { return &c.Server.Listen }),
	"server.data_dir": str(func(c *Config) *string { return &c.Server.DataDir }),

	"doh.https_listen": strList(func(c *Config) *[]string { return &c.DoH.HTTPSListen }),
	"doh.http3":        boolean(func(c *Config) *bool { return &c.DoH.HTTP3 }),
	"dot.listen":       strList(func(c *Config) *[]string { return &c.DoT.Listen }),
	"doq.listen":       strList(func(c *Config) *[]string { return &c.DoQ.Listen }),

	"tls.certificate":           str(func(c *Config) *string { return &c.TLS.Certificate }),
	"tls.domains":               strList(func(c *Config) *[]string { return &c.TLS.Domains }),
	"tls.ip_addresses":          boolean(func(c *Config) *bool { return &c.TLS.IPAddresses }),
	"tls.email":                 str(func(c *Config) *string { return &c.TLS.Email }),
	"tls.challenge":             str(func(c *Config) *string { return &c.TLS.Challenge }),
	"tls.http_challenge_listen": str(func(c *Config) *string { return &c.TLS.HTTPChallengeListen }),
	"tls.acme_directory":        str(func(c *Config) *string { return &c.TLS.ACMEDirectory }),
	"tls.cert_file":             str(func(c *Config) *string { return &c.TLS.CertFile }),
	"tls.key_file":              str(func(c *Config) *string { return &c.TLS.KeyFile }),
	"ddr.enabled":               boolean(func(c *Config) *bool { return &c.DDR.Enabled }),

	"doh.listen":          str(func(c *Config) *string { return &c.DoH.Listen }),
	"doh.path":            str(func(c *Config) *string { return &c.DoH.Path }),
	"doh.trusted_proxies": prefixes(func(c *Config) *[]netip.Prefix { return &c.DoH.TrustedProxies }),

	"upstream.primary":        strList(func(c *Config) *[]string { return &c.Upstream.Primary }),
	"upstream.fallback":       strList(func(c *Config) *[]string { return &c.Upstream.Fallback }),
	"upstream.bootstrap":      strList(func(c *Config) *[]string { return &c.Upstream.Bootstrap }),
	"upstream.parallel":       integer(func(c *Config) *int { return &c.Upstream.Parallel }),
	"upstream.timeout":        duration(func(c *Config) *time.Duration { return &c.Upstream.Timeout }),
	"upstream.fallback_delay": duration(func(c *Config) *time.Duration { return &c.Upstream.FallbackDelay }),

	"cache.size":             integer(func(c *Config) *int { return &c.Cache.Size }),
	"cache.min_ttl":          seconds(func(c *Config) *uint32 { return &c.Cache.MinTTL }),
	"cache.max_ttl":          seconds(func(c *Config) *uint32 { return &c.Cache.MaxTTL }),
	"cache.max_negative_ttl": seconds(func(c *Config) *uint32 { return &c.Cache.MaxNegativeTTL }),
	"cache.serve_stale":      duration(func(c *Config) *time.Duration { return &c.Cache.ServeStale }),
	"cache.prefetch":         boolean(func(c *Config) *bool { return &c.Cache.Prefetch }),

	"access.allow": prefixes(func(c *Config) *[]netip.Prefix { return &c.Access.Allow }),

	"limits.client_qps":           number(func(c *Config) *float64 { return &c.Limits.ClientQPS }),
	"limits.client_burst":         number(func(c *Config) *float64 { return &c.Limits.ClientBurst }),
	"limits.prefix_qps":           number(func(c *Config) *float64 { return &c.Limits.PrefixQPS }),
	"limits.prefix_burst":         number(func(c *Config) *float64 { return &c.Limits.PrefixBurst }),
	"limits.global_qps":           number(func(c *Config) *float64 { return &c.Limits.GlobalQPS }),
	"limits.upstream_concurrency": integer(func(c *Config) *int { return &c.Limits.UpstreamConcurrency }),
	"limits.zone_concurrency":     integer(func(c *Config) *int { return &c.Limits.ZoneConcurrency }),
	"limits.tcp_connections":      integer(func(c *Config) *int { return &c.Limits.TCPConnections }),
	"limits.quic_connections":     integer(func(c *Config) *int { return &c.Limits.QUICConnections }),
	"limits.tcp_pipeline":         integer(func(c *Config) *int { return &c.Limits.TCPPipeline }),
	"limits.tcp_idle_timeout":     duration(func(c *Config) *time.Duration { return &c.Limits.TCPIdleTimeout }),
	"limits.udp_max_size":         integer(func(c *Config) *int { return &c.Limits.UDPMaxSize }),
	"limits.rrl_rate":             number(func(c *Config) *float64 { return &c.Limits.RRLRate }),
	"limits.rrl_slip":             integer(func(c *Config) *int { return &c.Limits.RRLSlip }),
	"limits.block_any":            boolean(func(c *Config) *bool { return &c.Limits.BlockANY }),

	"metrics.listen": str(func(c *Config) *string { return &c.Metrics.Listen }),
	"admin.listen":   str(func(c *Config) *string { return &c.Admin.Listen }),
	"status.enabled": boolean(func(c *Config) *bool { return &c.Status.Enabled }),
	"log.queries":    boolean(func(c *Config) *bool { return &c.Log.Queries }),
}

var knownTables = map[string]bool{
	"server": true, "doh": true, "dot": true, "doq": true, "tls": true, "ddr": true, "upstream": true, "cache": true,
	"access": true, "limits": true, "metrics": true, "log": true, "admin": true, "status": true,
}

func want(v Value, k Kind) error {
	if v.Kind != k {
		return fmt.Errorf("expected %s, got %s", article(k), v.Kind)
	}
	return nil
}

func article(k Kind) string {
	switch k {
	case Array:
		return "an array"
	case Int:
		return "an integer"
	}
	return "a " + k.String()
}

func str(p func(*Config) *string) field {
	return field{func(c *Config, v Value) error {
		if err := want(v, String); err != nil {
			return err
		}
		*p(c) = v.Str
		return nil
	}, func(c *Config) Value { return Str(*p(c)) }}
}

func boolean(p func(*Config) *bool) field {
	return field{func(c *Config, v Value) error {
		if err := want(v, Bool); err != nil {
			return err
		}
		*p(c) = v.Bool
		return nil
	}, func(c *Config) Value { return BoolV(*p(c)) }}
}

func integer(p func(*Config) *int) field {
	return field{func(c *Config, v Value) error {
		if err := want(v, Int); err != nil {
			return err
		}
		if v.Int > 1<<31 || v.Int < -(1<<31) {
			return errors.New("number out of range")
		}
		*p(c) = int(v.Int)
		return nil
	}, func(c *Config) Value { return IntV(int64(*p(c))) }}
}

func number(p func(*Config) *float64) field {
	return field{func(c *Config, v Value) error {
		switch v.Kind {
		case Int:
			*p(c) = float64(v.Int)
		case Float:
			*p(c) = v.Float
		default:
			return fmt.Errorf("expected a number, got %s", v.Kind)
		}
		return nil
	}, func(c *Config) Value {
		if f := *p(c); f == math.Trunc(f) && math.Abs(f) < 1<<53 {
			return IntV(int64(f))
		}
		return FloatV(*p(c))
	}}
}

// duration accepts "250ms", "3s", "24h" or a plain number of seconds.
func duration(p func(*Config) *time.Duration) field {
	return field{func(c *Config, v Value) error {
		d, err := toDuration(v)
		if err != nil {
			return err
		}
		*p(c) = d
		return nil
	}, func(c *Config) Value { return Str(FormatDuration(*p(c))) }}
}

// FormatDuration writes d the way a person would: "3s", "10m", "24h", "250ms".
func FormatDuration(d time.Duration) string {
	switch {
	case d == 0:
		return "0s"
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	case d%time.Millisecond == 0 && d < time.Second:
		return strconv.FormatInt(int64(d/time.Millisecond), 10) + "ms"
	}
	return d.String()
}

func toDuration(v Value) (time.Duration, error) {
	switch v.Kind {
	case Int:
		if v.Int < 0 || v.Int > 1<<31 {
			return 0, errors.New("number out of range")
		}
		return time.Duration(v.Int) * time.Second, nil
	case String:
		d, err := time.ParseDuration(v.Str)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q (examples: \"500ms\", \"3s\", \"24h\")", v.Str)
		}
		return d, nil
	}
	return 0, fmt.Errorf("expected a duration such as \"3s\", got %s", v.Kind)
}

// seconds is a TTL: a duration rounded down to whole seconds.
func seconds(p func(*Config) *uint32) field {
	return field{func(c *Config, v Value) error {
		d, err := toDuration(v)
		if err != nil {
			return err
		}
		if d < 0 || d > 1<<31*time.Second {
			return errors.New("out of range")
		}
		*p(c) = uint32(d / time.Second)
		return nil
	}, func(c *Config) Value { return Str(FormatDuration(time.Duration(*p(c)) * time.Second)) }}
}

func strList(p func(*Config) *[]string) field {
	return field{func(c *Config, v Value) error {
		if err := want(v, Array); err != nil {
			return err
		}
		out := make([]string, 0, len(v.Arr))
		for _, it := range v.Arr {
			if it.Kind != String {
				return fmt.Errorf("expected an array of strings, got %s items", it.Kind)
			}
			out = append(out, it.Str)
		}
		*p(c) = out
		return nil
	}, func(c *Config) Value { return StrList(*p(c)) }}
}

func prefixes(p func(*Config) *[]netip.Prefix) field {
	return field{func(c *Config, v Value) error {
		var list []string
		if err := strList(func(*Config) *[]string { return &list }).set(c, v); err != nil {
			return err
		}
		out, err := ParsePrefixes(list)
		if err != nil {
			return err
		}
		*p(c) = out
		return nil
	}, func(c *Config) Value {
		list := make([]string, 0, len(*p(c)))
		for _, pf := range *p(c) {
			if pf.IsSingleIP() {
				list = append(list, pf.Addr().String())
			} else {
				list = append(list, pf.String())
			}
		}
		return StrList(list)
	}}
}

// ParsePrefixes parses CIDRs and bare addresses (as single-host prefixes).
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p)).Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or network", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// unmapBits adjusts the prefix length of an IPv4-mapped IPv6 prefix such as
// ::ffff:10.0.0.0/104 when it is converted to plain IPv4.
func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return 96
	}
	return 0
}

func suggest(name string) string {
	best, bestD := "", 4
	for k := range fields {
		if d := levenshtein(name, k); d < bestD {
			best, bestD = k, d
		}
	}
	if best != "" {
		return fmt.Sprintf(" (did you mean %s?)", best)
	}
	return ""
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
