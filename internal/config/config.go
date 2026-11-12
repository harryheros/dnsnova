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

	"github.com/harryheros/dnsnova/internal/filter"
	"github.com/harryheros/dnsnova/internal/recursor"
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
		Cookies bool // DNS Cookies (RFC 7873, RFC 9018)
		// ProxyProtocol lists the load balancers whose PROXY protocol
		// header (v1/v2 on TCP, DoT and DoH; v2 on UDP) is required and
		// believed. Empty: none.
		ProxyProtocol []netip.Prefix
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
		Persist        string // keep the answer cache across restarts: "auto", "on" or "off" (see PersistCache)
	}
	Access struct {
		Deny  []netip.Prefix // never answered, in either mode
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
		ClientConnections   int // open connections per client address (TCP, DoT, DoH, DoQ); 0 = no limit
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
	// Cluster: several nodes sharing one configuration (see docs/cluster.md).
	// Without a role the server stands alone and nothing here runs.
	Cluster Cluster
	// Anycast: run the operator's commands to announce or withdraw this
	// node's anycast route as its health changes. File only.
	Anycast Anycast
	// Alerts: notifications when something is wrong (docs/alerts.md).
	// Where they go is not here but in data_dir/secrets/alerts.json.
	Alerts Alerts
	Status struct {
		Enabled bool // public status page on the DoH addresses
	}
	Local struct {
		Records []string // "name address", answered by DNSNova itself
	}
	ECS struct {
		// Address is a network ("1.2.3.0/24") or an address in it,
		// sent as the EDNS Client Subnet of every query. Empty: off.
		Address string
		// ClientPath is a DoH path, kept secret, on which a query's own
		// EDNS Client Subnet is sent to name servers, for tools that
		// measure how names resolve from a given network. Such answers
		// never go into the shared cache. Needs recursion. Empty: off.
		ClientPath string
	}
	Stats struct {
		Retention string // how far back statistics go: 24h, 7d or 30d (memory only)
	}
	Log struct {
		Queries bool // no longer used: the query log runs from the admin interface, in memory
	}
	// Filter is the filtered service: the same server answers on its own
	// addresses ("doors") with block lists applied. Every other address
	// stays unfiltered unless All is set.
	Filter struct {
		Enabled        bool
		All            bool     // filter every address, not only the filtered ones
		Lists          []string // http(s) URLs or absolute file paths
		Block          []string // own rules: these domains and every name under them
		Allow          []string // never blocked, whatever a list says
		UpdateInterval time.Duration
		DoHPath        string   // DoH path of the filtered service, such as /filtered
		Names          []string // DoT, DoQ and DoH names of the filtered service
		Listen         []string // plain DNS addresses (UDP and TCP) of the filtered service
	}
	// Recursion resolves names from the root servers instead of asking
	// upstreams, and validates answers with DNSSEC.
	Recursion struct {
		Enabled           bool
		DNSSEC            bool
		QNameMinimisation bool
		IPv6              bool
		Fallback          bool     // ask the upstreams when no authoritative server answers
		AllowNetworks     []string // networks that may be queried although private or local
		TrustAnchors      []string // replace the root trust anchors: "tag algorithm digest-type digest"
		// NegativeTrustAnchors (RFC 7646) are domains whose answers are
		// not validated: for a domain whose DNSSEC is broken by its owner.
		NegativeTrustAnchors []string
		RootHints            []string // replace the root server addresses
		Cookies              bool     // DNS Cookies with authoritative servers (RFC 7873)
	}
}

// DefaultFilterList is ShieldNova's full list: privacy, ads and security,
// chosen for few false positives.
const DefaultFilterList = "https://raw.githubusercontent.com/harryheros/shieldnova/main/dist/shieldnova-full.txt"

// PersistCache reports whether the answer cache is kept across restarts.
// "auto" follows what the server is for: on for a public server, where the
// cached names belong to many people and a warm cache after a restart
// matters most; off for a home or office network (private mode), where a
// few people's lookups would be kept on disk for little gain.
func (c *Config) PersistCache() bool {
	switch c.Cache.Persist {
	case "on":
		return true
	case "off":
		return false
	}
	return c.Server.Mode == ModePublic
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
	c.Stats.Retention = "7d"
	c.Upstream.Parallel = 2
	c.Upstream.Timeout = 3 * time.Second
	c.Cache.Size = 100000
	c.Cache.MaxTTL = 86400
	c.Cache.MaxNegativeTTL = 3600
	c.Cache.ServeStale = 24 * time.Hour
	c.Cache.Prefetch = true
	c.Server.Cookies = true
	c.Recursion.Cookies = true
	c.Cache.Persist = "auto"
	c.Cluster.Interval = 10 * time.Second
	c.Anycast.Interval = 2 * time.Second
	c.Anycast.Rise = 3
	c.Anycast.Fall = 3
	c.Anycast.Drain = 5 * time.Second
	c.Alerts = DefaultAlerts
	c.Limits.ClientQPS = 100
	c.Limits.ClientBurst = 400
	c.Limits.PrefixQPS = 1000
	c.Limits.PrefixBurst = 4000
	c.Limits.GlobalQPS = 50000
	c.Limits.UpstreamConcurrency = 2000
	c.Limits.ZoneConcurrency = 50
	c.Limits.TCPConnections = 10000
	c.Limits.QUICConnections = 3000
	c.Limits.ClientConnections = 100
	c.Limits.TCPPipeline = 16
	c.Limits.TCPIdleTimeout = 10 * time.Second
	c.Limits.UDPMaxSize = 1232
	c.Limits.RRLRate = 20
	c.Limits.RRLSlip = 2
	c.Limits.BlockANY = true
	c.Filter.Lists = []string{DefaultFilterList}
	c.Filter.UpdateInterval = 24 * time.Hour
	c.Filter.DoHPath = "/filtered"
	c.Recursion.DNSSEC = true
	c.Recursion.QNameMinimisation = true
	c.Recursion.IPv6 = true
	c.Recursion.Fallback = true
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
	dns := c.ServesDNS()
	if !dns && c.Admin.Listen == "" {
		bad("server.listen", "nothing to listen on: set server.listen, dot.listen, doq.listen or doh.https_listen")
	}
	if !dns {
		// A fresh install: only the admin interface runs until setup is done.
		warns = append(warns, "DNS is not served yet: no listen address is set (finish setup in the admin interface)")
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
	errs, warns = c.validateCluster(lines, errs, warns)
	errs = c.validateAlerts(lines, errs)

	if len(c.Upstream.Primary) == 0 && dns && !c.Recursion.Enabled {
		bad("upstream.primary", "at least one upstream is required (or turn on recursion.enabled)")
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
	if _, err := parseClientSubnet(c.ECS.Address); err != nil {
		bad("ecs.address", err.Error())
	}
	if p := c.ECS.ClientPath; p != "" {
		switch {
		case !strings.HasPrefix(p, "/") || strings.ContainsAny(p, " ?#%") || len(p) < 25:
			bad("ecs.client_path", "a secret path: / and at least 24 random letters or digits, like /ecs-k3v9q2m8x7w4r1t6y5u0p2z8")
		case p == c.DoH.Path || p == c.Filter.DoHPath:
			bad("ecs.client_path", "must differ from doh.path and filter.doh_path")
		case !c.Recursion.Enabled:
			bad("ecs.client_path", "needs recursion.enabled: the network is sent to the domains' own name servers")
		case c.DoH.Listen == "" && len(c.DoH.HTTPSListen) == 0:
			bad("ecs.client_path", "needs DNS over HTTPS: set doh.https_listen or doh.listen")
		}
	}
	if _, ok := RetentionHours[c.Stats.Retention]; !ok {
		bad("stats.retention", `must be "24h", "7d" or "30d"`)
	}
	if _, err := ParseLocalRecords(c.Local.Records); err != nil {
		bad("local.records", err.Error())
	}
	if c.Status.Enabled {
		if len(c.DoH.HTTPSListen) == 0 && c.DoH.Listen == "" {
			warns = append(warns, "status.enabled: the status page is served on the DNS-over-HTTPS addresses, and none is set (doh.https_listen or doh.listen)")
		}
		if len(c.TLS.Domains) == 0 {
			warns = append(warns, "status.enabled: without tls.domains the status page cannot offer encrypted addresses or the check")
		}
	}
	errs, warns = c.validateFilter(lines, errs, warns)
	errs, warns = c.validateRecursion(lines, errs, warns)
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
		"limits.client_connections": l.ClientConnections,
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

// ServesDNS reports whether any DNS listener is configured. A fresh
// install has none until setup is finished in the admin interface.
func (c *Config) ServesDNS() bool {
	return len(c.Server.Listen) > 0 || c.Filter.Enabled && len(c.Filter.Listen) > 0 || c.DoH.Listen != "" || len(c.DoH.HTTPSListen) > 0 || len(c.DoT.Listen) > 0 || len(c.DoQ.Listen) > 0
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

func (c *Config) validateRecursion(lines map[string]int, errs Errors, warns []string) (Errors, []string) {
	bad := func(key, msg string) { errs = append(errs, &Error{Line: lines[key], Key: key, Msg: msg}) }
	r := &c.Recursion
	for _, n := range r.AllowNetworks {
		if _, err := netip.ParsePrefix(n); err != nil {
			bad("recursion.allow_networks", fmt.Sprintf("%q: give a network such as 10.0.0.0/8", n))
		}
	}
	for _, a := range r.TrustAnchors {
		if _, err := recursor.ParseAnchor(a); err != nil {
			bad("recursion.trust_anchors", fmt.Sprintf("%q: %v", a, err))
		}
	}
	for _, h := range r.RootHints {
		if _, err := netip.ParseAddr(h); err != nil {
			bad("recursion.root_hints", fmt.Sprintf("%q is not an IP address", h))
		}
	}
	for _, d := range r.NegativeTrustAnchors {
		if !validDomain(d) {
			// a whole top-level domain cannot be exempted: one domain at a time
			bad("recursion.negative_trust_anchors", fmt.Sprintf("%q: give a domain such as example.com", d))
		}
	}
	if n := len(r.NegativeTrustAnchors); r.Enabled && r.DNSSEC && n > 0 {
		warns = append(warns, fmt.Sprintf("recursion.negative_trust_anchors: answers for %d domain(s) are not validated; remove each once its owner has fixed DNSSEC", n))
	}
	if r.Enabled && r.Fallback && len(c.Upstream.Primary) == 0 {
		warns = append(warns, "recursion.fallback: no upstreams are set, so there is nothing to fall back to")
	}
	if r.Enabled && !r.DNSSEC {
		warns = append(warns, "recursion.dnssec is off: answers are not checked, so forged ones can get through")
	}
	return errs, warns
}

// RecursionNetworks returns recursion.allow_networks parsed.
func (c *Config) RecursionNetworks() []netip.Prefix {
	var out []netip.Prefix
	for _, n := range c.Recursion.AllowNetworks {
		if p, err := netip.ParsePrefix(n); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// ClientSubnet returns the network of ecs.address; false when it is off.
func (c *Config) ClientSubnet() (netip.Prefix, bool) {
	p, err := parseClientSubnet(c.ECS.Address)
	return p, err == nil && p.IsValid()
}

// parseClientSubnet reads ecs.address: a network, or an address, which
// stands for its /24 (IPv4) or /56 (IPv6), the sizes RFC 7871 recommends.
// Empty is the zero Prefix.
func parseClientSubnet(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, errors.New("must be an IP address or a network")
		}
		a = a.Unmap()
		bits := 24
		if a.Is6() {
			bits = 56
		}
		p = netip.PrefixFrom(a, bits)
	}
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
	if a := p.Addr(); p.Bits() < 8 || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || specialNet(p) {
		return netip.Prefix{}, errors.New("must be a public address or network (/8 or smaller): name servers answer by where it is on the internet")
	}
	return p.Masked(), nil
}

// notOnInternet are special-purpose ranges (RFC 6890 and its updates)
// that are not anybody's network on the internet: shared address space
// behind carrier NAT, documentation, benchmarking, reserved and NAT64.
var notOnInternet = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "3fff::/20", "fc00::/7",
	} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

func specialNet(p netip.Prefix) bool {
	for _, s := range notOnInternet {
		if s.Overlaps(p) {
			return true
		}
	}
	return false
}

// RecursionRootHints returns recursion.root_hints parsed.
func (c *Config) RecursionRootHints() []netip.Addr {
	var out []netip.Addr
	for _, h := range c.Recursion.RootHints {
		if a, err := netip.ParseAddr(h); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func (c *Config) validateFilter(lines map[string]int, errs Errors, warns []string) (Errors, []string) {
	bad := func(key, msg string) { errs = append(errs, &Error{Line: lines[key], Key: key, Msg: msg}) }
	f := &c.Filter
	for _, src := range f.Lists {
		if u, err := url.Parse(src); strings.HasPrefix(src, "/") || err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			if u != nil && u.Scheme == "http" {
				warns = append(warns, fmt.Sprintf("filter.lists: %s is fetched over plain HTTP, where it can be changed on the way; use https:// if the site offers it", src))
			}
			continue
		}
		bad("filter.lists", fmt.Sprintf("%q: give an http(s) address or an absolute file path", src))
	}
	for key, list := range map[string][]string{"filter.block": f.Block, "filter.allow": f.Allow, "filter.names": f.Names} {
		for _, d := range list {
			if !filter.ValidDomain(d) {
				bad(key, fmt.Sprintf("%q is not a valid domain name", d))
			}
		}
	}
	if f.UpdateInterval < time.Hour || f.UpdateInterval > 30*24*time.Hour {
		bad("filter.update_interval", "must be between 1h and 720h")
	}
	if !strings.HasPrefix(f.DoHPath, "/") {
		bad("filter.doh_path", "must start with /")
	} else if f.DoHPath == c.DoH.Path {
		bad("filter.doh_path", "must differ from doh.path")
	}
	for _, a := range f.Listen {
		if err := checkListen(a); err != nil {
			bad("filter.listen", err.Error())
		} else if slices.Contains(c.Server.Listen, a) {
			bad("filter.listen", fmt.Sprintf("%q is also in server.listen; an address is either filtered or not", a))
		}
	}
	if f.Enabled && !f.All && len(f.Listen) == 0 && len(f.Names) == 0 && len(c.DoH.HTTPSListen) == 0 && c.DoH.Listen == "" {
		warns = append(warns, "filter.enabled: no address uses filtering; set filter.listen, filter.names, a DoH address (filter.doh_path) or filter.all")
	}
	if f.Enabled && len(f.Names) > 0 && c.TLS.Certificate == "files" {
		warns = append(warns, "filter.names: the certificate file must also cover "+strings.Join(f.Names, ", "))
	}
	return errs, warns
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
	"server.mode":           str(func(c *Config) *string { return &c.Server.Mode }),
	"server.listen":         strList(func(c *Config) *[]string { return &c.Server.Listen }),
	"server.data_dir":       str(func(c *Config) *string { return &c.Server.DataDir }),
	"server.cookies":        boolean(func(c *Config) *bool { return &c.Server.Cookies }),
	"server.proxy_protocol": prefixes(func(c *Config) *[]netip.Prefix { return &c.Server.ProxyProtocol }),

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
	"cache.persist": {func(c *Config, v Value) error {
		switch {
		case v.Kind == Bool && v.Bool: // true and false read as "on" and "off"
			c.Cache.Persist = "on"
		case v.Kind == Bool:
			c.Cache.Persist = "off"
		case v.Kind == String && (v.Str == "auto" || v.Str == "on" || v.Str == "off"):
			c.Cache.Persist = v.Str
		default:
			return fmt.Errorf(`must be "auto", "on" or "off"`)
		}
		return nil
	}, func(c *Config) Value { return Str(c.Cache.Persist) }},

	"access.allow":    prefixes(func(c *Config) *[]netip.Prefix { return &c.Access.Allow }),
	"access.deny":     prefixes(func(c *Config) *[]netip.Prefix { return &c.Access.Deny }),
	"local.records":   strList(func(c *Config) *[]string { return &c.Local.Records }),
	"ecs.address":     str(func(c *Config) *string { return &c.ECS.Address }),
	"ecs.client_path": str(func(c *Config) *string { return &c.ECS.ClientPath }),
	"stats.retention": str(func(c *Config) *string { return &c.Stats.Retention }),

	"limits.client_qps":           number(func(c *Config) *float64 { return &c.Limits.ClientQPS }),
	"limits.client_burst":         number(func(c *Config) *float64 { return &c.Limits.ClientBurst }),
	"limits.prefix_qps":           number(func(c *Config) *float64 { return &c.Limits.PrefixQPS }),
	"limits.prefix_burst":         number(func(c *Config) *float64 { return &c.Limits.PrefixBurst }),
	"limits.global_qps":           number(func(c *Config) *float64 { return &c.Limits.GlobalQPS }),
	"limits.upstream_concurrency": integer(func(c *Config) *int { return &c.Limits.UpstreamConcurrency }),
	"limits.zone_concurrency":     integer(func(c *Config) *int { return &c.Limits.ZoneConcurrency }),
	"limits.tcp_connections":      integer(func(c *Config) *int { return &c.Limits.TCPConnections }),
	"limits.client_connections":   integer(func(c *Config) *int { return &c.Limits.ClientConnections }),
	"limits.quic_connections":     integer(func(c *Config) *int { return &c.Limits.QUICConnections }),
	"limits.tcp_pipeline":         integer(func(c *Config) *int { return &c.Limits.TCPPipeline }),
	"limits.tcp_idle_timeout":     duration(func(c *Config) *time.Duration { return &c.Limits.TCPIdleTimeout }),
	"limits.udp_max_size":         integer(func(c *Config) *int { return &c.Limits.UDPMaxSize }),
	"limits.rrl_rate":             number(func(c *Config) *float64 { return &c.Limits.RRLRate }),
	"limits.rrl_slip":             integer(func(c *Config) *int { return &c.Limits.RRLSlip }),
	"limits.block_any":            boolean(func(c *Config) *bool { return &c.Limits.BlockANY }),

	"metrics.listen": str(func(c *Config) *string { return &c.Metrics.Listen }),
	"admin.listen":   str(func(c *Config) *string { return &c.Admin.Listen }),

	"cluster.role":     str(func(c *Config) *string { return &c.Cluster.Role }),
	"cluster.name":     str(func(c *Config) *string { return &c.Cluster.Name }),
	"cluster.region":   str(func(c *Config) *string { return &c.Cluster.Region }),
	"cluster.listen":   str(func(c *Config) *string { return &c.Cluster.Listen }),
	"cluster.primary":  str(func(c *Config) *string { return &c.Cluster.Primary }),
	"cluster.interval": duration(func(c *Config) *time.Duration { return &c.Cluster.Interval }),

	"anycast.enabled":             boolean(func(c *Config) *bool { return &c.Anycast.Enabled }),
	"anycast.announce":            strList(func(c *Config) *[]string { return &c.Anycast.Announce }),
	"anycast.withdraw":            strList(func(c *Config) *[]string { return &c.Anycast.Withdraw }),
	"anycast.interval":            duration(func(c *Config) *time.Duration { return &c.Anycast.Interval }),
	"anycast.rise":                integer(func(c *Config) *int { return &c.Anycast.Rise }),
	"anycast.fall":                integer(func(c *Config) *int { return &c.Anycast.Fall }),
	"anycast.drain":               duration(func(c *Config) *time.Duration { return &c.Anycast.Drain }),
	"alerts.enabled":              boolean(func(c *Config) *bool { return &c.Alerts.Enabled }),
	"alerts.repeat":               duration(func(c *Config) *time.Duration { return &c.Alerts.Repeat }),
	"alerts.nodes":                boolean(func(c *Config) *bool { return &c.Alerts.Nodes }),
	"alerts.upstream_down_for":    duration(func(c *Config) *time.Duration { return &c.Alerts.UpstreamDownFor }),
	"alerts.upstream_failing_for": duration(func(c *Config) *time.Duration { return &c.Alerts.UpstreamFailingFor }),
	"alerts.servfail_ratio":       number(func(c *Config) *float64 { return &c.Alerts.ServfailRatio }),
	"alerts.servfail_min_queries": integer(func(c *Config) *int { return &c.Alerts.ServfailMinQueries }),
	"alerts.servfail_for":         duration(func(c *Config) *time.Duration { return &c.Alerts.ServfailFor }),
	"alerts.latency_p95":          duration(func(c *Config) *time.Duration { return &c.Alerts.LatencyP95 }),
	"alerts.latency_min_queries":  integer(func(c *Config) *int { return &c.Alerts.LatencyMinQueries }),
	"alerts.latency_for":          duration(func(c *Config) *time.Duration { return &c.Alerts.LatencyFor }),
	"alerts.dnssec_failures":      integer(func(c *Config) *int { return &c.Alerts.DNSSECFailures }),
	"alerts.cert_warn_days":       integer(func(c *Config) *int { return &c.Alerts.CertWarnDays }),
	"alerts.cert_critical_days":   integer(func(c *Config) *int { return &c.Alerts.CertCriticalDays }),

	"status.enabled": boolean(func(c *Config) *bool { return &c.Status.Enabled }),
	"log.queries":    boolean(func(c *Config) *bool { return &c.Log.Queries }),

	"filter.enabled":         boolean(func(c *Config) *bool { return &c.Filter.Enabled }),
	"filter.all":             boolean(func(c *Config) *bool { return &c.Filter.All }),
	"filter.lists":           strList(func(c *Config) *[]string { return &c.Filter.Lists }),
	"filter.block":           strList(func(c *Config) *[]string { return &c.Filter.Block }),
	"filter.allow":           strList(func(c *Config) *[]string { return &c.Filter.Allow }),
	"filter.update_interval": duration(func(c *Config) *time.Duration { return &c.Filter.UpdateInterval }),
	"filter.doh_path":        str(func(c *Config) *string { return &c.Filter.DoHPath }),
	"filter.names":           strList(func(c *Config) *[]string { return &c.Filter.Names }),
	"filter.listen":          strList(func(c *Config) *[]string { return &c.Filter.Listen }),

	"recursion.enabled":                boolean(func(c *Config) *bool { return &c.Recursion.Enabled }),
	"recursion.dnssec":                 boolean(func(c *Config) *bool { return &c.Recursion.DNSSEC }),
	"recursion.qname_minimisation":     boolean(func(c *Config) *bool { return &c.Recursion.QNameMinimisation }),
	"recursion.ipv6":                   boolean(func(c *Config) *bool { return &c.Recursion.IPv6 }),
	"recursion.fallback":               boolean(func(c *Config) *bool { return &c.Recursion.Fallback }),
	"recursion.allow_networks":         strList(func(c *Config) *[]string { return &c.Recursion.AllowNetworks }),
	"recursion.trust_anchors":          strList(func(c *Config) *[]string { return &c.Recursion.TrustAnchors }),
	"recursion.negative_trust_anchors": strList(func(c *Config) *[]string { return &c.Recursion.NegativeTrustAnchors }),
	"recursion.cookies":                boolean(func(c *Config) *bool { return &c.Recursion.Cookies }),
	"recursion.root_hints":             strList(func(c *Config) *[]string { return &c.Recursion.RootHints }),
}

var knownTables = map[string]bool{
	"cluster": true, "anycast": true, "alerts": true,
	"server": true, "doh": true, "dot": true, "doq": true, "tls": true, "ddr": true, "upstream": true, "cache": true,
	"access": true, "limits": true, "metrics": true, "log": true, "admin": true, "status": true, "local": true, "stats": true, "ecs": true, "filter": true,
	"recursion": true,
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

// RetentionHours maps stats.retention to hours.
var RetentionHours = map[string]int{"24h": 24, "7d": 7 * 24, "30d": 30 * 24}

// LocalRecord is one entry of local.records: a name and the address DNSNova
// answers for it. A name starting with "*." covers every name below it.
type LocalRecord struct {
	Name string // lowercase, no trailing dot
	Addr netip.Addr
}

// ParseLocalRecords reads entries like "nas.home 192.168.1.5". The same name
// may have several addresses (IPv4 and IPv6, or more than one of each).
func ParseLocalRecords(list []string) ([]LocalRecord, error) {
	var out []LocalRecord
	for _, e := range list {
		f := strings.Fields(e)
		if len(f) != 2 {
			return nil, fmt.Errorf("%q: write a name and an address, such as \"nas.home 192.168.1.5\"", e)
		}
		name := strings.ToLower(strings.TrimSuffix(f[0], "."))
		check := strings.TrimPrefix(name, "*.")
		if check == "" || len(check) > 253 || strings.Contains(check, "*") || strings.Contains(check, "..") || strings.HasPrefix(check, ".") {
			return nil, fmt.Errorf("%q: not a valid name", f[0])
		}
		for _, l := range strings.Split(check, ".") {
			if len(l) > 63 || strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
				return nil, fmt.Errorf("%q: not a valid name", f[0])
			}
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("%q: %q is not an IP address", e, f[1])
		}
		out = append(out, LocalRecord{Name: name, Addr: a.Unmap()})
	}
	return out, nil
}

// Cluster is the [cluster] table.
type Cluster struct {
	Role     string        // "", "primary" or "follower"
	Name     string        // this node's name; default: the host name
	Region   string        // free text, shown on the Nodes page
	Listen   string        // primary: address followers sync from
	Primary  string        // follower: the primary's cluster address
	Interval time.Duration // follower: how often it syncs
}

// Anycast is the [anycast] table.
type Anycast struct {
	Enabled  bool
	Announce []string      // argv, e.g. ["birdc", "enable", "anycast"]
	Withdraw []string      // argv
	Interval time.Duration // between health checks
	Rise     int           // healthy checks in a row before announcing
	Fall     int           // failed checks in a row before withdrawing
	Drain    time.Duration // at shutdown: withdraw, then keep answering this long
}

// NodeLocalTables are never synced from a primary: each node's own
// [cluster] and [anycast] settings (who it follows, which commands it runs).
var NodeLocalTables = []string{"cluster", "anycast"}

// FileOnlyTables cannot be changed through the admin API, only in the file
// on the server: [cluster] decides where a node takes its configuration
// from and [anycast] runs commands, so a stolen admin password must not
// reach either.
var FileOnlyTables = NodeLocalTables

func (c *Config) validateCluster(lines map[string]int, errs Errors, warns []string) (Errors, []string) {
	bad := func(key, msg string) { errs = append(errs, &Error{Line: lines[key], Key: key, Msg: msg}) }
	switch c.Cluster.Role {
	case "":
	case "primary":
		if c.Cluster.Listen == "" {
			bad("cluster.listen", `a primary needs an address for its followers, e.g. "10.0.0.1:7001"`)
		} else if err := checkListen(c.Cluster.Listen); err != nil {
			bad("cluster.listen", err.Error())
		}
	case "follower":
		if _, _, err := net.SplitHostPort(c.Cluster.Primary); err != nil || c.Cluster.Primary == "" {
			bad("cluster.primary", `a follower needs the primary's cluster address as host:port, e.g. "10.0.0.1:7001"`)
		}
	default:
		bad("cluster.role", fmt.Sprintf(`must be "primary" or "follower" (or absent), got %q`, c.Cluster.Role))
	}
	if c.Cluster.Interval < time.Second || c.Cluster.Interval > time.Hour {
		bad("cluster.interval", "must be between 1s and 1h")
	}
	if len(c.Cluster.Name) > 63 {
		bad("cluster.name", "at most 63 characters")
	}
	if c.Anycast.Enabled {
		if len(c.Anycast.Announce) == 0 || c.Anycast.Announce[0] == "" {
			bad("anycast.announce", `the command that announces the route, as a list: ["birdc", "enable", "anycast"]`)
		}
		if len(c.Anycast.Withdraw) == 0 || c.Anycast.Withdraw[0] == "" {
			bad("anycast.withdraw", `the command that withdraws the route, as a list: ["birdc", "disable", "anycast"]`)
		}
	}
	if c.Anycast.Interval < 100*time.Millisecond {
		bad("anycast.interval", "at least 100ms")
	}
	if c.Anycast.Rise < 1 || c.Anycast.Rise > 100 {
		bad("anycast.rise", "between 1 and 100")
	}
	if c.Anycast.Fall < 1 || c.Anycast.Fall > 100 {
		bad("anycast.fall", "between 1 and 100")
	}
	if c.Anycast.Drain < 0 || c.Anycast.Drain > 5*time.Minute {
		bad("anycast.drain", "between 0s and 5m")
	}
	return errs, warns
}

// IsFollower reports whether the file at src makes this node a follower,
// reading only [cluster] role: a follower's own file need not be a whole
// configuration.
func IsFollower(src []byte) (bool, error) {
	doc, err := Parse(src)
	if err != nil {
		return false, err
	}
	e := doc.Lookup("cluster", "role")
	return e != nil && e.Value.Kind == String && e.Value.Str == "follower", nil
}

// SharedPart returns src without the node-local tables, as a primary hands
// it to its followers.
func SharedPart(src []byte) ([]byte, error) {
	doc, err := Parse(src)
	if err != nil {
		return nil, err
	}
	for _, e := range doc.Entries {
		if !slices.Contains(NodeLocalTables, e.Table) {
			continue
		}
		if src, err = doc.Delete(e.Table, e.Key); err != nil {
			return nil, err
		}
		if doc, err = Parse(src); err != nil {
			return nil, err
		}
	}
	return doc.Src, nil
}

// Merge makes a follower's configuration: the shared part from the primary
// with every setting of the follower's own file on top (its listen
// addresses, data_dir, [cluster], [anycast], ...). It returns the merged
// source and the node's overrides: the shared settings ("table.key") its
// own file replaces or adds ([cluster] and [anycast] are its own anyway).
func Merge(shared, local []byte) ([]byte, []string, error) {
	shared, err := SharedPart(shared)
	if err != nil {
		return nil, nil, fmt.Errorf("shared configuration: %w", err)
	}
	ldoc, err := Parse(local)
	if err != nil {
		return nil, nil, err
	}
	out := shared
	var keys []string
	for _, e := range ldoc.Entries {
		doc, err := Parse(out)
		if err != nil {
			return nil, nil, err
		}
		if out, err = doc.Set(e.Table, e.Key, e.Value); err != nil {
			return nil, nil, err
		}
		if !slices.Contains(NodeLocalTables, e.Table) {
			keys = append(keys, strings.TrimPrefix(e.Table+"."+e.Key, "."))
		}
	}
	return out, keys, nil
}

// Alerts is the [alerts] table. A threshold of 0 turns its check off.
type Alerts struct {
	Enabled bool
	// Repeat: a condition that lasts is notified again this often (0: never).
	Repeat time.Duration
	// Nodes: on a cluster's primary, also notify about the followers
	// (their own alerts, and a node going offline).
	Nodes bool
	// every upstream failing, for this long
	UpstreamDownFor time.Duration
	// one upstream failing at least half its queries, for this long
	UpstreamFailingFor time.Duration
	// SERVFAIL answers (DNSSEC failures aside) over five minutes, with at
	// least ServfailMinQueries answers, for ServfailFor
	ServfailRatio      float64
	ServfailMinQueries int
	ServfailFor        time.Duration
	// 95th percentile of the time to answer queries not in the cache, over
	// five minutes, with at least LatencyMinQueries of them, for LatencyFor
	LatencyP95        time.Duration
	LatencyMinQueries int
	LatencyFor        time.Duration
	// answers refused for failing DNSSEC validation in five minutes
	DNSSECFailures int
	// days left on the certificate: warning, then critical
	CertWarnDays, CertCriticalDays int
}

// DefaultAlerts are the defaults of [alerts].
var DefaultAlerts = Alerts{
	Repeat: 4 * time.Hour, Nodes: true,
	UpstreamDownFor: 30 * time.Second, UpstreamFailingFor: 5 * time.Minute,
	ServfailRatio: 0.05, ServfailMinQueries: 500, ServfailFor: 5 * time.Minute,
	LatencyP95: 500 * time.Millisecond, LatencyMinQueries: 100, LatencyFor: 5 * time.Minute,
	DNSSECFailures: 100, CertWarnDays: 14, CertCriticalDays: 3,
}

func (c *Config) validateAlerts(lines map[string]int, errs Errors) Errors {
	bad := func(key, msg string) { errs = append(errs, &Error{Line: lines[key], Key: key, Msg: msg}) }
	a := &c.Alerts
	if a.Repeat != 0 && (a.Repeat < 10*time.Minute || a.Repeat > 7*24*time.Hour) {
		bad("alerts.repeat", "between 10m and 168h, or 0s for never")
	}
	for key, d := range map[string]time.Duration{"alerts.upstream_down_for": a.UpstreamDownFor,
		"alerts.upstream_failing_for": a.UpstreamFailingFor, "alerts.servfail_for": a.ServfailFor, "alerts.latency_for": a.LatencyFor} {
		if d < 0 || d > 24*time.Hour {
			bad(key, "between 0s and 24h")
		}
	}
	if a.ServfailRatio < 0 || a.ServfailRatio > 1 {
		bad("alerts.servfail_ratio", "a fraction between 0 and 1 (0.05 is 5%), or 0 for off")
	}
	if a.LatencyP95 < 0 || a.LatencyP95 > 10*time.Second {
		bad("alerts.latency_p95", "between 0s (off) and 10s")
	}
	for key, n := range map[string]int{"alerts.servfail_min_queries": a.ServfailMinQueries, "alerts.latency_min_queries": a.LatencyMinQueries,
		"alerts.dnssec_failures": a.DNSSECFailures} {
		if n < 0 || n > 100_000_000 {
			bad(key, "a number of queries, 0 or more")
		}
	}
	if a.CertWarnDays < 0 || a.CertWarnDays > 90 || a.CertCriticalDays < 0 || a.CertCriticalDays > 90 {
		bad("alerts.cert_warn_days", "days between 0 (off) and 90")
	} else if a.CertCriticalDays > a.CertWarnDays && a.CertWarnDays > 0 {
		bad("alerts.cert_critical_days", "fewer days than alerts.cert_warn_days")
	}
	return errs
}
