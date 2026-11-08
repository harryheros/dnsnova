// Package config loads, validates and edits the dnsnova configuration file.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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
		Mode   string
		Listen []string
	}
	DoH struct {
		Listen         string
		Path           string
		TrustedProxies []netip.Prefix
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
	Log struct {
		Queries bool
	}
}

// Defaults returns a Config with every optional setting at its default.
func Defaults() *Config {
	c := &Config{}
	c.DoH.Path = "/dns-query"
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
		if err := f(cfg, e.Value); err != nil {
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
	if len(c.Server.Listen) == 0 && c.DoH.Listen == "" {
		bad("server.listen", "nothing to listen on: set server.listen and/or doh.listen")
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
	if c.Metrics.Listen != "" {
		if err := checkListen(c.Metrics.Listen); err != nil {
			bad("metrics.listen", err.Error())
		}
	}

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
		"limits.tcp_connections": l.TCPConnections, "limits.tcp_pipeline": l.TCPPipeline, "limits.rrl_slip": l.RRLSlip,
	} {
		if v < 0 {
			bad(key, "must be 0 or more")
		}
	}
	if l.TCPConnections == 0 {
		bad("limits.tcp_connections", "must be at least 1")
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

type setter func(c *Config, v Value) error

var fields = map[string]setter{
	"server.mode":   str(func(c *Config) *string { return &c.Server.Mode }),
	"server.listen": strList(func(c *Config) *[]string { return &c.Server.Listen }),

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
	"limits.tcp_pipeline":         integer(func(c *Config) *int { return &c.Limits.TCPPipeline }),
	"limits.tcp_idle_timeout":     duration(func(c *Config) *time.Duration { return &c.Limits.TCPIdleTimeout }),
	"limits.udp_max_size":         integer(func(c *Config) *int { return &c.Limits.UDPMaxSize }),
	"limits.rrl_rate":             number(func(c *Config) *float64 { return &c.Limits.RRLRate }),
	"limits.rrl_slip":             integer(func(c *Config) *int { return &c.Limits.RRLSlip }),
	"limits.block_any":            boolean(func(c *Config) *bool { return &c.Limits.BlockANY }),

	"metrics.listen": str(func(c *Config) *string { return &c.Metrics.Listen }),
	"log.queries":    boolean(func(c *Config) *bool { return &c.Log.Queries }),
}

var knownTables = map[string]bool{
	"server": true, "doh": true, "upstream": true, "cache": true,
	"access": true, "limits": true, "metrics": true, "log": true,
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

func str(p func(*Config) *string) setter {
	return func(c *Config, v Value) error {
		if err := want(v, String); err != nil {
			return err
		}
		*p(c) = v.Str
		return nil
	}
}

func boolean(p func(*Config) *bool) setter {
	return func(c *Config, v Value) error {
		if err := want(v, Bool); err != nil {
			return err
		}
		*p(c) = v.Bool
		return nil
	}
}

func integer(p func(*Config) *int) setter {
	return func(c *Config, v Value) error {
		if err := want(v, Int); err != nil {
			return err
		}
		if v.Int > 1<<31 || v.Int < -(1<<31) {
			return errors.New("number out of range")
		}
		*p(c) = int(v.Int)
		return nil
	}
}

func number(p func(*Config) *float64) setter {
	return func(c *Config, v Value) error {
		switch v.Kind {
		case Int:
			*p(c) = float64(v.Int)
		case Float:
			*p(c) = v.Float
		default:
			return fmt.Errorf("expected a number, got %s", v.Kind)
		}
		return nil
	}
}

// duration accepts "250ms", "3s", "24h" or a plain number of seconds.
func duration(p func(*Config) *time.Duration) setter {
	return func(c *Config, v Value) error {
		d, err := toDuration(v)
		if err != nil {
			return err
		}
		*p(c) = d
		return nil
	}
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
func seconds(p func(*Config) *uint32) setter {
	return func(c *Config, v Value) error {
		d, err := toDuration(v)
		if err != nil {
			return err
		}
		if d < 0 || d > 1<<31*time.Second {
			return errors.New("out of range")
		}
		*p(c) = uint32(d / time.Second)
		return nil
	}
}

func strList(p func(*Config) *[]string) setter {
	return func(c *Config, v Value) error {
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
	}
}

func prefixes(p func(*Config) *[]netip.Prefix) setter {
	return func(c *Config, v Value) error {
		var list []string
		if err := strList(func(*Config) *[]string { return &list })(c, v); err != nil {
			return err
		}
		out, err := ParsePrefixes(list)
		if err != nil {
			return err
		}
		*p(c) = out
		return nil
	}
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
