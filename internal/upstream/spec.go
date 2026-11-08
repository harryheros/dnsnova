// Package upstream sends queries to upstream resolvers over UDP, TCP, DNS
// over TLS and DNS over HTTPS, and groups them into primary and fallback sets.
package upstream

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Spec is a parsed upstream address.
//
//	203.0.113.53                    plain DNS over UDP (TCP when truncated), port 53
//	udp://203.0.113.53:5353         the same with an explicit scheme and port
//	tcp://203.0.113.53              DNS over TCP
//	tls://dns.example               DNS over TLS, port 853
//	https://dns.example/dns-query   DNS over HTTPS
//
// A hostname may be pinned to an address with a fragment, which skips the
// bootstrap lookup while the certificate is still checked against the name:
//
//	tls://dns.google#8.8.8.8
//	https://dns.google/dns-query#8.8.8.8
type Spec struct {
	Raw    string
	Scheme string // udp, tcp, tls, https
	Host   string // hostname or IP address, without brackets
	Port   int
	URL    string // https only: the request URL without the fragment
	Pin    netip.Addr
}

// HostIsIP reports whether the host part is an IP literal.
func (s Spec) HostIsIP() bool {
	_, err := netip.ParseAddr(s.Host)
	return err == nil
}

// Addr returns host:port.
func (s Spec) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// ParseSpec parses an upstream address.
func ParseSpec(raw string) (Spec, error) {
	s := Spec{Raw: raw}
	rest := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		s.Scheme, rest = strings.ToLower(raw[:i]), raw[i+3:]
	} else {
		s.Scheme = "udp"
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		pin, err := netip.ParseAddr(rest[i+1:])
		if err != nil {
			return s, fmt.Errorf("%q: the part after # must be an IP address", raw)
		}
		s.Pin = pin.Unmap()
		rest = rest[:i]
	}
	defPort := map[string]int{"udp": 53, "tcp": 53, "tls": 853, "https": 443}
	port, ok := defPort[s.Scheme]
	if !ok {
		return s, fmt.Errorf("%q: unsupported scheme %q (use udp, tcp, tls or https)", raw, s.Scheme)
	}
	if s.Scheme == "https" {
		u, err := url.Parse("https://" + rest)
		if err != nil || u.Host == "" {
			return s, fmt.Errorf("%q: invalid URL", raw)
		}
		if u.User != nil || u.RawQuery != "" {
			return s, fmt.Errorf("%q: credentials and query strings are not supported", raw)
		}
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		s.Host = u.Hostname()
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return s, fmt.Errorf("%q: invalid port", raw)
			}
			port = n
		}
		s.Port = port
		s.URL = u.String()
	} else {
		if strings.ContainsAny(rest, "/?") {
			return s, fmt.Errorf("%q: unexpected path", raw)
		}
		host, p, err := net.SplitHostPort(rest)
		if err != nil {
			host = strings.TrimSuffix(strings.TrimPrefix(rest, "["), "]")
		} else {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return s, fmt.Errorf("%q: invalid port", raw)
			}
			port = n
		}
		s.Host, s.Port = host, port
	}
	if s.Host == "" {
		return s, fmt.Errorf("%q: missing host", raw)
	}
	if a, err := netip.ParseAddr(s.Host); err == nil {
		if s.Pin.IsValid() {
			return s, fmt.Errorf("%q: an IP address cannot be pinned", raw)
		}
		s.Host = a.Unmap().String()
	} else {
		if !validHostname(s.Host) {
			return s, fmt.Errorf("%q: invalid host name %q", raw, s.Host)
		}
		if s.Scheme == "udp" || s.Scheme == "tcp" {
			if !s.Pin.IsValid() {
				return s, fmt.Errorf("%q: plain DNS upstreams must be IP addresses", raw)
			}
		}
	}
	return s, nil
}

func validHostname(h string) bool {
	if len(h) > 253 || h == "" {
		return false
	}
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
