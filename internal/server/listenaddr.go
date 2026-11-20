package server

import (
	"net"
	"net/netip"

	"github.com/harryheros/dnsnova/internal/config"
)

// hostAddrs lists this machine's addresses; a variable for tests.
var hostAddrs = func() []netip.Addr {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap().WithZone(""))
		}
	}
	return out
}

// dnsListen is every address DNS is served on (plain, DoT, DoQ, DoH).
func dnsListen(c *config.Config) []string {
	out := append([]string{}, plainListen(c)...)
	out = append(out, c.DoT.Listen...)
	out = append(out, c.DoQ.Listen...)
	out = append(out, c.DoH.HTTPSListen...)
	if c.DoH.Listen != "" {
		out = append(out, c.DoH.Listen)
	}
	return out
}

// missingListen returns the DNS listen addresses of c that name an IP this
// machine does not have, leaving out those already in prev. They are bound
// anyway (freeBind) and answered once the address is up.
func missingListen(c, prev *config.Config) []string {
	had := map[string]bool{}
	if prev != nil {
		for _, a := range dnsListen(prev) {
			had[a] = true
		}
	}
	have := map[netip.Addr]bool{}
	var out []string
	seen := map[string]bool{}
	for _, a := range dnsListen(c) {
		if had[a] || seen[a] {
			continue
		}
		seen[a] = true
		host, _, err := net.SplitHostPort(a)
		if err != nil || host == "" {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		if len(have) == 0 {
			for _, h := range hostAddrs() {
				have[h] = true
			}
		}
		if !have[ip.Unmap().WithZone("")] {
			out = append(out, a)
		}
	}
	return out
}
