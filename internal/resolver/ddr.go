package resolver

import (
	"encoding/binary"
	"net/netip"
	"strings"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// DDR describes the encrypted endpoints advertised to clients through
// Discovery of Designated Resolvers (RFC 9462).
type DDR struct {
	Name    string // the encrypted resolver's name, e.g. "dns.example.com"
	DoTPort int    // 0 = no DoT
	DoHPort int    // 0 = no DoH
	DoHPath string // e.g. "/dns-query"
	IPv4    []netip.Addr
	IPv6    []netip.Addr
}

// Records builds the SVCB record data answered for _dns.resolver.arpa: DoT
// first (priority 1), then DoH (priority 2), each with address hints.
func (d DDR) Records() [][]byte {
	if d.Name == "" || (d.DoTPort == 0 && d.DoHPort == 0) {
		return nil
	}
	target := m.WireName(strings.Split(strings.ToLower(strings.TrimSuffix(d.Name, ".")), ".")...)
	hints := func(params []m.SvcParam) []m.SvcParam {
		if len(d.IPv4) > 0 {
			var v []byte
			for _, a := range d.IPv4 {
				b := a.As4()
				v = append(v, b[:]...)
			}
			params = append(params, m.SvcParam{Key: m.SvcIPv4Hint, Value: v})
		}
		if len(d.IPv6) > 0 {
			var v []byte
			for _, a := range d.IPv6 {
				b := a.As16()
				v = append(v, b[:]...)
			}
			params = append(params, m.SvcParam{Key: m.SvcIPv6Hint, Value: v})
		}
		return params
	}
	alpn := func(ids ...string) m.SvcParam {
		var v []byte
		for _, id := range ids {
			v = append(v, byte(len(id)))
			v = append(v, id...)
		}
		return m.SvcParam{Key: m.SvcALPN, Value: v}
	}
	port := func(p int) m.SvcParam {
		return m.SvcParam{Key: m.SvcPort, Value: binary.BigEndian.AppendUint16(nil, uint16(p))}
	}
	var out [][]byte
	if d.DoTPort > 0 {
		params := []m.SvcParam{alpn("dot")}
		if d.DoTPort != 853 {
			params = append(params, port(d.DoTPort))
		}
		out = append(out, m.SVCB(1, target, hints(params)))
	}
	if d.DoHPort > 0 {
		params := []m.SvcParam{alpn("h2")}
		if d.DoHPort != 443 {
			params = append(params, port(d.DoHPort))
		}
		params = hints(params)
		params = append(params, m.SvcParam{Key: m.SvcDoHPath, Value: []byte(d.DoHPath + "{?dns}")})
		out = append(out, m.SVCB(2, target, params))
	}
	return out
}
