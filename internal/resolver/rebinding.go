package resolver

import (
	"net/netip"
	"strings"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/stats"
)

// DNS rebinding protection. A web page can point a name of its own at an
// address on the visitor's network (a router, a NAS, a printer) and then
// reach that device from the browser, as if it were its own site. So an
// answer from outside that gives an address of a private network is
// refused, unless the name is one of the network's own:
//
//   - names under a domain in local.forward (asked from the network's own
//     servers) or local.allow_private;
//   - names under domains kept for private use (lan, home, internal,
//     home.arpa, ...) and names of one label;
//   - names in local.records, answered before any of this.
//
// Whether an answer holds such an address is found once, when it is
// cached; answering from the cache only reads that flag.

// Rebinding is the protection's settings; nil: off.
type Rebinding struct {
	allow map[string]struct{} // wire names, lowercase
}

// NewRebinding turns the protection on, with the domains (dotted) whose
// names may point into private networks.
func NewRebinding(allow []string) *Rebinding {
	rb := &Rebinding{allow: map[string]struct{}{}}
	for _, d := range allow {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d != "" {
			rb.allow[m.WireName(strings.Split(d, ".")...)] = struct{}{}
		}
	}
	return rb
}

// privateUse are domains for names that only exist on a local network
// (RFC 6761, RFC 6762, RFC 8375, ICANN's .internal) and ones routers and
// offices commonly use for the same.
var privateUse = func() map[string]struct{} {
	out := map[string]struct{}{}
	for _, d := range []string{"lan", "home", "internal", "local", "localdomain", "corp", "intranet", "private", "home.arpa"} {
		out[m.WireName(strings.Split(d, ".")...)] = struct{}{}
	}
	return out
}()

// exempt says whether name (wire format, lowercase) may point into a
// private network.
func (rb *Rebinding) exempt(name string) bool {
	if name == "" || 1+int(name[0]) >= len(name) {
		return true // the root, or a single label
	}
	for i := 0; i < len(name); i += 1 + int(name[i]) {
		if _, ok := rb.allow[name[i:]]; ok {
			return true
		}
		if _, ok := privateUse[name[i:]]; ok {
			return true
		}
	}
	return false
}

var privateNets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), // 0.0.0.0 itself is let through (below)
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space (CGNAT, overlay networks)
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// privateAddr says whether a is an address of a private network or of the
// machine itself. 0.0.0.0 and :: are not: blocking services answer with
// them, and browsers do not connect to them.
func privateAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsUnspecified() {
		return false
	}
	for _, p := range privateNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// privateRR says whether an A or AAAA record in msg gives a private address.
func privateRR(msg []byte, rr m.RR) bool {
	switch {
	case rr.Type == m.TypeA && rr.RDLen == 4:
		return privateAddr(netip.AddrFrom4([4]byte(msg[rr.RDOff : rr.RDOff+4])))
	case rr.Type == m.TypeAAAA && rr.RDLen == 16:
		return privateAddr(netip.AddrFrom16([16]byte(msg[rr.RDOff : rr.RDOff+16])))
	}
	return false
}

// rebound says whether e must be refused as a rebinding answer for this
// query.
func (f finisher) rebound(e *entry) bool {
	rb := f.s.Rebinding
	if !e.private || rb == nil || rb.exempt(f.q.Name) {
		return false
	}
	return f.s.Forward.match(f.q.Name) == nil // the network's own servers answered
}

// rebinding answers a refused rebinding answer: no addresses (NOERROR,
// NODATA) rather than an error, so that a client does not go on to ask
// another resolver, and an Extended DNS Error saying why.
func (f finisher) rebinding() Result {
	res := Result{Resp: m.NegativeSOA(f.req, f.q, f.q.Name, BlockedTTL, m.RcodeNoError), Q: f.q, Source: stats.SourceBlocked, Status: "rebinding", Rebinding: true}
	return f.done(res, m.EDE(m.EDEBlocked, "the answer pointed into a private network (DNS rebinding protection)"))
}
