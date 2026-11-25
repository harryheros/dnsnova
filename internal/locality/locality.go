// Package locality is private locality: clients far from the server get
// the answers that name servers give where they are, without anything
// about them being sent.
//
// Some name servers answer by where the question comes from: a content
// network gives the address of its servers nearest the resolver that asks.
// A resolver far from its clients sends them to servers near itself. EDNS
// Client Subnet fixes that by telling name servers the client's network.
// Private locality fixes it without that: the server also asks from a few
// other places (exits: small hosts that only pass the questions on), and
// each client gets the answer given where it is.
//
// The rules that keep it private:
//
//   - A client's address, and the country or network it is in, only pick
//     an answer inside the server. They are never sent, and never written
//     to disk.
//   - What is sent does not depend on who asked: a name whose answers
//     depend on where they are asked from is asked from every place at
//     once, whoever needs it. Name servers and exits see what they would
//     without private locality: that the server asked for a name.
//   - Off, nothing changes: no exit is used, no country table is loaded.
//
// This package holds what the resolver and the recursion share: the exits,
// which one serves a client (Mapper), the country table, and how a lookup
// says which client view it is for and returns the answers for all views.
package locality

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// Exit is a place questions can leave from besides the server itself: a
// host reached through a tunnel, to which the server sends questions from
// a source address of its own (Local) that the system routes into the
// tunnel.
type Exit struct {
	Name string
	// Local are the source addresses questions to name servers are sent
	// from: at most one IPv4 and one IPv6 address. Name servers of the
	// other family are not asked through this exit.
	Local []netip.Addr
	// Countries (ISO 3166 codes, upper case) and Networks are the clients
	// this exit answers for. A network wins over a country.
	Countries []string
	Networks  []netip.Prefix
}

// LocalFor returns the exit's source address for the family of a, if any.
func (e *Exit) LocalFor(a netip.Addr) (netip.Addr, bool) {
	for _, l := range e.Local {
		if l.Is4() == a.Is4() {
			return l, true
		}
	}
	return netip.Addr{}, false
}

// MaxExits bounds the exits: each one asks every name whose answers vary
// once more.
const MaxExits = 16

// ParseExits reads entries like
//
//	exit-a 10.66.1.2 XA XB
//	exit-b 10.66.2.2,fd66:2::2 XC,XD,XE
//	office-b 10.66.3.2 10.20.0.0/16
//
// a name, the source addresses that lead into its tunnel (an IPv4 address,
// an IPv6 address or both, separated by a comma), then the clients it
// answers for: country codes and networks, separated by spaces or commas.
func ParseExits(list []string) ([]Exit, error) {
	if len(list) > MaxExits {
		return nil, fmt.Errorf("at most %d exits", MaxExits)
	}
	var out []Exit
	names := map[string]bool{}
	locals := map[netip.Addr]string{}
	countries := map[string]string{}
	nets := map[netip.Prefix]string{}
	for _, e := range list {
		f := strings.Fields(strings.ReplaceAll(e, ", ", ","))
		if len(f) < 3 {
			return nil, fmt.Errorf("%q: write a name, the address queries leave from, and the clients it serves, such as \"exit-a 10.66.1.2 XA,XB\"", e)
		}
		x := Exit{Name: strings.ToLower(f[0])}
		if len(x.Name) > 32 || strings.Trim(x.Name, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" || x.Name == "server" {
			return nil, fmt.Errorf("%q: an exit name is letters, digits, - and _, at most 32 (not \"server\")", f[0])
		}
		if names[x.Name] {
			return nil, fmt.Errorf("%q: exit listed twice", f[0])
		}
		names[x.Name] = true
		for _, s := range strings.Split(f[1], ",") {
			a, err := netip.ParseAddr(s)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("%q: %q is not an address (the source address that leads into the exit's tunnel)", e, s)
			}
			a = a.Unmap()
			if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
				return nil, fmt.Errorf("%q: %s cannot be a source address", e, a)
			}
			if _, dup := x.LocalFor(a); dup {
				return nil, fmt.Errorf("%q: one IPv4 and one IPv6 address at most", e)
			}
			if other, ok := locals[a]; ok {
				return nil, fmt.Errorf("%q: %s is already exit %s's", e, a, other)
			}
			locals[a] = x.Name
			x.Local = append(x.Local, a)
		}
		for _, w := range f[2:] {
			for _, s := range strings.Split(w, ",") {
				if s == "" {
					continue
				}
				if cc := strings.ToUpper(s); len(cc) == 2 && strings.Trim(cc, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
					if other, ok := countries[cc]; ok {
						return nil, fmt.Errorf("%q: %s is already served by exit %s", e, cc, other)
					}
					countries[cc] = x.Name
					x.Countries = append(x.Countries, cc)
					continue
				}
				p, err := netip.ParsePrefix(s)
				if err != nil {
					a, aerr := netip.ParseAddr(s)
					if aerr != nil || a.Zone() != "" {
						return nil, fmt.Errorf("%q: %q is not a country code (two letters) or a network", e, s)
					}
					a = a.Unmap()
					p = netip.PrefixFrom(a, a.BitLen())
				}
				p = p.Masked()
				if other, ok := nets[p]; ok {
					return nil, fmt.Errorf("%q: %s is already served by exit %s", e, p, other)
				}
				nets[p] = x.Name
				x.Networks = append(x.Networks, p)
			}
		}
		if len(x.Countries) == 0 && len(x.Networks) == 0 {
			return nil, fmt.Errorf("%q: name the clients this exit serves: country codes or networks", e)
		}
		out = append(out, x)
	}
	return out, nil
}

// ServerName is what the views of the server itself are called.
const ServerName = "server"

// Mapper tells which view serves a client: 0 is the server itself, i the
// exit Exits[i-1]. It is safe for concurrent use.
type Mapper struct {
	exits     []Exit
	byCountry map[string]int
	nets      []netView // narrowest first
	countries *atomic.Pointer[Countries]
	Report    *Report
}

type netView struct {
	p    netip.Prefix
	view int
}

// NewMapper returns a Mapper for exits (as ParseExits returns them).
func NewMapper(exits []Exit) *Mapper {
	m := &Mapper{exits: exits, byCountry: map[string]int{}, Report: &Report{}, countries: new(atomic.Pointer[Countries])}
	for i, x := range exits {
		for _, cc := range x.Countries {
			m.byCountry[cc] = i + 1
		}
		for _, p := range x.Networks {
			m.nets = append(m.nets, netView{p, i + 1})
		}
	}
	slices.SortStableFunc(m.nets, func(a, b netView) int { return b.p.Bits() - a.p.Bits() })
	return m
}

// Exits returns the exits, in view order (view i is Exits()[i-1]).
func (m *Mapper) Exits() []Exit { return m.exits }

// Views is the number of views: the server and each exit.
func (m *Mapper) Views() int { return len(m.exits) + 1 }

// Signature identifies the views: the same exits in the same order give
// the same signature, so answers kept per view still belong to them.
func (m *Mapper) Signature() string {
	if m == nil {
		return ""
	}
	names := make([]string, len(m.exits))
	for i, x := range m.exits {
		names[i] = x.Name
	}
	return strings.Join(names, " ")
}

// ViewName names view v.
func (m *Mapper) ViewName(v int) string {
	if v <= 0 || v > len(m.exits) {
		return ServerName
	}
	return m.exits[v-1].Name
}

// NeedsCountries reports whether any exit serves clients by country.
func (m *Mapper) NeedsCountries() bool { return len(m.byCountry) > 0 }

// Share makes m use a country table and a report kept elsewhere, which
// outlive one configuration.
func (m *Mapper) Share(countries *atomic.Pointer[Countries], report *Report) {
	m.countries, m.Report = countries, report
}

// SetCountries publishes a country table (nil: none yet).
func (m *Mapper) SetCountries(c *Countries) { m.countries.Store(c) }

// CountryTable returns the table in use, or nil.
func (m *Mapper) CountryTable() *Countries { return m.countries.Load() }

// View returns the view that serves a client at a.
func (m *Mapper) View(a netip.Addr) int {
	v, _, _ := m.Place(a)
	return v
}

// Place returns the view that serves a client at a, the network that chose
// it (if one did) and the country a is registered in ("" when unknown or
// not looked up: a network chose first, or no exit serves by country).
// Nothing is allocated: it runs for every query.
func (m *Mapper) Place(a netip.Addr) (view int, by netip.Prefix, cc string) {
	if m == nil || !a.IsValid() {
		return 0, netip.Prefix{}, ""
	}
	a = a.Unmap()
	for _, n := range m.nets {
		if n.p.Contains(a) {
			return n.view, n.p, ""
		}
	}
	if len(m.byCountry) > 0 {
		cc = m.Country(a)
		if v, ok := m.byCountry[cc]; ok && cc != "" {
			return v, netip.Prefix{}, cc
		}
	}
	return 0, netip.Prefix{}, cc
}

// Explain returns the view that serves a client at a, and why: the network
// or the country that chose it ("" when none did).
func (m *Mapper) Explain(a netip.Addr) (int, string) {
	v, by, cc := m.Place(a)
	switch {
	case by.IsValid():
		return v, by.String()
	case v != 0:
		return v, cc
	}
	return 0, ""
}

// Country returns the country a is registered in, "" when unknown (no
// table yet, a private address, an unlisted one).
func (m *Mapper) Country(a netip.Addr) string {
	if m == nil {
		return ""
	}
	return m.countries.Load().Lookup(a)
}

// ---- how a lookup carries its view, and returns every view's answer ----

type viewKey struct{}

// WithView returns ctx for a lookup made for a client in view v.
func WithView(ctx context.Context, v int) context.Context {
	return context.WithValue(ctx, viewKey{}, v)
}

// ViewFrom returns the view a lookup is for: 0 (the server) by default.
func ViewFrom(ctx context.Context) int {
	if v, ok := ctx.Value(viewKey{}).(int); ok {
		return v
	}
	return 0
}

// Variants collects the answers for every view when a lookup's answer
// depends on where it was asked from: Resps[v] is the answer for view v,
// nil for a view whose answer is not known yet. Nil Resps: the answer is
// the same for everyone.
type Variants struct {
	mu    sync.Mutex
	Resps [][]byte
}

// Set records the answers (called by the recursion).
func (x *Variants) Set(resps [][]byte) {
	x.mu.Lock()
	x.Resps = resps
	x.mu.Unlock()
}

// Get returns the answers recorded, if any.
func (x *Variants) Get() [][]byte {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.Resps
}

type variantsKey struct{}

// WithVariants returns ctx for a lookup whose answers for every view are
// to be put in x.
func WithVariants(ctx context.Context, x *Variants) context.Context {
	return context.WithValue(ctx, variantsKey{}, x)
}

// VariantsFrom returns where to put every view's answer, or nil.
func VariantsFrom(ctx context.Context) *Variants {
	x, _ := ctx.Value(variantsKey{}).(*Variants)
	return x
}

// ---- the siting report ----

// Report counts queries by the country they came from, and how many of
// them were for names whose answers depend on where they are asked from:
// counts only, in memory, no names and no addresses. It shows where exits
// would help.
type Report struct {
	mu sync.RWMutex
	by map[string]*[2]atomic.Int64
}

// ReportRow is one country's counts.
type ReportRow struct {
	Country string `json:"country"` // "--": not known (private address, not listed)
	Queries int64  `json:"queries"`
	Varying int64  `json:"varying"` // for names whose answers depend on where they are asked from
}

// maxReportRows bounds the countries counted (there are about 250).
const maxReportRows = 300

// Add counts one query from a client in country cc ("" when unknown).
func (r *Report) Add(cc string, varying bool) {
	if r == nil {
		return
	}
	if cc == "" {
		cc = "--"
	}
	r.mu.RLock() // a country already counted: no lock held against others
	c := r.by[cc]
	r.mu.RUnlock()
	if c == nil {
		r.mu.Lock()
		if r.by == nil {
			r.by = map[string]*[2]atomic.Int64{}
		}
		if c = r.by[cc]; c == nil {
			if len(r.by) >= maxReportRows {
				r.mu.Unlock()
				return
			}
			c = new([2]atomic.Int64)
			r.by[cc] = c
		}
		r.mu.Unlock()
	}
	c[0].Add(1)
	if varying {
		c[1].Add(1)
	}
}

// Reset forgets the counts.
func (r *Report) Reset() {
	r.mu.Lock()
	r.by = nil
	r.mu.Unlock()
}

// Rows returns the counts, most queries first.
func (r *Report) Rows() []ReportRow {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]ReportRow, 0, len(r.by))
	for cc, c := range r.by {
		out = append(out, ReportRow{Country: cc, Queries: c[0].Load(), Varying: c[1].Load()})
	}
	r.mu.RUnlock()
	slices.SortFunc(out, func(a, b ReportRow) int {
		if a.Queries != b.Queries {
			return int(b.Queries - a.Queries)
		}
		return strings.Compare(a.Country, b.Country)
	})
	return out
}
