package resolver

import (
	"net/netip"
	"slices"

	"github.com/harryheros/dnsnova/internal/filter"
)

// Group is clients on some networks with filtering of their own
// (clients.groups).
type Group struct {
	Name string
	// Filter: +1 the block lists apply whichever address the clients use,
	// -1 never, 0 as the address decides.
	Filter int8
	// Rules are the group's own block and allow rules (nil: none): they
	// apply whether or not the block lists do, and an allow rule also
	// exempts the name from the lists.
	Rules *filter.Set
}

// Groups finds a client's group. Built once, then read only.
type Groups struct {
	nets []groupNet // narrowest first
}

type groupNet struct {
	p netip.Prefix
	g *Group
}

// NewGroups returns an empty set.
func NewGroups() *Groups { return &Groups{} }

// Add puts the clients on p in g.
func (gs *Groups) Add(p netip.Prefix, g *Group) {
	gs.nets = append(gs.nets, groupNet{p.Masked(), g})
	slices.SortStableFunc(gs.nets, func(a, b groupNet) int { return b.p.Bits() - a.p.Bits() })
}

// find returns the group of ip (the one with the narrowest network), or nil.
func (gs *Groups) find(ip netip.Addr) *Group {
	if gs == nil || !ip.IsValid() {
		return nil
	}
	ip = ip.Unmap()
	for _, n := range gs.nets {
		if n.p.Contains(ip) {
			return n.g
		}
	}
	return nil
}

// filtering decides whether the block lists apply: the group's choice, or
// the address's (door) when the group has none.
func (g *Group) filtering(door bool) bool {
	if g == nil || g.Filter == 0 {
		return door
	}
	return g.Filter > 0
}

func (g *Group) rules() *filter.Set {
	if g == nil {
		return nil
	}
	return g.Rules
}

func (g *Group) name() string {
	if g == nil {
		return ""
	}
	return g.Name
}
