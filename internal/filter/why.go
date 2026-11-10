package filter

import (
	"bytes"
	"os"
)

// Why says which lists and rules decide about a name.
type Why struct {
	Enabled bool `json:"enabled"`
	Blocked bool `json:"blocked"` // what the filtered service answers
	// BlockedBy and AllowedBy name lists by their source; the operator's
	// own rules are "filter.block" and "filter.allow".
	BlockedBy []string `json:"blocked_by"`
	AllowedBy []string `json:"allowed_by"`
}

// Why checks name (wire format, lowercased) against each list on its own.
// It reads and parses every stored copy, so it is for the occasional
// question from the administrator, one at a time.
func (m *Manager) Why(name string) Why {
	m.whyMu.Lock()
	defer m.whyMu.Unlock()
	m.mu.Lock()
	s := m.set
	m.mu.Unlock()
	w := Why{Enabled: s.Enabled, BlockedBy: []string{}, AllowedBy: []string{}}
	if !s.Enabled {
		return w
	}
	check := func(source string, set *Set) {
		switch {
		case set.Allowed(name):
			w.AllowedBy = append(w.AllowedBy, source)
		case set.blocks(name):
			w.BlockedBy = append(w.BlockedBy, source)
		}
	}
	for _, src := range s.Lists {
		data, err := os.ReadFile(m.path(src))
		if err != nil {
			continue // not downloaded yet
		}
		b := NewBuilder()
		Parse(bytes.NewReader(data), b)
		check(src, b.Set())
	}
	own := func(rules []string, allow bool) *Set {
		b := NewBuilder()
		for _, d := range rules {
			if allow {
				b.Allow(d)
			} else {
				b.Block(d)
			}
		}
		return b.Set()
	}
	check("filter.block", own(s.Block, false))
	check("filter.allow", own(s.Allow, true))
	// an allow rule anywhere wins (as in Set.Blocked)
	w.Blocked = len(w.BlockedBy) > 0 && len(w.AllowedBy) == 0
	return w
}
