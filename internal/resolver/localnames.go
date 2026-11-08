package resolver

import (
	"net/netip"
	"strings"

	"github.com/harryheros/dnsnova/internal/config"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// localTTLNames is short so that edits reach clients quickly.
const localTTLNames = 60

// LocalNames answers the names an administrator set in local.records, such
// as "nas.home 192.168.1.5", without asking upstream. A name that is listed
// answers its A and AAAA records and has no records of other types; "*.x"
// covers every name below x, and an exact entry wins over a wildcard.
type LocalNames struct {
	exact map[string][]netip.Addr // wire-format name
	wild  map[string][]netip.Addr // wire-format suffix, without the "*" label
}

// NewLocalNames builds the table, or returns nil when there is nothing in it.
func NewLocalNames(recs []config.LocalRecord) *LocalNames {
	if len(recs) == 0 {
		return nil
	}
	l := &LocalNames{exact: map[string][]netip.Addr{}, wild: map[string][]netip.Addr{}}
	for _, r := range recs {
		if rest, ok := strings.CutPrefix(r.Name, "*."); ok {
			k := toWire(rest)
			l.wild[k] = append(l.wild[k], r.Addr)
		} else {
			k := toWire(r.Name)
			l.exact[k] = append(l.exact[k], r.Addr)
		}
	}
	return l
}

func (l *LocalNames) lookup(name string) ([]netip.Addr, bool) {
	if a, ok := l.exact[name]; ok {
		return a, true
	}
	// Walk up the labels: the longest matching wildcard wins.
	for i := 0; i < len(name); i += int(name[i]) + 1 {
		rest := name[i+int(name[i])+1:]
		if rest == "" {
			break
		}
		if a, ok := l.wild[rest]; ok {
			return a, true
		}
	}
	return nil, false
}

// answer returns the response for q, or nil when q's name is not listed.
func (l *LocalNames) answer(req []byte, q *m.Query) []byte {
	addrs, ok := l.lookup(q.Name)
	if !ok {
		return nil
	}
	var rd [][]byte
	for _, a := range addrs {
		switch {
		case q.Type == m.TypeA && a.Is4():
			b := a.As4()
			rd = append(rd, b[:])
		case q.Type == m.TypeAAAA && a.Is6():
			b := a.As16()
			rd = append(rd, b[:])
		}
	}
	if len(rd) == 0 { // the name exists here, with no records of this type
		return m.NegativeSOA(req, q, q.Name, localTTLNames, m.RcodeNoError)
	}
	return m.AnswerMulti(req, q, localTTLNames, rd)
}
