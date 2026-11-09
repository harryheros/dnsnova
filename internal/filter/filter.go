// Package filter decides which names the filtered service blocks. It reads
// domain block lists (AdGuard / ABP domain rules such as ShieldNova's,
// hosts files, or one domain per line), adds the operator's own rules and
// matches query names against them.
//
// Only domain rules are used; rules that depend on a page, a path, a regular
// expression or a wildcard cannot apply to DNS and are skipped (and counted).
// An allow rule always wins over a block rule.
package filter

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

// Set is an immutable collection of rules, safe for concurrent use.
type Set struct {
	block      map[string]struct{} // the domain and every name under it
	blockExact map[string]struct{} // only the name itself (hosts files)
	allow      map[string]struct{} // the domain and every name under it
}

// Rules counts the block rules in s.
func (s *Set) Rules() int {
	if s == nil {
		return 0
	}
	return len(s.block) + len(s.blockExact)
}

// Allowed reports whether an allow rule covers name.
func (s *Set) Allowed(name string) bool {
	if s == nil {
		return false
	}
	for i := 0; i < len(name); i += 1 + int(name[i]) {
		if _, ok := s.allow[name[i:]]; ok {
			return true
		}
	}
	return false
}

// Blocked reports whether a query name is blocked. name is in wire format
// without the final zero byte, lowercased (as in dnsmsg.Query.Name).
func (s *Set) Blocked(name string) bool {
	if s == nil || name == "" {
		return false
	}
	// Walk the suffixes: www.ads.example.com, ads.example.com, example.com, com.
	for i := 0; i < len(name); i += 1 + int(name[i]) {
		if _, ok := s.allow[name[i:]]; ok {
			return false
		}
	}
	if _, ok := s.blockExact[name]; ok {
		return true
	}
	for i := 0; i < len(name); i += 1 + int(name[i]) {
		if _, ok := s.block[name[i:]]; ok {
			return true
		}
	}
	return false
}

// Builder collects rules from several sources into one Set.
type Builder struct {
	s Set
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	return &Builder{s: Set{block: map[string]struct{}{}, blockExact: map[string]struct{}{}, allow: map[string]struct{}{}}}
}

// Block adds a domain and everything under it; Allow exempts them. Invalid
// names are ignored and reported as false.
func (b *Builder) Block(domain string) bool { return add(b.s.block, domain) }
func (b *Builder) Allow(domain string) bool { return add(b.s.allow, domain) }

// BlockExact blocks only the name itself.
func (b *Builder) BlockExact(domain string) bool { return add(b.s.blockExact, domain) }

func add(m map[string]struct{}, domain string) bool {
	w, ok := wire(domain)
	if ok {
		m[w] = struct{}{}
	}
	return ok
}

// Set returns the rules collected so far. The builder must not be used
// afterwards.
func (b *Builder) Set() *Set { return &b.s }

// Counts describes what a parse found.
type Counts struct {
	Block   int // block rules taken
	Allow   int // allow (exception) rules taken
	Skipped int // rules that cannot apply to DNS
}

// Parse reads one list into b. Lines are recognised as:
//
//	||example.com^          block example.com and every name under it
//	@@||example.com^        never block them
//	0.0.0.0 a.com b.com     hosts file: block exactly these names
//	example.com             one domain per line: block it and every name under it
//
// "!" and "#" start comments; "$important" is accepted, other modifiers
// make a rule page-specific and it is skipped.
func Parse(r io.Reader, b *Builder) (Counts, error) {
	var c Counts
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '!' || line[0] == '#' || line[0] == '[' {
			continue
		}
		// An inline comment after an adblock rule, as in "||a.com^   ! tracker".
		if strings.HasPrefix(line, "||") || strings.HasPrefix(line, "@@") {
			if i := strings.IndexAny(line, " \t"); i >= 0 {
				line = line[:i]
			}
		}
		switch {
		case strings.HasPrefix(line, "@@||"):
			if d, ok := domainRule(line[4:]); ok && b.Allow(d) {
				c.Allow++
			} else {
				c.Skipped++
			}
		case strings.HasPrefix(line, "||"):
			if d, ok := domainRule(line[2:]); ok && b.Block(d) {
				c.Block++
			} else {
				c.Skipped++
			}
		case strings.ContainsAny(line, " \t"):
			fields := strings.Fields(line)
			if _, err := netip.ParseAddr(fields[0]); err != nil {
				c.Skipped++
				continue
			}
			for _, f := range fields[1:] {
				if f[0] == '#' {
					break
				}
				if hostsLocal(f) {
					continue
				}
				if b.BlockExact(f) {
					c.Block++
				} else {
					c.Skipped++
				}
			}
		default:
			if b.Block(line) {
				c.Block++
			} else {
				c.Skipped++
			}
		}
	}
	return c, sc.Err()
}

// domainRule returns the domain of "example.com^" or "example.com^$important".
func domainRule(r string) (string, bool) {
	d, mods, _ := strings.Cut(r, "$")
	if mods != "" && mods != "important" {
		return "", false
	}
	d, ok := strings.CutSuffix(d, "^")
	if !ok {
		d, ok = strings.CutSuffix(d, "^|")
	}
	if !ok || strings.ContainsAny(d, "*/^|:") {
		return "", false
	}
	return d, true
}

// hostsLocal reports names a hosts file lists for the machine itself.
func hostsLocal(n string) bool {
	switch strings.ToLower(n) {
	case "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
		"ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0":
		return true
	}
	return false
}

// wire converts a domain to wire format without the final zero byte,
// lowercased, or reports false if it is not a usable domain name: at least
// two labels, letters, digits, "-" and "_", at most 253 characters.
func wire(d string) (string, bool) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") {
		return "", false
	}
	b := make([]byte, 0, len(d)+1)
	for label := range strings.SplitSeq(d, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return string(b), true
}

// ValidDomain reports whether d can be used as a rule (for configuration).
func ValidDomain(d string) bool {
	_, ok := wire(d)
	return ok
}
