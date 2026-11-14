package filter

import (
	"strings"
)

// RPZ (Response Policy Zones) is the zone format threat feeds publish
// block lists in. Each record's owner is a name, relative to the zone
// ($ORIGIN), and its data the action:
//
//	evil.example   CNAME .              NXDOMAIN: block
//	*.evil.example CNAME .              block every name under evil.example
//	evil.example   CNAME *.             NODATA: block
//	evil.example   CNAME rpz-drop.      drop: block
//	evil.example   CNAME landing.test.  answer with another name: block
//	evil.example   A 0.0.0.0            answer with an address: block
//	good.example   CNAME rpz-passthru.  exempt the name: skipped
//
// Triggers on answer addresses, name servers or clients (rpz-ip,
// rpz-nsdname, rpz-nsip, rpz-client-ip) cannot apply to a domain list and
// are skipped. The zone's SOA and NS records are neither taken nor skipped.
// "*.x" blocks x as well: feeds list both.

// zoneState is what a zone file's directives and records set for the lines
// after them.
type zoneState struct {
	origin string // lowercase, with the final dot; "" when not set
	paren  bool   // inside ( ... ) of a record split over lines
}

// directive handles $ORIGIN, $TTL and $INCLUDE lines and reports whether
// line was one.
func (z *zoneState) directive(line string) bool {
	f := strings.Fields(stripZoneComment(line))
	if len(f) == 0 {
		return false
	}
	switch strings.ToUpper(f[0]) {
	case "$ORIGIN":
		if len(f) > 1 {
			z.origin = strings.ToLower(f[1])
			if !strings.HasSuffix(z.origin, ".") {
				z.origin += "."
			}
		}
		return true
	case "$TTL", "$INCLUDE":
		return true
	}
	return false
}

// record reads one zone record (comments already removed) into b. A line
// that is not a record is skipped.
func (z *zoneState) record(line string, b *Builder, c *Counts) {
	if strings.Count(line, "(") > strings.Count(line, ")") {
		z.paren = true
	}
	owner, typ, data, ok := rpzRecord(strings.Fields(line))
	switch {
	case !ok:
		c.Skipped++
		return
	case typ == "SOA" || typ == "NS" || owner == "" || owner == "@":
		return // the zone's own records
	}
	name, ok := z.relative(strings.ToLower(owner))
	if !ok {
		c.Skipped++ // a name outside the zone
		return
	}
	wild := strings.HasPrefix(name, "*.")
	name = strings.TrimPrefix(name, "*.")
	for _, t := range []string{"rpz-ip", "rpz-nsdname", "rpz-nsip", "rpz-client-ip"} {
		if name == t || strings.HasSuffix(name, "."+t) {
			c.Skipped++
			return
		}
	}
	switch {
	case typ == "CNAME" && (strings.EqualFold(data, "rpz-passthru.") || strings.EqualFold(data, "rpz-tcp-only.")):
		c.Skipped++
		return
	case typ != "CNAME" && typ != "A" && typ != "AAAA":
		c.Skipped++
		return
	}
	var added bool
	if wild {
		added = b.Block(name)
	} else {
		added = b.BlockExact(name)
	}
	if added {
		c.Block++
	} else {
		c.Skipped++
	}
}

// relative returns owner relative to the zone: unchanged when written
// relative, with the origin removed when written in full (ending in a dot).
func (z *zoneState) relative(owner string) (string, bool) {
	if !strings.HasSuffix(owner, ".") {
		return owner, true
	}
	if z.origin == "" || !strings.HasSuffix(owner, "."+z.origin) {
		return "", false
	}
	return strings.TrimSuffix(owner, "."+z.origin), true
}

// rpzRecord splits the fields of a zone record: owner [ttl] [class] type
// data. The type is uppercase. A record without an owner (one that
// continues the previous owner) has owner "".
func rpzRecord(f []string) (owner, typ, data string, ok bool) {
	i := 0
	if len(f) > 0 && !isTTL(f[0]) && !isClass(f[0]) && !isType(f[0]) {
		owner, i = f[0], 1
	}
	for n := 0; n < 2 && i < len(f) && (isTTL(f[i]) || isClass(f[i])); n++ {
		i++
	}
	if i >= len(f) || !isType(f[i]) {
		return "", "", "", false
	}
	typ = strings.ToUpper(f[i])
	if i+1 < len(f) {
		data = f[i+1]
	}
	return owner, typ, data, true
}

func isTTL(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func isClass(s string) bool {
	switch strings.ToUpper(s) {
	case "IN", "CH", "HS", "CS":
		return true
	}
	return false
}

func isType(s string) bool {
	switch strings.ToUpper(s) {
	case "CNAME", "A", "AAAA", "SOA", "NS", "TXT", "MX", "PTR", "SRV", "DNAME", "HTTPS", "SVCB", "CAA":
		return true
	}
	return false
}

// stripZoneComment removes a ";" comment.
func stripZoneComment(line string) string {
	if i := strings.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}
