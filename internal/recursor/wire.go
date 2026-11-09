// Package recursor resolves names itself, starting from the root servers,
// and validates the answers with DNSSEC. It implements resolver.Exchanger,
// so the resolver's cache, limits and filtering work as with upstreams.
package recursor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Names are kept in wire format without the final zero byte, lowercased,
// as in dnsmsg.Query.Name; the root is "". Record data keeps the case it
// arrived with (it matters for some types) with compressed names expanded.

// Record types beyond those in dnsmsg.
const (
	typeMX     = 15
	typeTXT    = 16
	typeSRV    = 33
	typeDNAME  = 39
	typeDS     = 43
	typeRRSIG  = 46
	typeNSEC   = 47
	typeDNSKEY = 48
	typeNSEC3  = 50
	typeNSEC3P = 51
)

var errFormat = errors.New("malformed response")

// rr is one resource record.
type rr struct {
	name  string // lowercase wire name
	typ   uint16
	class uint16
	ttl   uint32
	data  []byte // record data, names expanded
}

// message is a parsed response.
type message struct {
	id, flags  uint16
	rcode      int
	qname      string
	qtype      uint16
	answer     []rr
	authority  []rr
	additional []rr
	edns       bool
	ede        []uint16 // Extended DNS Error codes the server sent
}

func (msg *message) aa() bool { return msg.flags&m.FlagAA != 0 }
func (msg *message) tc() bool { return msg.flags&m.FlagTC != 0 }

// readName reads a possibly compressed name at off. It returns the name in
// wire format without the final zero, in its original case, and the offset
// after the name where it started.
func readName(b []byte, off int) ([]byte, int, error) {
	var name []byte
	end := -1
	for jumps := 0; ; {
		if off >= len(b) {
			return nil, 0, errFormat
		}
		c := int(b[off])
		switch {
		case c == 0:
			if end < 0 {
				end = off + 1
			}
			if len(name) > 254 {
				return nil, 0, errFormat
			}
			return name, end, nil
		case c&0xC0 == 0xC0:
			if off+1 >= len(b) {
				return nil, 0, errFormat
			}
			if end < 0 {
				end = off + 2
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3FFF)
			if ptr >= off || jumps > 64 { // only backwards: no loops
				return nil, 0, errFormat
			}
			jumps++
			off = ptr
		case c&0xC0 != 0:
			return nil, 0, errFormat
		default:
			if off+1+c > len(b) {
				return nil, 0, errFormat
			}
			name = append(name, b[off:off+1+c]...)
			off += 1 + c
			if len(name) > 254 {
				return nil, 0, errFormat
			}
		}
	}
}

func lower(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// layout describes where names are inside record data, for expanding
// compression and for the canonical form used by DNSSEC (RFC 4034 6.2).
// 'N' a name, digits a fixed number of bytes, 'S' a character string,
// 'R' the rest.
var layouts = map[uint16]string{
	2: "N", 3: "N", 4: "N", 5: "N", 7: "N", 8: "N", 9: "N", 12: "N", typeDNAME: "N",
	6:  "NN\x14",       // SOA: two names, 20 bytes
	14: "NN", 17: "NN", // MINFO, RP
	15: "\x02N", 18: "\x02N", 21: "\x02N", 36: "\x02N", // MX, AFSDB, RT, KX
	26:        "\x02NN",   // PX
	typeSRV:   "\x06N",    // SRV
	35:        "\x04SSSN", // NAPTR
	typeRRSIG: "\x12NR",   // RRSIG: 18 bytes, signer, signature
	typeNSEC:  "NR",       // next name, type bitmaps
}

// compressible types may carry compressed names (RFC 3597 section 4).
func compressible(t uint16) bool {
	switch t {
	case 2, 3, 4, 5, 6, 7, 8, 9, 12, 14, 15:
		return true
	}
	return false
}

// expandRdata copies record data, expanding compressed names.
func expandRdata(b []byte, typ uint16, off, n int) ([]byte, error) {
	end := off + n
	if end > len(b) {
		return nil, errFormat
	}
	lay, ok := layouts[typ]
	if !ok {
		return slices.Clone(b[off:end]), nil
	}
	out := make([]byte, 0, n+16)
	for i := 0; i < len(lay); i++ {
		switch c := lay[i]; c {
		case 'N':
			name, next, err := readName(b, off)
			if err != nil || next > end {
				return nil, errFormat
			}
			out = append(append(out, name...), 0)
			off = next
		case 'S':
			if off >= end || off+1+int(b[off]) > end {
				return nil, errFormat
			}
			out = append(out, b[off:off+1+int(b[off])]...)
			off += 1 + int(b[off])
		case 'R':
			out = append(out, b[off:end]...)
			off = end
		default:
			if off+int(c) > end {
				return nil, errFormat
			}
			out = append(out, b[off:off+int(c)]...)
			off += int(c)
		}
	}
	if off != end {
		return nil, errFormat
	}
	return out, nil
}

// eachName calls fn with the start and end of every name in expanded
// record data (end includes the zero byte).
func eachName(typ uint16, data []byte, fn func(start, end int)) bool {
	lay, ok := layouts[typ]
	if !ok {
		return true
	}
	off := 0
	for i := 0; i < len(lay); i++ {
		switch c := lay[i]; c {
		case 'N':
			s := off
			for {
				if off >= len(data) {
					return false
				}
				l := int(data[off])
				off += 1 + l
				if l == 0 {
					break
				}
			}
			if off > len(data) {
				return false
			}
			fn(s, off)
		case 'S':
			if off >= len(data) {
				return false
			}
			off += 1 + int(data[off])
		case 'R':
			off = len(data)
		default:
			off += int(c)
		}
		if off > len(data) {
			return false
		}
	}
	return true
}

// canonicalRdata returns data with the names that RFC 4034 6.2 (as amended
// by RFC 6840 5.1: not NSEC) lowercases.
func canonicalRdata(typ uint16, data []byte) []byte {
	if _, ok := layouts[typ]; !ok || typ == typeNSEC {
		return data
	}
	out := slices.Clone(data)
	eachName(typ, out, func(s, e int) {
		for i := s; i < e; i++ {
			if out[i] >= 'A' && out[i] <= 'Z' {
				out[i] += 'a' - 'A'
			}
		}
	})
	return out
}

// parseMessage parses a response.
func parseMessage(b []byte) (*message, error) {
	if len(b) < m.HeaderLen {
		return nil, errFormat
	}
	msg := &message{id: m.U16(b, 0), flags: m.U16(b, 2)}
	msg.rcode = int(msg.flags & 0xF)
	qd, an, ns, ar := int(m.U16(b, 4)), int(m.U16(b, 6)), int(m.U16(b, 8)), int(m.U16(b, 10))
	if qd != 1 {
		return nil, errFormat
	}
	name, off, err := readName(b, m.HeaderLen)
	if err != nil || off+4 > len(b) {
		return nil, errFormat
	}
	msg.qname, msg.qtype = lower(name), m.U16(b, off)
	off += 4
	read := func(n int, dst *[]rr, add bool) error {
		for i := 0; i < n; i++ {
			name, next, err := readName(b, off)
			if err != nil || next+10 > len(b) {
				return errFormat
			}
			r := rr{name: lower(name), typ: m.U16(b, next), class: m.U16(b, next+2), ttl: m.U32(b, next+4)}
			rdl := int(m.U16(b, next+8))
			if next+10+rdl > len(b) {
				return errFormat
			}
			if r.ttl > 1<<31-1 {
				r.ttl = 0 // RFC 2181 section 8
			}
			if r.typ == m.TypeOPT {
				if !add || msg.edns {
					return errFormat
				}
				msg.edns = true
				msg.rcode |= int(b[next+4]) << 4 // extended rcode
				rd := b[next+10 : next+10+rdl]
				for len(rd) >= 4 {
					code, l := binary.BigEndian.Uint16(rd), int(binary.BigEndian.Uint16(rd[2:]))
					if 4+l > len(rd) {
						break
					}
					if code == m.OptEDE && l >= 2 {
						msg.ede = append(msg.ede, binary.BigEndian.Uint16(rd[4:]))
					}
					rd = rd[4+l:]
				}
				off = next + 10 + rdl
				continue
			}
			if r.data, err = expandRdata(b, r.typ, next+10, rdl); err != nil {
				return err
			}
			*dst = append(*dst, r)
			off = next + 10 + rdl
		}
		return nil
	}
	if err := read(an, &msg.answer, false); err != nil {
		return nil, err
	}
	if err := read(ns, &msg.authority, false); err != nil {
		return nil, err
	}
	if err := read(ar, &msg.additional, true); err != nil {
		return nil, err
	}
	return msg, nil
}

// ---- names ----

// labelCount returns the number of labels in a wire name.
func labelCount(name string) int {
	n := 0
	for i := 0; i < len(name); i += 1 + int(name[i]) {
		n++
	}
	return n
}

// parent strips the first label ("" for the root and top-level names).
func parent(name string) string {
	if name == "" {
		return ""
	}
	return name[1+int(name[0]):]
}

// isSub reports whether name is zone or below it.
func isSub(name, zone string) bool {
	if zone == "" {
		return true
	}
	if len(name) < len(zone) || name[len(name)-len(zone):] != zone {
		return false
	}
	// the suffix must start at a label boundary
	for i := 0; i < len(name); i += 1 + int(name[i]) {
		if i == len(name)-len(zone) {
			return true
		}
	}
	return false
}

// ancestorAt returns the ancestor of name that has n labels.
func ancestorAt(name string, n int) string {
	for labelCount(name) > n {
		name = parent(name)
	}
	return name
}

// labelsOf splits a wire name into labels, left to right.
func labelsOf(name string) []string {
	var out []string
	for i := 0; i < len(name); i += 1 + int(name[i]) {
		out = append(out, name[i+1:i+1+int(name[i])])
	}
	return out
}

// canonicalCompare orders names as RFC 4034 6.1: label by label from the
// right, each compared as lowercase bytes.
func canonicalCompare(a, b string) int {
	la, lb := labelsOf(a), labelsOf(b)
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare([]byte(lowerStr(la[i])), []byte(lowerStr(lb[j]))); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

func lowerStr(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return lower([]byte(s))
		}
	}
	return s
}

// ---- building messages ----

// builder writes a message, compressing owner names and the names inside
// the record types that allow it.
type builder struct {
	b     []byte
	names map[string]int // suffix (lowercase wire name) -> offset
}

func (w *builder) name(n []byte) {
	ln := lower(n)
	for i := 0; i < len(ln); i += 1 + int(ln[i]) {
		if off, ok := w.names[ln[i:]]; ok {
			w.b = append(w.b, n[:i]...)
			w.b = append(w.b, byte(0xC0|off>>8), byte(off))
			return
		}
		if len(w.b) < 0x3FFF {
			w.names[ln[i:]] = len(w.b) + i
		}
	}
	w.b = append(append(w.b, n...), 0)
}

func (w *builder) rr(r rr) {
	w.name([]byte(r.name))
	w.b = binary.BigEndian.AppendUint16(w.b, r.typ)
	w.b = binary.BigEndian.AppendUint16(w.b, r.class)
	w.b = binary.BigEndian.AppendUint32(w.b, r.ttl)
	lenOff := len(w.b)
	w.b = append(w.b, 0, 0)
	if compressible(r.typ) {
		last := 0
		eachName(r.typ, r.data, func(s, e int) {
			w.b = append(w.b, r.data[last:s]...)
			w.name(r.data[s : e-1])
			last = e
		})
		w.b = append(w.b, r.data[last:]...)
	} else {
		w.b = append(w.b, r.data...)
	}
	binary.BigEndian.PutUint16(w.b[lenOff:], uint16(len(w.b)-lenOff-2))
}

// buildMessage writes a response to qname/qtype.
func buildMessage(id, flags uint16, qname string, qtype uint16, an, ns, ar []rr, edns bool, do bool, ede []byte) []byte {
	w := &builder{b: make([]byte, 0, 512), names: map[string]int{}}
	arc := len(ar)
	if edns {
		arc++
	}
	w.b = append(w.b, byte(id>>8), byte(id), byte(flags>>8), byte(flags), 0, 1,
		byte(len(an)>>8), byte(len(an)), byte(len(ns)>>8), byte(len(ns)), byte(arc>>8), byte(arc))
	w.name([]byte(qname))
	w.b = binary.BigEndian.AppendUint16(w.b, qtype)
	w.b = binary.BigEndian.AppendUint16(w.b, m.ClassIN)
	for _, sec := range [][]rr{an, ns, ar} {
		for _, r := range sec {
			w.rr(r)
		}
	}
	if edns {
		w.b = m.AppendOPT(w.b, m.EDNSSize, do)
		if len(ede) > 0 {
			l := len(w.b)
			binary.BigEndian.PutUint16(w.b[l-2:], uint16(len(ede)))
			w.b = append(w.b, ede...)
		}
	}
	return w.b
}

// typeBitmapHas reports whether an NSEC/NSEC3 type bitmap includes t.
func typeBitmapHas(bm []byte, t uint16) bool {
	win, bit := byte(t>>8), t&0xFF
	for len(bm) >= 2 {
		w, l := bm[0], int(bm[1])
		if l < 1 || l > 32 || 2+l > len(bm) {
			return false
		}
		if w == win {
			i := int(bit / 8)
			return i < l && bm[2+i]&(0x80>>(bit%8)) != 0
		}
		bm = bm[2+l:]
	}
	return false
}
