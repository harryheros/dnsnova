// Package dnsmsg implements the small part of the DNS wire format that
// dnsnova needs. It never interprets record data: it reads the question
// (for cache keys), finds TTL fields (to age cached answers) and handles the
// EDNS OPT record. Everything else is passed through byte for byte.
//
// Every read is bounds-checked; malformed input returns ErrMalformed and
// never panics. The parsers are covered by fuzz tests.
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// Wire constants.
const (
	HeaderLen = 12

	TypeA     = 1
	TypeNS    = 2
	TypeCNAME = 5
	TypeSOA   = 6
	TypePTR   = 12
	TypeAAAA  = 28
	TypeOPT   = 41
	TypeSVCB  = 64
	TypeHTTPS = 65
	TypeIXFR  = 251
	TypeAXFR  = 252
	TypeANY   = 255

	ClassIN = 1

	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5

	FlagQR = 1 << 15
	FlagAA = 1 << 10
	FlagTC = 1 << 9
	FlagRD = 1 << 8
	FlagRA = 1 << 7
	FlagAD = 1 << 5
	FlagCD = 1 << 4

	// EDNSSize is the UDP payload size dnsnova advertises and uses upstream
	// (DNS flag day 2020 recommendation).
	EDNSSize = 1232

	maxNameLen = 255
)

// ErrMalformed reports a message that does not follow the wire format.
var ErrMalformed = errors.New("malformed dns message")

// U16 reads a big-endian uint16. The caller must have checked bounds.
func U16(b []byte, off int) uint16 { return binary.BigEndian.Uint16(b[off:]) }

// U32 reads a big-endian uint32. The caller must have checked bounds.
func U32(b []byte, off int) uint32 { return binary.BigEndian.Uint32(b[off:]) }

// Query is a parsed client query.
type Query struct {
	ID      uint16
	Flags   uint16
	Name    string // wire-format name, lowercased, without the final zero byte
	Type    uint16
	Class   uint16
	QEnd    int // offset just after the question section; 0 if not parsed
	EDNS    bool
	UDPSize uint16
	DO      bool
}

// CacheKey identifies answers that may be shared between clients: the same
// name, type and class, and the same DNSSEC-related flags (DO, CD).
func (q *Query) CacheKey() string {
	var bits byte
	if q.DO {
		bits |= 1
	}
	if q.Flags&FlagCD != 0 {
		bits |= 2
	}
	return q.Name + string([]byte{byte(q.Type >> 8), byte(q.Type), byte(q.Class >> 8), byte(q.Class), bits})
}

// SkipName returns the offset just after the (possibly compressed) name at off.
func SkipName(msg []byte, off int) (int, error) {
	for hops := 0; hops < 128; hops++ {
		if off < 0 || off >= len(msg) {
			return 0, ErrMalformed
		}
		c := int(msg[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				return off + 1, nil
			}
			off += 1 + c
		case 0xC0:
			if off+2 > len(msg) {
				return 0, ErrMalformed
			}
			return off + 2, nil
		default:
			return 0, ErrMalformed
		}
	}
	return 0, ErrMalformed
}

// ReadQName reads an uncompressed name (as in a question section) and returns
// it lowercased in wire format without the final zero, plus the offset after it.
func ReadQName(msg []byte, off int) (string, int, error) {
	start := off
	var b []byte
	for {
		if off < 0 || off >= len(msg) {
			return "", 0, ErrMalformed
		}
		c := int(msg[off])
		if c == 0 {
			off++
			break
		}
		if c&0xC0 != 0 || off+1+c > len(msg) {
			return "", 0, ErrMalformed
		}
		b = append(b, byte(c))
		for _, ch := range msg[off+1 : off+1+c] {
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			b = append(b, ch)
		}
		off += 1 + c
		if off-start > maxNameLen {
			return "", 0, ErrMalformed
		}
	}
	return string(b), off, nil
}

// RR describes one resource record inside a message.
type RR struct {
	Type, Class uint16
	TTLOff      int // offset of the 32-bit TTL field
	RDOff       int // offset of the record data
	RDLen       int
	Start, End  int // the whole record, including its owner name
}

// WalkRRs walks n records starting at off, calls fn for each and returns the
// offset after them.
func WalkRRs(msg []byte, off, n int, fn func(rr RR) error) (int, error) {
	for i := 0; i < n; i++ {
		start := off
		var err error
		if off, err = SkipName(msg, off); err != nil {
			return 0, err
		}
		if off+10 > len(msg) {
			return 0, ErrMalformed
		}
		rr := RR{
			Type:   U16(msg, off),
			Class:  U16(msg, off+2),
			TTLOff: off + 4,
			RDLen:  int(U16(msg, off+8)),
			RDOff:  off + 10,
			Start:  start,
		}
		off = rr.RDOff + rr.RDLen
		if off > len(msg) {
			return 0, ErrMalformed
		}
		rr.End = off
		if fn != nil {
			if err := fn(rr); err != nil {
				return 0, err
			}
		}
	}
	return off, nil
}

// ParseQuery parses a client query. A non-nil error means the packet should
// be dropped silently; a non-zero rcode means an error response should be sent.
func ParseQuery(msg []byte) (*Query, int, error) {
	if len(msg) < HeaderLen {
		return nil, 0, ErrMalformed
	}
	q := &Query{ID: U16(msg, 0), Flags: U16(msg, 2)}
	if q.Flags&FlagQR != 0 {
		return nil, 0, ErrMalformed // a response, not a query
	}
	if (q.Flags>>11)&0xF != 0 {
		return q, RcodeNotImp, nil // only standard QUERY
	}
	qd, an, ns, ar := U16(msg, 4), U16(msg, 6), U16(msg, 8), U16(msg, 10)
	if qd != 1 {
		return q, RcodeFormErr, nil
	}
	name, off, err := ReadQName(msg, HeaderLen)
	if err != nil || off+4 > len(msg) {
		return q, RcodeFormErr, nil
	}
	q.Name, q.Type, q.Class = name, U16(msg, off), U16(msg, off+2)
	off += 4
	q.QEnd = off

	if off, err = WalkRRs(msg, off, int(an)+int(ns), nil); err != nil {
		return q, RcodeFormErr, nil
	}
	_, err = WalkRRs(msg, off, int(ar), func(rr RR) error {
		if rr.Type == TypeOPT {
			if q.EDNS || msg[rr.Start] != 0 {
				return ErrMalformed // duplicate OPT, or OPT not owned by the root
			}
			q.EDNS = true
			q.UDPSize = rr.Class
			q.DO = msg[rr.TTLOff+2]&0x80 != 0
		}
		return nil
	})
	if err != nil {
		q.EDNS = false
		return q, RcodeFormErr, nil
	}
	return q, 0, nil
}

// BuildUpstreamQuery builds the query sent upstream: RD set, CD copied from
// the client and dnsnova's own OPT record. Client EDNS options (cookies,
// padding, ECS) are not forwarded. The message ID is set by each upstream.
func BuildUpstreamQuery(q *Query) []byte {
	b := make([]byte, 0, HeaderLen+len(q.Name)+5+11)
	flags := uint16(FlagRD) | q.Flags&FlagCD
	b = append(b, 0, 0, byte(flags>>8), byte(flags), 0, 1, 0, 0, 0, 0, 0, 1)
	b = append(b, q.Name...)
	b = append(b, 0, byte(q.Type>>8), byte(q.Type), byte(q.Class>>8), byte(q.Class))
	return AppendOPT(b, EDNSSize, q.DO)
}

// AppendOPT appends an OPT record with no options.
func AppendOPT(b []byte, size uint16, do bool) []byte {
	var doBit byte
	if do {
		doBit = 0x80
	}
	return append(b, 0, 0, TypeOPT, byte(size>>8), byte(size), 0, 0, doBit, 0, 0, 0)
}

// WithID returns a copy of msg with a new message ID.
func WithID(msg []byte, id uint16) []byte {
	c := make([]byte, len(msg))
	copy(c, msg)
	binary.BigEndian.PutUint16(c, id)
	return c
}

// MatchResponse reports whether resp answers query: same ID, QR set and the
// same question, compared case-insensitively.
func MatchResponse(query, resp []byte) bool {
	if len(resp) < HeaderLen || len(query) < HeaderLen {
		return false
	}
	if U16(resp, 0) != U16(query, 0) || U16(resp, 2)&FlagQR == 0 || U16(resp, 4) != 1 {
		return false
	}
	_, qEnd, err := ReadQName(query, HeaderLen)
	if err != nil || qEnd+4 > len(query) {
		return false
	}
	qEnd += 4
	if len(resp) < qEnd {
		return false
	}
	return asciiEqualFold(query[HeaderLen:qEnd], resp[HeaderLen:qEnd])
}

func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// header returns a response header for req with the given rcode and counts.
func header(req []byte, rcode int, qd, an, ns, ar uint16) []byte {
	reqFlags := U16(req, 2)
	flags := uint16(FlagQR|FlagRA) | reqFlags&(FlagRD|FlagCD|0x7800) | uint16(rcode&0xF)
	return []byte{req[0], req[1], byte(flags >> 8), byte(flags),
		byte(qd >> 8), byte(qd), byte(an >> 8), byte(an), byte(ns >> 8), byte(ns), byte(ar >> 8), byte(ar)}
}

// ErrorResponse builds a minimal response for req carrying only rcode, the
// question (when it was parsed) and an OPT record (when the client sent one).
func ErrorResponse(req []byte, q *Query, rcode int) []byte {
	var qd, ar uint16
	if q != nil && q.QEnd > 0 {
		qd = 1
	}
	if q != nil && q.EDNS {
		ar = 1
	}
	b := header(req, rcode, qd, 0, 0, ar)
	if qd == 1 {
		b = append(b, req[HeaderLen:q.QEnd]...)
	}
	if ar == 1 {
		b = AppendOPT(b, EDNSSize, q.DO)
	}
	return b
}

// Truncated returns a TC=1 response for req carrying only the question, which
// tells a UDP client to retry over TCP.
func Truncated(req []byte, q *Query, rcode int) []byte {
	b := ErrorResponse(req, q, rcode)
	b[2] |= byte(FlagTC >> 8)
	return b
}

// NegativeSOA builds a negative response (rcode NXDOMAIN, or NOERROR for
// "no records of this type") with a synthesized SOA for zone (wire format,
// lowercase, no final zero) in the authority section, as used for locally
// answered names (RFC 6303). AD is never set.
func NegativeSOA(req []byte, q *Query, zone string, ttl uint32, rcode int) []byte {
	var ar uint16
	if q.EDNS {
		ar = 1
	}
	b := header(req, rcode, 1, 0, 1, ar)
	b[2] |= byte(FlagAA >> 8)
	b = append(b, req[HeaderLen:q.QEnd]...)
	b = append(b, zone...)
	b = append(b, 0)
	rd := make([]byte, 0, 64)
	rd = append(rd, zone...) // MNAME = the zone itself
	rd = append(rd, 0)
	rd = append(rd, 6, 'n', 'o', 'b', 'o', 'd', 'y', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0) // RNAME
	for _, v := range []uint32{1, 604800, 86400, 2419200, ttl} {
		rd = binary.BigEndian.AppendUint32(rd, v)
	}
	b = append(b, 0, TypeSOA, 0, ClassIN)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
	b = append(b, rd...)
	if q.EDNS {
		b = AppendOPT(b, EDNSSize, q.DO)
	}
	return b
}

// Answer builds a response with one record of q's name, type and class
// holding rdata (for example 127.0.0.1 for localhost). AD is never set.
func Answer(req []byte, q *Query, ttl uint32, rdata []byte) []byte {
	return AnswerMulti(req, q, ttl, [][]byte{rdata})
}

// AnswerMulti builds a response with one record per rdata, all of q's name,
// type and class. AD is never set.
func AnswerMulti(req []byte, q *Query, ttl uint32, rdatas [][]byte) []byte {
	var ar uint16
	if q.EDNS {
		ar = 1
	}
	b := header(req, RcodeNoError, 1, uint16(len(rdatas)), 0, ar)
	b[2] |= byte(FlagAA >> 8)
	b = append(b, req[HeaderLen:q.QEnd]...)
	for _, rd := range rdatas {
		b = append(b, 0xC0, HeaderLen, byte(q.Type>>8), byte(q.Type), byte(q.Class>>8), byte(q.Class))
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
		b = append(b, rd...)
	}
	if q.EDNS {
		b = AppendOPT(b, EDNSSize, q.DO)
	}
	return b
}

// SVCB parameter keys (RFC 9460, RFC 9461).
const (
	SvcALPN     = 1
	SvcPort     = 3
	SvcIPv4Hint = 4
	SvcIPv6Hint = 6
	SvcDoHPath  = 7
)

// SvcParam is one SVCB parameter; Value is its wire-format value.
type SvcParam struct {
	Key   uint16
	Value []byte
}

// SVCB encodes SVCB record data. target is a wire-format name without the
// final zero (empty for "."). Params must be sorted by key.
func SVCB(priority uint16, target string, params []SvcParam) []byte {
	b := binary.BigEndian.AppendUint16(nil, priority)
	b = append(b, target...)
	b = append(b, 0)
	for _, p := range params {
		b = binary.BigEndian.AppendUint16(b, p.Key)
		b = binary.BigEndian.AppendUint16(b, uint16(len(p.Value)))
		b = append(b, p.Value...)
	}
	return b
}

// NoData builds an empty NOERROR response (the name exists, no records of
// this type). AD is never set.
func NoData(req []byte, q *Query) []byte {
	b := ErrorResponse(req, q, RcodeNoError)
	b[2] |= byte(FlagAA >> 8)
	return b
}

// ResponseMinTTL returns the smallest TTL in the answer section, or for a
// negative answer the TTL of the SOA in the authority section.
func ResponseMinTTL(msg []byte) uint32 {
	if len(msg) < HeaderLen || U16(msg, 4) != 1 {
		return 0
	}
	off, err := SkipName(msg, HeaderLen)
	if err != nil || off+4 > len(msg) {
		return 0
	}
	off += 4
	an, ns := int(U16(msg, 6)), int(U16(msg, 8))
	var min uint32
	found := false
	off, err = WalkRRs(msg, off, an, func(rr RR) error {
		if rr.Type != TypeOPT {
			if t := U32(msg, rr.TTLOff); !found || t < min {
				min, found = t, true
			}
		}
		return nil
	})
	if err != nil || found {
		return min
	}
	WalkRRs(msg, off, ns, func(rr RR) error {
		if rr.Type == TypeSOA && !found {
			min, found = U32(msg, rr.TTLOff), true
		}
		return nil
	})
	return min
}

// Rcode returns the response code of msg, or -1 if msg is too short.
func Rcode(msg []byte) int {
	if len(msg) < HeaderLen {
		return -1
	}
	return int(U16(msg, 2) & 0xF)
}

// NameString converts a wire-format name (as in Query.Name) to dotted form.
func NameString(name string) string {
	if name == "" {
		return "."
	}
	var sb strings.Builder
	for i := 0; i < len(name); {
		l := int(name[i])
		i++
		if i+l > len(name) {
			break
		}
		sb.WriteString(name[i : i+l])
		sb.WriteByte('.')
		i += l
	}
	return sb.String()
}

// Labels splits a wire-format name into its labels.
func Labels(name string) []string {
	var out []string
	for i := 0; i < len(name); {
		l := int(name[i])
		i++
		if i+l > len(name) {
			break
		}
		out = append(out, name[i:i+l])
		i += l
	}
	return out
}

// WireName converts dotted labels to a wire-format name without the final zero.
func WireName(labels ...string) string {
	var b []byte
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return string(b)
}

var typeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
	28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
	64: "SVCB", 65: "HTTPS", 99: "SPF", 252: "AXFR", 255: "ANY", 257: "CAA",
}

// TypeString returns the mnemonic for a record type.
func TypeString(t uint16) string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

var rcodeNames = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

// RcodeString returns the mnemonic for a response code.
func RcodeString(rc int) string {
	if rc >= 0 && rc < len(rcodeNames) {
		return rcodeNames[rc]
	}
	return "RCODE" + strconv.Itoa(rc)
}
