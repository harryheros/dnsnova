package recursor

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
	"time"
)

// DNSSEC algorithm numbers (RFC 8624).
const (
	algRSASHA1      = 5
	algRSASHA1NSEC3 = 7
	algRSASHA256    = 8
	algRSASHA512    = 10
	algECDSAP256    = 13
	algECDSAP384    = 14
	algED25519      = 15
	digestSHA1      = 1
	digestSHA256    = 2
	digestSHA384    = 4
	keyFlagZone     = 0x0100
	keyFlagRevoke   = 0x0080
	keyFlagSEP      = 0x0001
	maxKeysPerSet   = 16 // more keys are not tried (KeyTrap, CVE-2023-50387)
	maxSigsPerRRset = 8
	maxValidations  = 64 // signature checks per resolution
	minRSABits      = 1024
	maxRSABits      = 4096
)

func algSupported(a uint8) bool {
	switch a {
	case algRSASHA1, algRSASHA1NSEC3, algRSASHA256, algRSASHA512, algECDSAP256, algECDSAP384, algED25519:
		return true
	}
	return false
}

func digestSupported(d uint8) bool {
	return d == digestSHA1 || d == digestSHA256 || d == digestSHA384
}

var (
	errSigExpired = errors.New("signature expired")
	errSigNotYet  = errors.New("signature not yet valid")
	errSigBad     = errors.New("signature does not verify")
	errNoKey      = errors.New("no key for the signature")
	errNoSig      = errors.New("no signature")
)

// rrset is one RRset with the signatures that cover it.
type rrset struct {
	name  string
	typ   uint16
	class uint16
	ttl   uint32
	data  [][]byte
	sigs  [][]byte // RRSIG record data
}

func (s *rrset) records() []rr {
	out := make([]rr, 0, len(s.data))
	for _, d := range s.data {
		out = append(out, rr{name: s.name, typ: s.typ, class: s.class, ttl: s.ttl, data: d})
	}
	return out
}

func (s *rrset) sigRecords(ttl uint32) []rr {
	out := make([]rr, 0, len(s.sigs))
	for _, d := range s.sigs {
		out = append(out, rr{name: s.name, typ: typeRRSIG, class: s.class, ttl: ttl, data: d})
	}
	return out
}

// groupRRsets turns records into RRsets and attaches each RRSIG to the set
// it covers. RRSIGs that cover nothing present are dropped.
func groupRRsets(rrs []rr) []*rrset {
	var sets []*rrset
	idx := map[string]*rrset{}
	key := func(name string, t, c uint16) string {
		return name + string([]byte{byte(t >> 8), byte(t), byte(c >> 8), byte(c)})
	}
	for _, r := range rrs {
		if r.typ == typeRRSIG {
			continue
		}
		k := key(r.name, r.typ, r.class)
		s := idx[k]
		if s == nil {
			s = &rrset{name: r.name, typ: r.typ, class: r.class, ttl: r.ttl}
			idx[k] = s
			sets = append(sets, s)
		}
		s.ttl = min(s.ttl, r.ttl) // RFC 2181 5.2
		if !slices.ContainsFunc(s.data, func(d []byte) bool { return bytes.Equal(d, r.data) }) {
			s.data = append(s.data, r.data)
		}
	}
	for _, r := range rrs {
		if r.typ != typeRRSIG || len(r.data) < 18 {
			continue
		}
		covered := binary.BigEndian.Uint16(r.data)
		if s := idx[key(r.name, covered, r.class)]; s != nil && len(s.sigs) < maxSigsPerRRset {
			s.sigs = append(s.sigs, r.data)
			s.ttl = min(s.ttl, r.ttl) // RFC 4035 5.3.3: no longer than the RRSIG's own TTL
		}
	}
	return sets
}

// sig is a parsed RRSIG.
type sig struct {
	covered      uint16
	alg, labels  uint8
	origTTL      uint32
	exp, inc     uint32
	tag          uint16
	signer       string // lowercase wire name
	signed, data []byte // the RDATA up to the signature (signer lowercased), the signature
}

func parseSig(d []byte) (*sig, bool) {
	if len(d) < 19 {
		return nil, false
	}
	s := &sig{covered: binary.BigEndian.Uint16(d), alg: d[2], labels: d[3], origTTL: binary.BigEndian.Uint32(d[4:]),
		exp: binary.BigEndian.Uint32(d[8:]), inc: binary.BigEndian.Uint32(d[12:]), tag: binary.BigEndian.Uint16(d[16:])}
	off := 18
	for {
		if off >= len(d) {
			return nil, false
		}
		l := int(d[off])
		if l == 0 {
			off++
			break
		}
		if l > 63 {
			return nil, false
		}
		off += 1 + l
	}
	if off > len(d) || off-18 > 255 {
		return nil, false
	}
	s.signer = lower(d[18 : off-1])
	s.signed = append(slices.Clone(d[:18]), s.signer...)
	s.signed = append(s.signed, 0)
	s.data = d[off:]
	return s, len(s.data) > 0
}

// dnskey is a parsed DNSKEY.
type dnskey struct {
	flags uint16
	alg   uint8
	tag   uint16
	rdata []byte
	pub   crypto.PublicKey // nil if the key cannot be used
}

func parseKey(d []byte) (*dnskey, bool) {
	if len(d) < 5 || d[2] != 3 {
		return nil, false
	}
	k := &dnskey{flags: binary.BigEndian.Uint16(d), alg: d[3], tag: keyTag(d), rdata: d}
	k.pub = publicKey(k.alg, d[4:])
	return k, true
}

// keyTag computes the key tag of DNSKEY record data (RFC 4034 appendix B).
func keyTag(d []byte) uint16 {
	var ac uint32
	for i, c := range d {
		if i&1 == 0 {
			ac += uint32(c) << 8
		} else {
			ac += uint32(c)
		}
	}
	ac += ac >> 16 & 0xFFFF
	return uint16(ac)
}

func publicKey(alg uint8, k []byte) crypto.PublicKey {
	switch alg {
	case algRSASHA1, algRSASHA1NSEC3, algRSASHA256, algRSASHA512:
		if len(k) < 3 {
			return nil
		}
		el, off := int(k[0]), 1
		if el == 0 {
			el, off = int(binary.BigEndian.Uint16(k[1:])), 3
		}
		if el == 0 || el > 8 || off+el >= len(k) {
			return nil
		}
		e := new(big.Int).SetBytes(k[off : off+el])
		n := new(big.Int).SetBytes(k[off+el:])
		if !e.IsInt64() || e.Int64() < 3 || n.BitLen() < minRSABits || n.BitLen() > maxRSABits {
			return nil
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}
	case algECDSAP256, algECDSAP384:
		c, size := elliptic.P256(), 64
		if alg == algECDSAP384 {
			c, size = elliptic.P384(), 96
		}
		if len(k) != size {
			return nil
		}
		pk, err := ecdsa.ParseUncompressedPublicKey(c, append([]byte{4}, k...))
		if err != nil {
			return nil
		}
		return pk
	case algED25519:
		if len(k) != ed25519.PublicKeySize {
			return nil
		}
		return ed25519.PublicKey(slices.Clone(k))
	}
	return nil
}

// dsMatches reports whether the DS record data ds points to key at owner.
func dsMatches(owner string, ds []byte, k *dnskey) bool {
	if len(ds) < 5 || binary.BigEndian.Uint16(ds) != k.tag || ds[2] != k.alg {
		return false
	}
	buf := append([]byte(owner), 0)
	buf = append(buf, k.rdata...)
	var sum []byte
	switch ds[3] {
	case digestSHA1:
		h := sha1.Sum(buf)
		sum = h[:]
	case digestSHA256:
		h := sha256.Sum256(buf)
		sum = h[:]
	case digestSHA384:
		h := sha512.Sum384(buf)
		sum = h[:]
	default:
		return false
	}
	return bytes.Equal(sum, ds[4:])
}

// serialLE reports a <= b in RFC 1982 serial number arithmetic.
func serialLE(a, b uint32) bool { return a == b || int32(b-a) > 0 }

// timeCheck checks the validity period, allowing for clock skew of a tenth
// of the period (between one hour and one day), as Unbound does.
func (s *sig) timeCheck(now time.Time) error {
	t := uint32(now.Unix())
	skew := (s.exp - s.inc) / 10
	skew = min(max(skew, 3600), 86400)
	if !serialLE(s.inc-skew, t) {
		return errSigNotYet
	}
	if !serialLE(t, s.exp+skew) {
		return errSigExpired
	}
	return nil
}

// signedData builds the data an RRSIG signs over set (RFC 4034 3.1.8.1).
func signedData(set *rrset, s *sig) []byte {
	owner := []byte(set.name)
	if n := labelCount(set.name); int(s.labels) < n { // expanded from a wildcard
		owner = append([]byte{1, '*'}, ancestorAt(set.name, int(s.labels))...)
	}
	rdatas := make([][]byte, 0, len(set.data))
	for _, d := range set.data {
		rdatas = append(rdatas, canonicalRdata(set.typ, d))
	}
	slices.SortFunc(rdatas, bytes.Compare)
	rdatas = slices.CompactFunc(rdatas, bytes.Equal)
	buf := slices.Clone(s.signed)
	for _, d := range rdatas {
		buf = append(buf, owner...)
		buf = append(buf, 0)
		buf = binary.BigEndian.AppendUint16(buf, set.typ)
		buf = binary.BigEndian.AppendUint16(buf, set.class)
		buf = binary.BigEndian.AppendUint32(buf, s.origTTL)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(d)))
		buf = append(buf, d...)
	}
	return buf
}

// verified remembers signatures that were checked: the same signed data
// comes back often (every expansion of a wildcard is signed as the
// wildcard; one NSEC record proves many names; RRsets fetched again keep
// their signatures), and checking an ECDSA signature costs tens of
// microseconds. The key covers the signed data, the signature and the key.
var verified = newTTLMap[struct{}](50000)

// verify checks one signature with one key.
func verify(set *rrset, s *sig, k *dnskey) bool {
	if k.pub == nil || k.alg != s.alg {
		return false
	}
	data := signedData(set, s)
	h := sha256.New()
	h.Write(data)
	h.Write(s.data)
	h.Write(k.rdata)
	key := string(h.Sum(nil))
	if _, exp, ok := verified.get(key); ok && time.Now().Before(exp) {
		return true
	}
	if !verifyCrypto(k, s, data) {
		return false
	}
	verified.set(key, struct{}{}, time.Now().Add(time.Hour))
	return true
}

func verifyCrypto(k *dnskey, s *sig, data []byte) bool {
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		var h crypto.Hash
		switch s.alg {
		case algRSASHA1, algRSASHA1NSEC3:
			h = crypto.SHA1
		case algRSASHA256:
			h = crypto.SHA256
		case algRSASHA512:
			h = crypto.SHA512
		default:
			return false
		}
		hh := h.New()
		hh.Write(data)
		return rsa.VerifyPKCS1v15(pub, h, hh.Sum(nil), s.data) == nil
	case *ecdsa.PublicKey:
		var sum []byte
		if s.alg == algECDSAP256 {
			h := sha256.Sum256(data)
			sum = h[:]
		} else {
			h := sha512.Sum384(data)
			sum = h[:]
		}
		half := len(s.data) / 2
		if len(s.data)%2 != 0 || half != (pub.Curve.Params().BitSize+7)/8 {
			return false
		}
		r, ss := new(big.Int).SetBytes(s.data[:half]), new(big.Int).SetBytes(s.data[half:])
		return ecdsa.Verify(pub, sum, r, ss)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, data, s.data)
	}
	return false
}

// verifySet checks set against keys of zone. It returns the TTL the set may
// be kept (bounded by the signature) or an error saying why it failed.
// budget limits the number of signature checks (KeyTrap protection).
func verifySet(set *rrset, zone string, keys []*dnskey, now time.Time, budget *int) (uint32, uint8, error) {
	if len(set.sigs) == 0 {
		return 0, 0, errNoSig
	}
	var firstErr error
	for _, raw := range set.sigs {
		s, ok := parseSig(raw)
		if !ok || s.covered != set.typ || s.signer != zone || int(s.labels) > labelCount(set.name) {
			continue
		}
		if !isSub(set.name, s.signer) {
			continue
		}
		if err := s.timeCheck(now); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		tried := false
		for _, k := range keys {
			if k.tag != s.tag || k.alg != s.alg || k.flags&keyFlagZone == 0 || k.flags&keyFlagRevoke != 0 {
				continue
			}
			if *budget <= 0 {
				return 0, 0, errSigBad
			}
			*budget--
			tried = true
			if verify(set, s, k) {
				ttl := min(set.ttl, s.origTTL)
				if left := int64(s.exp) - now.Unix(); left < int64(ttl) {
					ttl = uint32(max(left, 0))
				}
				return ttl, s.labels, nil
			}
		}
		if firstErr == nil || firstErr == errNoKey {
			if tried {
				firstErr = errSigBad
			} else if firstErr == nil {
				firstErr = errNoKey
			}
		}
	}
	if firstErr == nil {
		firstErr = errNoKey
	}
	return 0, 0, firstErr
}
