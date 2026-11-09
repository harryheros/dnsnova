package recursor

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Config configures a Recursor. It can be replaced at run time.
type Config struct {
	// DNSSEC validates answers; bogus ones become SERVFAIL.
	DNSSEC bool
	// QNameMinimisation sends each server only as much of the name as it
	// needs (RFC 9156).
	QNameMinimisation bool
	// IPv6 also contacts servers over IPv6.
	IPv6 bool
	// BlockPrivate refuses to send queries to private and shared address
	// space (RFC 1918, RFC 6598, unique local IPv6). Loopback, link-local,
	// multicast and unspecified addresses are always refused.
	BlockPrivate bool
	// Allow lists networks that may be contacted even so.
	Allow []netip.Prefix
	// RootHints replace the built-in root server addresses.
	RootHints []netip.Addr
	// TrustAnchors replace the built-in root DS records ("tag alg digesttype hex").
	TrustAnchors []string
	// CacheSize is the number of RRsets kept.
	CacheSize int
}

// Stats are counters for monitoring.
type Stats struct {
	Queries       atomic.Int64 // sent to authoritative servers
	Timeouts      atomic.Int64
	TCP           atomic.Int64
	Secure        atomic.Int64 // answers to clients, by DNSSEC result
	Insecure      atomic.Int64
	Bogus         atomic.Int64
	CacheHits     atomic.Int64
	CacheMisses   atomic.Int64
	BudgetReached atomic.Int64
	Aggressive    atomic.Int64 // answered from validated NSEC records (RFC 8198)
}

// Recursor is safe for concurrent use.
type Recursor struct {
	cfg     atomic.Pointer[Config]
	anchors atomic.Pointer[rrset]
	sets    *ttlMap[*cachedSet]
	wilds   *ttlMap[*cachedSet] // validated wildcard RRsets, by wildcard name (RFC 8198)
	negs    *ttlMap[*negEntry]
	keys    *ttlMap[*keyEntry]
	delegs  *ttlMap[*delegation]
	infra   *infra
	fl      flights
	Stats   Stats
	log     *slog.Logger
	now     func() time.Time
	port    uint16 // 53; tests use another
	socks   sockPool
	nsecs   nsecIndex
	v6down  atomic.Int64
	v6ok    atomic.Int64 // unix nanos of the last answer over IPv6
	v6fails atomic.Int64 // IPv6 timeouts in a row
	// hostV6 reports whether this machine has an IPv6 address that can
	// reach the internet; checked at most once a minute (v6Checked)
	hostV6    func() bool
	v6Checked atomic.Int64
	v6Host    atomic.Bool
	lastOK    atomic.Int64 // unix nanos of the last answer from any server
	failRun   atomic.Int64 // queries without an answer since then
	// send is replaced by tests.
	send func(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error)
}

// Built-in root DS records: KSK-2017 and KSK-2024 (in use since 11 October
// 2026), as published by IANA.
var builtinAnchors = []string{
	"20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	"38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// Root server addresses (IANA root hints).
var builtinRoots = []string{
	"198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4",
	"198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33",
	"2001:503:ba3e::2:30", "2801:1b8:10::b", "2001:500:2::c", "2001:500:2d::d", "2001:500:a8::e", "2001:500:2f::f",
	"2001:500:12::d0d", "2001:500:1::53", "2001:7fe::53", "2001:503:c27::2:30", "2001:7fd::1", "2001:500:9f::42",
	"2001:dc3::35",
}

// ParseAnchor checks a trust anchor in the form used by Config.TrustAnchors.
func ParseAnchor(s string) ([]byte, error) {
	f := strings.Fields(s)
	if len(f) != 4 {
		return nil, errors.New(`want "key-tag algorithm digest-type digest"`)
	}
	tag, err1 := strconv.ParseUint(f[0], 10, 16)
	alg, err2 := strconv.ParseUint(f[1], 10, 8)
	dt, err3 := strconv.ParseUint(f[2], 10, 8)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("key tag, algorithm and digest type must be numbers")
	}
	want := map[uint64]int{digestSHA1: 20, digestSHA256: 32, digestSHA384: 48}[dt]
	if want == 0 {
		return nil, errors.New("digest type must be 1 (SHA-1), 2 (SHA-256) or 4 (SHA-384)")
	}
	dig, err := hex.DecodeString(f[3])
	if err != nil || len(dig) != want {
		return nil, fmt.Errorf("the digest must be %d hexadecimal characters for digest type %d", want*2, dt)
	}
	return append([]byte{byte(tag >> 8), byte(tag), byte(alg), byte(dt)}, dig...), nil
}

// New returns a Recursor.
func New(c Config, log *slog.Logger) *Recursor {
	r := &Recursor{
		sets:   newTTLMap[*cachedSet](0),
		wilds:  newTTLMap[*cachedSet](10000),
		negs:   newTTLMap[*negEntry](0),
		keys:   newTTLMap[*keyEntry](10000),
		delegs: newTTLMap[*delegation](0),
		infra:  newInfra(),
		log:    log,
		now:    time.Now,
		port:   53,
		hostV6: hasGlobalIPv6,
	}
	r.send = r.exchange
	r.SetConfig(c)
	return r
}

// SetConfig applies a new configuration; caches are kept, and resized.
func (r *Recursor) SetConfig(c Config) {
	if len(c.RootHints) == 0 {
		for _, s := range builtinRoots {
			c.RootHints = append(c.RootHints, netip.MustParseAddr(s))
		}
	}
	anchors := c.TrustAnchors
	if len(anchors) == 0 {
		anchors = builtinAnchors
	}
	ds := &rrset{name: "", typ: typeDS, class: m.ClassIN, ttl: 86400}
	for _, a := range anchors {
		if d, err := ParseAnchor(a); err == nil {
			ds.data = append(ds.data, d)
		}
	}
	// The resolver cannot work without remembering delegations and keys
	// (every query would start at the root), so a size of 0, which turns
	// the answer cache off, leaves this one at its default.
	size := c.CacheSize
	if size <= 0 {
		size = 100000
	}
	r.sets.setLimit(size / 2)
	r.negs.setLimit(size / 4)
	r.delegs.setLimit(size / 4)
	old := r.cfg.Swap(&c)
	r.anchors.Store(ds)
	if old != nil && (old.DNSSEC != c.DNSSEC || fmt.Sprint(old.TrustAnchors) != fmt.Sprint(c.TrustAnchors) ||
		fmt.Sprint(old.RootHints) != fmt.Sprint(c.RootHints)) {
		r.ClearCache()
	}
}

// Healthy reports whether authoritative servers have been answering:
// false after a run of queries that all went unanswered (no network).
func (r *Recursor) Healthy() bool {
	return r.failRun.Load() < 20 || r.now().UnixNano()-r.lastOK.Load() < int64(30*time.Second)
}

// ClearCache forgets everything learnt.
func (r *Recursor) ClearCache() {
	r.sets.clear()
	r.wilds.clear()
	r.negs.clear()
	r.keys.clear()
	r.delegs.clear()
	r.nsecs.mu.Lock()
	r.nsecs.zones = nil
	r.nsecs.mu.Unlock()
}

// CacheSizes reports the number of RRsets, negative answers, zones with
// known keys, delegations and servers.
func (r *Recursor) CacheSizes() (sets, negs, keys, delegs, servers int) {
	return r.sets.len(), r.negs.len(), r.keys.len(), r.delegs.len(), r.infra.size()
}

// Janitor removes long-expired entries once a minute until ctx is done.
func (r *Recursor) Janitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := r.now()
			r.sets.sweep(now, time.Minute)
			r.negs.sweep(now, time.Minute)
			r.keys.sweep(now, time.Minute)
			r.delegs.sweep(now, time.Minute)
			r.wilds.sweep(now, time.Minute)
			r.nsecs.sweep(now)
		}
	}
}

// Errors that mean "could not resolve", as opposed to a DNSSEC failure: a
// caller may then try upstreams instead.
var (
	ErrUnreachable = errors.New("no authoritative server answered")
	errBudget      = errors.New("too much work for one query")
	errLoop        = errors.New("lookup loop")
)

// task is the work done for one client query.
type task struct {
	budget    int // queries that may still be sent
	sigBudget int // signature checks that may still be made
	depth     int
	stack     map[string]bool
}

const (
	maxQueriesPerTask = 150
	maxDepth          = 8
	maxCNAMEs         = 12
	maxReferrals      = 40
)

func newTask() *task {
	return &task{budget: maxQueriesPerTask, sigBudget: maxValidations, stack: map[string]bool{}}
}

// Exchange implements resolver.Exchanger: msg is a query (RD set, CD and DO
// as the client asked) and the response is built from the recursion.
func (r *Recursor) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	q, rcode, err := m.ParseQuery(msg)
	if err != nil {
		return nil, err
	}
	cfg := r.cfg.Load()
	flags := uint16(m.FlagQR|m.FlagRA) | q.Flags&(m.FlagRD|m.FlagCD)
	if rcode != 0 || q.Class != m.ClassIN {
		if rcode == 0 {
			rcode = m.RcodeRefused
		}
		return buildMessage(q.ID, flags|uint16(rcode&0xF), q.Name, q.Type, nil, nil, nil, q.EDNS, q.DO, nil), nil
	}
	if resp := r.special(q, flags); resp != nil {
		return resp, nil
	}
	validate := cfg.DNSSEC && q.Flags&m.FlagCD == 0
	t := newTask()
	ans, err := r.resolve(ctx, t, q.Name, q.Type, cfg.DNSSEC)
	if err != nil {
		if errors.Is(err, errBudget) {
			r.Stats.BudgetReached.Add(1)
		}
		return nil, err
	}
	return r.respond(q, flags, ans, validate), nil
}

// answer is the result of a resolution.
type answer struct {
	rcode    int
	chain    []*cachedSet
	neg      *negEntry
	sec      security
	ede      uint16
	why      string
	until    []time.Time // expiry of each chain entry, for TTLs
	negUntil time.Time
}

func (r *Recursor) respond(q *m.Query, flags uint16, ans *answer, validate bool) []byte {
	now := r.now()
	switch ans.sec {
	case secSecure:
		r.Stats.Secure.Add(1)
	case secBogus:
		r.Stats.Bogus.Add(1)
	default:
		r.Stats.Insecure.Add(1)
	}
	var ede []byte
	if ans.ede != 0 || ans.sec == secBogus {
		ede = m.EDE(ans.ede, ans.why)
	}
	if ans.sec == secBogus && validate {
		return buildMessage(q.ID, flags|m.RcodeServFail, q.Name, q.Type, nil, nil, nil, true, q.DO, ede)
	}
	if ans.sec == secSecure && validate {
		flags |= m.FlagAD
	}
	ttl := func(until time.Time, cap uint32) uint32 {
		left := until.Sub(now) / time.Second
		if left < 0 {
			left = 0
		}
		return min(uint32(left), cap)
	}
	var an, ns []rr
	for i, cs := range ans.chain {
		t := ttl(ans.until[i], cs.set.ttl)
		for _, rec := range cs.set.records() {
			rec.ttl = t
			an = append(an, rec)
		}
		if q.DO && !cs.synth {
			an = append(an, cs.set.sigRecords(t)...)
			// a wildcard expansion comes with the proof that the name itself
			// does not exist, so the client can check it too (RFC 4035 3.1.3.3)
			for _, p := range cs.proof {
				for _, rec := range p.records() {
					rec.ttl = t
					ns = append(ns, rec)
				}
				ns = append(ns, p.sigRecords(t)...)
			}
		}
	}
	if n := ans.neg; n != nil && n.soa != nil {
		t := ttl(ans.negUntil, n.soa.ttl)
		for _, rec := range n.soa.records() {
			rec.ttl = t
			ns = append(ns, rec)
		}
		if q.DO {
			ns = append(ns, n.soa.sigRecords(t)...)
			for _, p := range n.proof {
				for _, rec := range p.records() {
					rec.ttl = t
					ns = append(ns, rec)
				}
				ns = append(ns, p.sigRecords(t)...)
			}
		}
	}
	return buildMessage(q.ID, flags|uint16(ans.rcode&0xF), q.Name, q.Type, an, ns, nil, true, q.DO, ede)
}

// ---- names answered without asking anyone (RFC 6761, RFC 6303, RFC 7686, RFC 8375) ----

var localZones = func() []string {
	z := []string{"localhost", "invalid", "test", "onion", "local", "home.arpa",
		"10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa", "127.in-addr.arpa", "0.in-addr.arpa",
		"255.255.255.255.in-addr.arpa", "d.f.ip6.arpa", "c.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa",
		"a.e.f.ip6.arpa", "b.e.f.ip6.arpa", strings.Repeat("0.", 31) + "1.ip6.arpa", strings.Repeat("0.", 32) + "ip6.arpa"}
	for i := 16; i < 32; i++ {
		z = append(z, fmt.Sprintf("%d.172.in-addr.arpa", i))
	}
	for i := 64; i < 128; i++ {
		z = append(z, fmt.Sprintf("%d.100.in-addr.arpa", i))
	}
	out := make([]string, len(z))
	for i, s := range z {
		out[i] = m.WireName(strings.Split(s, ".")...)
	}
	return out
}()

var localhostWire = m.WireName("localhost")

func (r *Recursor) special(q *m.Query, flags uint16) []byte {
	for _, z := range localZones {
		if !isSub(q.Name, z) {
			continue
		}
		flags |= m.FlagAA
		soa := rr{name: z, typ: m.TypeSOA, class: m.ClassIN, ttl: 10800,
			data: append(append([]byte(localhostWire), 0, 6, 'n', 'o', 'b', 'o', 'd', 'y', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0),
				0, 0, 0, 1, 0, 0, 14, 16, 0, 0, 4, 176, 0, 9, 58, 128, 0, 0, 42, 48)}
		if z == localhostWire {
			var data []byte
			switch q.Type {
			case m.TypeA:
				data = []byte{127, 0, 0, 1}
			case m.TypeAAAA:
				data = netip.IPv6Loopback().AsSlice()
			}
			if data != nil {
				return buildMessage(q.ID, flags, q.Name, q.Type,
					[]rr{{name: q.Name, typ: q.Type, class: m.ClassIN, ttl: 10800, data: data}}, nil, nil, q.EDNS, q.DO, nil)
			}
			return buildMessage(q.ID, flags, q.Name, q.Type, nil, []rr{soa}, nil, q.EDNS, q.DO, nil)
		}
		return buildMessage(q.ID, flags|m.RcodeNXDomain, q.Name, q.Type, nil, []rr{soa}, nil, q.EDNS, q.DO, nil)
	}
	return nil
}

// ---- sending queries ----

// allowed reports whether queries may be sent to a.
//
// Addresses that are never a name server (unspecified, multicast,
// broadcast, 0.0.0.0/8) are refused whatever Allow says, and so is IPv6
// when it is off. Allow opens what is refused only because it is local:
// this machine, the link, and private networks.
func (r *Recursor) allowed(cfg *Config, a netip.Addr) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	if a.Is4() && a.As4()[0] == 0 {
		return false
	}
	if a.Is6() && !cfg.IPv6 {
		return false
	}
	for _, p := range cfg.Allow {
		if p.Contains(a) {
			return true
		}
	}
	if a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	if cfg.BlockPrivate && (a.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)) {
		return false
	}
	return true
}

// buildQuery writes a query to an authoritative server.
func buildQuery(id uint16, name string, qtype uint16, edns bool) []byte {
	b := make([]byte, 0, m.HeaderLen+len(name)+5+11)
	arc := byte(0)
	if edns {
		arc = 1
	}
	b = append(b, byte(id>>8), byte(id), 0, 0, 0, 1, 0, 0, 0, 0, 0, arc)
	b = append(b, name...)
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, m.ClassIN)
	if edns {
		b = m.AppendOPT(b, m.EDNSSize, true)
	}
	return b
}

func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
