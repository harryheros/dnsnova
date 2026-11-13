package recursor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// response is an authoritative server's answer to the full question.
type response struct {
	msg  *message
	zone string // the zone of the server that answered
}

// ---- delegations ----

func (r *Recursor) storeDeleg(d *delegation, ttl uint32) {
	ttl = min(max(ttl, 5), 86400)
	r.delegs.set(d.zone, d, r.now().Add(time.Duration(ttl)*time.Second))
}

// rootDeleg returns the root servers, priming them first (RFC 8109).
func (r *Recursor) rootDeleg(ctx context.Context, t *task) *delegation {
	if d, exp, ok := r.delegs.get(""); ok && r.now().Before(exp) {
		return d
	}
	cfg := r.cfg.Load()
	hints := &delegation{zone: "", ns: []nsHost{{addrs: cfg.RootHints}}}
	v, _ := r.fl.do(ctx, "prime", func() (any, error) {
		msg, err := r.query(ctx, t, hints, "", m.TypeNS)
		if err == nil && msg.rcode == m.RcodeNoError {
			if d, ttl := delegFrom(msg.answer, msg.additional, ""); d != nil &&
				slices.ContainsFunc(d.ns, func(h nsHost) bool { return len(h.addrs) > 0 }) {
				r.storeDeleg(d, ttl)
				return d, nil
			}
		}
		r.storeDeleg(hints, 60)
		return hints, nil
	})
	if d, ok := v.(*delegation); ok {
		return d
	}
	return hints
}

// delegFrom builds a delegation for zone from NS records and glue.
func delegFrom(nsRecs, glue []rr, zone string) (*delegation, uint32) {
	d := &delegation{zone: zone}
	ttl := uint32(86400)
	for _, rec := range nsRecs {
		if rec.typ != m.TypeNS || rec.name != zone {
			continue
		}
		host := lower(nameOf(rec.data))
		if slices.ContainsFunc(d.ns, func(h nsHost) bool { return h.name == host }) || len(d.ns) >= 20 {
			continue
		}
		ttl = min(ttl, rec.ttl)
		h := nsHost{name: host}
		for _, g := range glue {
			if g.name != host || (g.typ != m.TypeA && g.typ != m.TypeAAAA) {
				continue
			}
			if a, ok := netip.AddrFromSlice(g.data); ok {
				h.addrs = append(h.addrs, a.Unmap())
			}
		}
		d.ns = append(d.ns, h)
	}
	if len(d.ns) == 0 {
		return nil, 0
	}
	return d, ttl
}

// nameOf returns the name at the start of record data (wire, no zero byte).
func nameOf(d []byte) []byte {
	for off := 0; off < len(d); {
		l := int(d[off])
		if l == 0 {
			return d[:off]
		}
		off += 1 + l
	}
	return nil
}

// closestDeleg returns the deepest known delegation for qname. DS lives in
// the parent zone, so for DS the zone of qname itself is skipped.
func (r *Recursor) closestDeleg(ctx context.Context, t *task, qname string, qtype uint16) *delegation {
	name := qname
	if qtype == typeDS && name != "" {
		name = parent(name)
	}
	if t.fresh {
		name = "" // a trace walks down from the root
	}
	now := r.now()
	for name != "" {
		if d, exp, ok := r.delegs.get(name); ok && now.Before(exp) {
			return d
		}
		name = parent(name)
	}
	return r.rootDeleg(ctx, t)
}

// ---- iteration ----

// iterate asks authoritative servers, following referrals from the closest
// known delegation, until one answers qname/qtype (or says it does not exist).
func (r *Recursor) iterate(ctx context.Context, t *task, qname string, qtype uint16) (*response, error) {
	key := "i" + tkey(qname, qtype)
	if t.stack[key] {
		return nil, errLoop
	}
	t.stack[key] = true
	defer delete(t.stack, key)
	if t.fresh || !t.shared() { // a trace, or one network's answer, joins no other lookup
		return r.iterateOnce(ctx, t, qname, qtype)
	}
	v, err := r.fl.do(ctx, key, func() (any, error) { return r.iterateOnce(ctx, t, qname, qtype) })
	if err != nil {
		return nil, err
	}
	return v.(*response), nil
}

func (r *Recursor) iterateOnce(ctx context.Context, t *task, qname string, qtype uint16) (*response, error) {
	cfg := r.cfg.Load()
	d := r.closestDeleg(ctx, t, qname, qtype)
	known := d.zone
	minimise := cfg.QNameMinimisation
	steps := 0
	for i := 0; i < maxReferrals; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sendName, sendType := qname, qtype
		if minimise && steps < 10 && labelCount(qname) > labelCount(known)+1 {
			sendName, sendType = ancestorAt(qname, labelCount(known)+1), m.TypeA
			steps++
		}
		msg, err := r.query(ctx, t, d, sendName, sendType)
		if err != nil {
			if sendName != qname && errors.Is(err, ErrUnreachable) {
				// no server gave a usable reply to the shortened name (some
				// mishandle names that only exist as part of longer ones):
				// ask for the full name instead
				minimise = false
				continue
			}
			return nil, err
		}
		if child, ttl := referral(msg, d.zone, sendName); child != nil {
			if qtype == typeDS && child.zone == qname {
				return nil, ErrUnreachable // the parent must answer DS itself
			}
			child.signed = slices.ContainsFunc(msg.authority, func(a rr) bool { return a.typ == typeDS && a.name == child.zone })
			r.storeDeleg(child, ttl)
			r.storeReferralDS(msg, child.zone, d.zone)
			d, known = child, child.zone
			continue
		}
		if sendName != qname {
			switch {
			case msg.rcode == m.RcodeNXDomain && hasDenial(msg):
				// RFC 8020: nothing exists below a name that does not
				// exist. Signed zones prove it; unsigned ones are asked
				// again with the full name, as some servers get this wrong.
				return &response{msg: msg, zone: d.zone}, nil
			case msg.rcode == m.RcodeNoError && !hasAlias(msg, sendName):
				known = sendName // no zone cut here; one label further
			default:
				minimise = false
			}
			continue
		}
		return &response{msg: msg, zone: d.zone}, nil
	}
	return nil, errBudget
}

func hasDenial(msg *message) bool {
	for _, a := range msg.authority {
		if a.typ == typeNSEC || a.typ == typeNSEC3 {
			return true
		}
	}
	return false
}

func hasAlias(msg *message, name string) bool {
	for _, a := range msg.answer {
		if (a.typ == m.TypeCNAME && a.name == name) || (a.typ == typeDNAME && isSub(name, a.name)) {
			return true
		}
	}
	return false
}

// referral returns the delegation a response refers to: NS records for a
// zone below the server's zone that contains qname, and no answer.
func referral(msg *message, zone, qname string) (*delegation, uint32) {
	if msg.rcode != m.RcodeNoError || msg.aa() {
		return nil, 0
	}
	for _, a := range msg.answer {
		if a.name == qname {
			return nil, 0
		}
	}
	for _, a := range msg.authority {
		if a.typ == m.TypeSOA {
			return nil, 0
		}
	}
	for _, a := range msg.authority {
		if a.typ == m.TypeNS && a.name != zone && isSub(a.name, zone) && isSub(qname, a.name) {
			return delegFrom(msg.authority, msg.additional, a.name)
		}
	}
	return nil, 0
}

// storeReferralDS keeps the DS records (or the proof there are none) that
// came with a referral, saving a query when the child is validated.
func (r *Recursor) storeReferralDS(msg *message, child, zone string) {
	if !r.cfg.Load().DNSSEC {
		return
	}
	sets := groupRRsets(msg.authority)
	now := r.now()
	for _, s := range sets {
		if s.name == child && s.typ == typeDS && len(s.sigs) > 0 {
			cs := &cachedSet{set: s, zone: zone, orig: s.ttl}
			r.sets.set(tkey(child, typeDS), cs, now.Add(time.Duration(min(s.ttl, 86400))*time.Second))
			return
		}
	}
	var proof []*rrset
	ttl := uint32(3600)
	for _, s := range sets {
		if (s.typ == typeNSEC || s.typ == typeNSEC3) && len(s.sigs) > 0 {
			proof = append(proof, s)
			ttl = min(ttl, s.ttl)
		}
	}
	if len(proof) > 0 {
		ne := &negEntry{rcode: m.RcodeNoError, proof: proof, zone: zone, orig: ttl}
		r.negs.set(tkey(child, typeDS), ne, now.Add(time.Duration(ttl)*time.Second))
	}
}

// scrub drops records outside the zone of the server that sent them (they
// could be used to poison the cache) and everything in the additional
// section but addresses.
func scrub(msg *message, zone string) {
	keep := func(rrs []rr, addrOnly bool) []rr {
		out := rrs[:0]
		for _, x := range rrs {
			if !isSub(x.name, zone) {
				continue
			}
			if addrOnly && x.typ != m.TypeA && x.typ != m.TypeAAAA {
				continue
			}
			out = append(out, x)
		}
		return out
	}
	msg.answer = keep(msg.answer, false)
	msg.authority = keep(msg.authority, false)
	msg.additional = keep(msg.additional, true)
}

// usable reports whether a response from a server for zone is an answer,
// a negative answer or a referral, rather than a lame reply.
func usable(msg *message, zone, qname string) bool {
	if msg.aa() {
		return true
	}
	if child, _ := referral(msg, zone, qname); child != nil {
		return true
	}
	// some servers leave AA off answers (load balancers answering for a
	// zone delegated to them): an answer for the very name asked, from a
	// server of the zone it was delegated to (scrub has dropped anything
	// outside the zone), is as good as one with AA
	for _, a := range msg.answer {
		if a.name == qname {
			return true
		}
	}
	// and off negative answers; accept them with an SOA
	for _, a := range msg.authority {
		if a.typ == m.TypeSOA && isSub(qname, a.name) && len(msg.answer) == 0 {
			return true
		}
	}
	return false
}

// query asks the servers of d, best first, until one gives a usable reply.
func (r *Recursor) query(ctx context.Context, t *task, d *delegation, name string, qtype uint16) (*message, error) {
	cfg := r.cfg.Load()
	addrs := r.serverAddrs(ctx, t, d, cfg, false)
	now := r.now()
	tried := 0
	var asked []netip.Addr
	more := false
	var why []string // what each server did, for the error when none answers
	note := func(a netip.Addr, s string) {
		if len(why) < 8 {
			why = append(why, a.String()+" "+s)
		}
	}
	for tried < 8 {
		if len(addrs) == 0 {
			// every address known failed: look up the zone's other name
			// servers (glueless ones are only partly looked up at first)
			if more {
				break
			}
			more = true
			for _, a := range r.serverAddrs(ctx, t, d, cfg, true) {
				if !slices.Contains(asked, a) {
					addrs = append(addrs, a)
				}
			}
			if len(addrs) == 0 {
				break
			}
		}
		scores := make(map[netip.Addr]time.Duration, len(addrs))
		v6proven := r.v6Proven()
		for _, a := range addrs {
			scores[a] = r.infra.score(a, d.zone, now)
			if a.Is6() && !v6proven {
				// IPv6 that may be silently broken: IPv4 first
				scores[a] += v6Penalty
			}
		}
		slices.SortStableFunc(addrs, func(a, b netip.Addr) int { return int(scores[a] - scores[b]) })
		a := addrs[0]
		addrs = addrs[1:]
		if t.budget <= 0 {
			return nil, errBudget
		}
		t.budget--
		tried++
		asked = append(asked, a)
		start := time.Now()
		msg, err := r.ask(ctx, a, d, name, qtype)
		rtt := time.Since(start)
		if err != nil {
			if t.trace != nil {
				r.traceQuery(t, d.zone, a, name, qtype, rtt, nil, err, false)
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var rw *rewritten
			switch {
			case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
				note(a, "timed out")
			case errors.As(err, &rw):
				note(a, "answer rewritten on the way: "+rw.why)
				if r.Intercepted() {
					// the other servers' answers go the same way
					return nil, &unreachable{zone: d.zone, name: name, qtype: qtype, servers: len(d.ns), why: why}
				}
			default:
				note(a, err.Error())
			}
			continue
		}
		if msg.rcode != m.RcodeNoError && msg.rcode != m.RcodeNXDomain {
			if t.trace != nil {
				r.traceQuery(t, d.zone, a, name, qtype, rtt, msg, nil, false)
			}
			r.infra.setLame(a, d.zone, now)
			note(a, m.RcodeString(msg.rcode))
			continue
		}
		scrub(msg, d.zone)
		if !usable(msg, d.zone, name) {
			if t.trace != nil {
				r.traceQuery(t, d.zone, a, name, qtype, rtt, msg, nil, true)
			}
			r.infra.setLame(a, d.zone, now)
			note(a, "not authoritative (lame)")
			continue
		}
		if qtype == typeDS {
			if child, _ := referral(msg, d.zone, name); child != nil && child.zone == name {
				// a DS question sent down to the child, which some servers do
				// wrongly (the parent holds DS): ask another of the parent's
				// servers. Not lame: it answers everything else.
				if t.trace != nil {
					r.traceQuery(t, d.zone, a, name, qtype, rtt, msg, nil, false)
				}
				note(a, "sent the DS question down")
				continue
			}
		}
		if t.trace != nil {
			r.traceQuery(t, d.zone, a, name, qtype, rtt, msg, nil, false)
		}
		return msg, nil
	}
	return nil, &unreachable{zone: d.zone, name: name, qtype: qtype, servers: len(d.ns), why: why}
}

// unreachable is ErrUnreachable with what happened: which zone's servers
// were asked, for what, and what each did. It is only made when a lookup
// fails, for the log and the trace.
type unreachable struct {
	zone, name string
	qtype      uint16
	servers    int // name servers of the zone
	why        []string
}

func (e *unreachable) Error() string {
	q := m.NameString(e.name) + " " + m.TypeString(e.qtype)
	if len(e.why) == 0 {
		return fmt.Sprintf("%s: no address to ask for any of the %d name servers of %s", q, e.servers, zoneName(e.zone))
	}
	return fmt.Sprintf("%s: no server of %s answered (%s)", q, zoneName(e.zone), strings.Join(e.why, "; "))
}

func (e *unreachable) Is(target error) bool { return target == ErrUnreachable }

// serverAddrs returns the addresses that may be asked for d, looking up
// the addresses of name servers that came without glue.
func (r *Recursor) serverAddrs(ctx context.Context, t *task, d *delegation, cfg *Config, more bool) []netip.Addr {
	var out []netip.Addr
	add := func(a netip.Addr) {
		if r.allowed(cfg, a) && !(a.Is6() && r.v6Down()) && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	var missing []string
	for _, h := range d.ns {
		for _, a := range h.addrs {
			add(a)
		}
		if len(h.addrs) == 0 && h.name != "" {
			addrs := r.cachedAddrs(h.name, cfg)
			for _, a := range addrs {
				add(a)
			}
			switch {
			case isSub(h.name, d.zone): // in-zone names without glue cannot be found
			case len(addrs) == 0:
				missing = append(missing, h.name)
			case more && !slices.ContainsFunc(addrs, netip.Addr.Is4):
				// only IPv6 known, and it failed: its IPv4 addresses too
				missing = append(missing, h.name)
			}
		}
	}
	if (len(out) >= 2 && !more) || len(missing) == 0 || t.depth >= maxDepth-2 {
		return out
	}
	// glueless: look up a few name servers (NXNSAttack: not all of them).
	// With more (the addresses known so far all failed), up to six.
	rand.Shuffle(len(missing), func(i, j int) { missing[i], missing[j] = missing[j], missing[i] })
	found, limit := false, 3
	if more {
		limit = 6
	}
	for i, host := range missing {
		if i >= limit || (found && len(out) >= 2 && !more) {
			break
		}
		types := []uint16{m.TypeA}
		if cfg.IPv6 && !r.v6Down() {
			types = append(types, m.TypeAAAA)
		}
		for _, qt := range types {
			ans, err := r.resolve(ctx, t, host, qt, false)
			if err != nil || ans.rcode != m.RcodeNoError {
				continue
			}
			for _, cs := range ans.chain {
				if cs.set.typ != qt {
					continue
				}
				for _, data := range cs.set.data {
					if a, ok := netip.AddrFromSlice(data); ok {
						add(a.Unmap())
						found = true
					}
				}
			}
		}
	}
	return out
}

func (r *Recursor) cachedAddrs(host string, cfg *Config) []netip.Addr {
	var out []netip.Addr
	types := []uint16{m.TypeA}
	if cfg.IPv6 {
		types = append(types, m.TypeAAAA)
	}
	now := r.now()
	for _, qt := range types {
		if cs, exp, ok := r.sets.get(tkey(host, qt)); ok && now.Before(exp) {
			for _, data := range cs.set.data {
				if a, ok := netip.AddrFromSlice(data); ok {
					out = append(out, a.Unmap())
				}
			}
		}
	}
	return out
}

// v6Down reports whether IPv6 is not to be used now: this machine has no
// IPv6 address that reaches the internet, or IPv6 failed recently.
func (r *Recursor) v6Down() bool {
	now := r.now()
	if !r.hasV6(now) {
		return true
	}
	return now.UnixNano() < r.v6down.Load()
}

// hasV6 checks the machine's addresses, at most once a minute: on a network
// without IPv6 (or with it turned off) no IPv6 server is ever tried.
func (r *Recursor) hasV6(now time.Time) bool {
	if last := r.v6Checked.Load(); last == 0 || now.Sub(time.Unix(0, last)) > time.Minute {
		r.v6Host.Store(r.hostV6())
		r.v6Checked.Store(now.UnixNano())
	}
	return r.v6Host.Load()
}

// hasGlobalIPv6 reports whether this machine can reach the internet over
// IPv6. Connecting a UDP socket sends nothing: the kernel only looks up the
// route, so this answers at once. No route (ENETUNREACH), IPv6 turned off
// (EAFNOSUPPORT) or a source address that is only link-local or a private
// ULA all mean no. The address is a root server's, which recursion asks
// anyway.
func hasGlobalIPv6() bool {
	c, err := net.Dial("udp6", "[2001:500:2::c]:53") // c.root-servers.net
	if err != nil {
		return false
	}
	defer c.Close()
	ap, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return false
	}
	ip := ap.Addr()
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// IPv6 can be configured yet broken: packets vanish instead of failing at
// once (a router announcing a route it does not carry). Every server asked
// over it would then cost a timeout, several per name. So IPv6 is preferred
// only after it has answered, and three timeouts in a row without any
// answer turn it off for v6Pause.
const (
	v6Penalty = 300 * time.Millisecond
	v6Pause   = 10 * time.Minute
)

func (r *Recursor) v6Proven() bool {
	ok := r.v6ok.Load()
	return ok != 0 && r.now().Sub(time.Unix(0, ok)) < v6Pause
}

// localV6Error reports errors that mean IPv6 cannot be used from here at
// all, rather than that one server failed: no route, a firewall rule,
// IPv6 turned off in the system, no address to send from.
func localV6Error(err error) bool {
	for _, e := range []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EPERM, syscall.EACCES,
		syscall.EAFNOSUPPORT, syscall.EADDRNOTAVAIL, syscall.EPROTONOSUPPORT} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func (r *Recursor) v6Result(a netip.Addr, err error, now time.Time) {
	if !a.Is6() {
		return
	}
	switch {
	case err == nil:
		r.v6ok.Store(now.UnixNano())
		r.v6fails.Store(0)
	case localV6Error(err):
		r.v6down.Store(now.Add(v6Pause).UnixNano())
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		if r.v6fails.Add(1) >= 3 && !r.v6Proven() {
			r.v6down.Store(now.Add(v6Pause).UnixNano())
			r.v6fails.Store(0)
		}
	}
}

// ask sends one question to one server of d: over UDP, then TCP if the
// answer was truncated or looks forged; without EDNS for servers that do
// not support it.
//
// With DNS Cookies (RFC 7873) each question carries a client cookie made
// for this server, and the server cookie it gave last time. A UDP answer
// with another client cookie cannot be the server's: it is forged. A
// server that has always sent cookies but answers over UDP without one is
// doubted too; if its genuine TCP answer has no cookie either (anycast
// instances that differ), cookies are not insisted on for that server for
// an hour.
//
// Each UDP answer is judged as it arrives (see pick): forged ones are
// dropped while the genuine one, which a censor on the path cannot stop,
// is waited for. Only when none comes is the question asked over TCP.
func (r *Recursor) ask(ctx context.Context, a netip.Addr, d *delegation, name string, qtype uint16) (*message, error) {
	now := r.now()
	cfg := r.cfg.Load()
	edns := r.infra.useEDNS(a, now)
	ap := netip.AddrPortFrom(a, r.port)
	// The client subnet goes with questions for a name's records, not
	// with those that only find the way there (NS, DS, DNSKEY, SOA).
	var ecs []byte
	if edns && qtype != m.TypeNS && qtype != typeDS && qtype != typeDNSKEY && qtype != m.TypeSOA {
		ecs = cfg.ECS
		if v, ok := ctx.Value(subnetKey{}).([]byte); ok { // ExchangeSubnet
			ecs = v
		}
	}
	plain := r.infra.plain(a, now)
	// on a network that answers in the servers' place, nothing better
	// than an impossible answer is coming
	intercepted := r.Intercepted()
	cookies, badRetried := cfg.Cookies, false
	for attempt := 0; attempt < 5; attempt++ {
		opts, cc := ecs, []byte(nil)
		if cookies && edns {
			if c, sc, ok := r.infra.cookieFor(a, now, r.clientCookie); ok {
				cc = c
				opts = append(append(make([]byte, 0, len(ecs)+4+8+len(sc)), ecs...), cookieOption(cc, sc)...)
			}
		}
		q := buildQuery(uint16(rand.Uint32()), name, qtype, edns, opts)
		sentEDNS, sentCookie := edns, cc
		var sawImpossible atomic.Value // why the last UDP answer could not be the server's
		judge := func(resp []byte) verdict {
			msg, err := parseMessage(resp)
			if err != nil || msg.tc() {
				return vAccept // broken answers are dealt with below; truncated ones go to TCP anyway
			}
			v := vAccept
			if why := impossible(msg, d.zone, name, qtype); why != "" {
				sawImpossible.Store(why)
				v = vForged
				if intercepted {
					v = vGiveUp
				}
			} else if !plain {
				v, _ = r.doubt(msg, a, d, name, qtype, sentEDNS, sentCookie, now)
			}
			if v != vAccept {
				r.Stats.Forged.Add(1)
			}
			return v
		}
		overTCP := func() (*message, error) {
			c, cancel := context.WithTimeout(ctx, 2*r.infra.timeout(a)+time.Second)
			resp, err := r.send(c, ap, q, true)
			cancel()
			r.Stats.TCP.Add(1)
			if err != nil {
				r.infra.fail(a, now)
				return nil, err
			}
			return parseMessage(resp)
		}
		start := time.Now()
		c, cancel := context.WithTimeout(withJudge(ctx, judge), r.infra.timeout(a))
		resp, err := r.send(c, ap, q, false)
		cancel()
		r.Stats.Queries.Add(1)
		tcp, doubted := false, false
		switch {
		case errors.Is(err, ErrSpoofed):
			// Someone is guessing answers to this query: ask over TCP.
			r.Stats.Spoofed.Add(1)
			fallthrough
		case errors.Is(err, ErrForged):
			// Only forged or doubtful answers came: ask over TCP, where
			// nothing can be forged from the path (a censor resets, at most).
			doubted = errors.Is(err, ErrForged)
			c, cancel := context.WithTimeout(ctx, 2*r.infra.timeout(a)+time.Second)
			resp, err = r.send(c, ap, q, true)
			cancel()
			r.Stats.TCP.Add(1)
			tcp = true
		}
		if err != nil {
			if why, ok := sawImpossible.Load().(string); ok && tcp && ctx.Err() == nil {
				// UDP answered by someone else, and TCP blocked: the network
				// has taken over port 53 just the same
				r.noteRewritten(a, why, now)
				r.failRun.Add(1)
				return nil, &rewritten{why: why}
			}
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				r.Stats.Timeouts.Add(1)
			}
			r.v6Result(a, err, now)
			r.infra.fail(a, now)
			r.failRun.Add(1)
			return nil, err
		}
		msg, perr := parseMessage(resp)
		if perr == nil {
			if why := impossible(msg, d.zone, name, qtype); why != "" {
				// not from the server at all: someone in between answers
				// for it, over TCP too (or the answer would have been
				// dropped above)
				r.noteRewritten(a, why, now)
				r.failRun.Add(1)
				return nil, &rewritten{why: why}
			}
		}
		r.infra.ok(a, time.Since(start), now)
		r.v6Result(a, nil, now)
		r.lastOK.Store(now.UnixNano())
		r.failRun.Store(0)
		if perr != nil {
			r.infra.setLame(a, "", now)
			return nil, perr
		}
		if msg.tc() && !tcp {
			if msg, err = overTCP(); err != nil {
				return nil, err
			}
			tcp = true
		}
		if doubted && !plain {
			// The genuine answer, over TCP, looks just like the doubted ones
			// did: that is how this server answers. Stop doubting it.
			if v, _ := r.doubt(msg, a, d, name, qtype, sentEDNS, nil, now); v != vAccept {
				r.infra.setPlain(a, now)
				plain = true
			}
		}
		if cc != nil {
			switch r.checkCookie(a, cc, msg, tcp, badRetried, now) {
			case cookieAgain: // BADCOOKIE: now with the server cookie it just gave
				badRetried = true
				continue
			case cookieTCP:
				if msg, err = overTCP(); err != nil {
					return nil, err
				}
				r.checkCookie(a, cc, msg, true, true, now) // learns from the genuine answer
			}
		}
		if msg.rcode == m.RcodeFormErr || msg.rcode == m.RcodeNotImp {
			switch {
			case ecs != nil: // a server that trips over the client subnet: ask without it
				ecs = nil
				continue
			case cc != nil: // or over the cookie
				r.infra.setNoCookie(a, now)
				continue
			case edns && !msg.edns:
				r.infra.setNoEDNS(a, now)
				edns = false
				continue
			}
		}
		return msg, nil
	}
	return nil, ErrUnreachable
}

// rewritten is an answer that cannot have come from the server asked: the
// network answers in its place.
type rewritten struct{ why string }

func (e *rewritten) Error() string { return "answer rewritten on the way: " + e.why }

// rootServed are the zones that the root servers serve besides the root.
var rootServed = []string{m.WireName("arpa"), m.WireName("root-servers", "net")}

// impossible says why msg, an answer from a server of zone to name/qtype,
// cannot be that server's over any transport, or "" when it can be. Only
// what no genuine server sends counts here: these are what networks that
// take over port 53 give themselves away by.
func impossible(msg *message, zone, name string, qtype uint16) string {
	if msg.rcode != m.RcodeNoError && msg.rcode != m.RcodeNXDomain {
		return ""
	}
	if qtype != typeANY {
		for _, a := range msg.answer {
			if a.name == name && a.typ != qtype && a.typ != m.TypeCNAME && a.typ != typeDNAME && a.typ != typeRRSIG {
				return fmt.Sprintf("a %s record in answer to a question for %s", m.TypeString(a.typ), m.TypeString(qtype))
			}
		}
	}
	if zone != "" || slices.ContainsFunc(rootServed, func(z string) bool { return isSub(name, z) }) {
		return ""
	}
	// The root servers are authoritative for the root and refer every other
	// name to its top-level domain (RIPE Labs, "Detecting DNS root
	// manipulation", 2022).
	for _, a := range msg.answer {
		if a.name != "" && (a.typ == m.TypeA || a.typ == m.TypeAAAA || a.typ == m.TypeCNAME) {
			return "a root server answered " + m.NameString(a.name) + " with an address"
		}
	}
	if !msg.aa() {
		if child, _ := referral(msg, zone, name); child == nil {
			return "a root server answered " + m.NameString(name) + " without authority"
		}
	}
	return ""
}

// doubt judges a UDP answer by what a censor's forged answers look like
// and genuine ones from this server do not: vForged when it cannot be the
// server's, vSuspect when it is merely unlike it. The reason is for the
// trace. The same checks on a genuine (TCP) answer show whether the server
// simply answers that way (infra.setPlain).
func (r *Recursor) doubt(msg *message, a netip.Addr, d *delegation, name string, qtype uint16, edns bool, cc []byte, now time.Time) (verdict, string) {
	if msg.rcode != m.RcodeNoError && msg.rcode != m.RcodeNXDomain {
		return vAccept, ""
	}
	if cc != nil {
		switch valid := len(msg.cookie) >= 8 && bytes.Equal(msg.cookie[:8], cc); {
		case msg.cookie != nil && !valid:
			return vForged, "another client's cookie"
		case msg.cookie == nil && r.infra.cookieExpected(a, now):
			return vForged, "no cookie from a server that always sends one"
		}
	}
	if qtype == m.TypeAAAA {
		for _, x := range msg.answer {
			if x.name == name && x.typ == m.TypeAAAA && len(x.data) == 16 && x.data[0] == 0x20 && x.data[1] == 0x01 && x.data[2] == 0 && x.data[3] == 0 {
				return vForged, "an address in 2001::/32 (Teredo), which censors answer with"
			}
		}
	}
	answers := len(msg.answer) > 0
	unsigned := !slices.ContainsFunc(msg.answer, func(x rr) bool { return x.typ == typeRRSIG })
	isReferral := false
	if child, _ := referral(msg, d.zone, name); child != nil {
		isReferral = true
	}
	switch {
	case !isReferral && !msg.aa() && labelCount(d.zone) <= 1:
		// top-level domains (and the root) always answer with authority
		return vForged, "an answer without authority from a server of a top-level domain"
	case answers && unsigned && d.signed && edns && name != d.zone:
		// a signed zone signs its answers; a censor cannot
		return vForged, "an unsigned answer from a signed zone"
	case edns && !msg.edns:
		return vSuspect, "no EDNS in the answer"
	case answers && !msg.aa():
		return vSuspect, "an answer without authority"
	}
	return vAccept, ""
}

// noteRewritten counts an answer rewritten on the way, and says once in a
// while what it means.
func (r *Recursor) noteRewritten(a netip.Addr, why string, now time.Time) {
	r.Stats.Rewritten.Add(1)
	r.rewrittenAt.Store(now.UnixNano())
	if last := r.rewriteWarned.Load(); last != 0 && now.Sub(time.Unix(0, last)) < 10*time.Minute {
		return
	}
	r.rewriteWarned.Store(now.UnixNano())
	r.log.Warn("recursion: port 53 is intercepted by the network, so names cannot be resolved privately here; "+
		"use your own DNSNova elsewhere as an encrypted upstream (docs/restricted-networks.md)", "server", a.String(), "seen", why)
}

// Intercepted reports whether answers from name servers have been
// rewritten on the way lately: the network takes over port 53.
func (r *Recursor) Intercepted() bool {
	at := r.rewrittenAt.Load()
	return at != 0 && r.now().Sub(time.Unix(0, at)) < 5*time.Minute && at >= r.lastOK.Load()
}

// What to do after looking at an answer's cookie.
const (
	cookieOK    = iota
	cookieAgain // BADCOOKIE: ask again (once) with the new server cookie
	cookieTCP   // looks forged: ask over TCP
)

func (r *Recursor) checkCookie(a netip.Addr, cc []byte, msg *message, tcp, retried bool, now time.Time) int {
	valid := len(msg.cookie) >= 8 && bytes.Equal(msg.cookie[:8], cc)
	switch {
	case msg.cookie != nil && !valid:
		if tcp {
			return cookieOK // a genuine answer with a broken cookie: nothing to learn
		}
		r.Stats.CookieMismatch.Add(1)
		return cookieTCP
	case valid:
		r.infra.cookieGood(a, msg.cookie[8:])
		if msg.rcode == m.RcodeBadCookie && !retried {
			return cookieAgain
		}
		if msg.rcode == m.RcodeBadCookie && !tcp {
			return cookieTCP
		}
		return cookieOK
	case r.infra.cookieExpected(a, now):
		if tcp {
			r.infra.cookieLoose(a, now) // genuinely without one: not every instance does cookies
			return cookieOK
		}
		r.Stats.CookieMissing.Add(1)
		return cookieTCP
	}
	return cookieOK
}

// clientCookie is this resolver's client cookie for server a: from a
// secret made at start, different for every server, so that servers
// cannot link the questions they receive from it to each other's.
func (r *Recursor) clientCookie(a netip.Addr) []byte {
	mac := hmac.New(sha256.New, r.cookieKey[:])
	b := a.As16()
	mac.Write(b[:])
	return mac.Sum(nil)[:8]
}

func cookieOption(cc, sc []byte) []byte {
	o := binary.BigEndian.AppendUint16(nil, m.OptCookie)
	o = binary.BigEndian.AppendUint16(o, uint16(len(cc)+len(sc)))
	return append(append(o, cc...), sc...)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

var udpBufs = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

// exchange sends q to addr and waits for the matching answer: over UDP
// from the socket pool, over TCP on a new connection.
func (r *Recursor) exchange(ctx context.Context, addr netip.AddrPort, q []byte, tcp bool) ([]byte, error) {
	if !tcp {
		return r.socks.exchangeUDP(ctx, addr, q)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	if _, err := conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(conn, lb[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if !m.MatchResponse(q, resp) {
		return nil, errFormat
	}
	return resp, nil
}
