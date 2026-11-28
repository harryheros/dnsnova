package recursor

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/locality"
)

// ---- private locality ----
//
// Some name servers answer by where the question comes from (see package
// locality). Besides the server itself, questions can leave from exits:
// hosts reached through tunnels, which only pass them on. Each exit is a
// view; the server is view 0.
//
// Which zones answer by where they are asked from is learned: now and then
// a question just answered from here is asked again through an exit, and a
// zone whose addresses share no /24 (/48) with the server's three times in
// a row is marked. Below a marked zone, answers are kept for every view:
// when a client's lookup reaches such a zone, the rest of its chain is
// resolved for every view at once, whoever asked (fork), and each client
// gets its own view's answer. Root, top-level domains, DS and DNSKEY are
// always asked from here: they do not depend on where they are asked from,
// and the chain of trust never passes through an exit.
//
// Every view of a fork expires at the same time (the earliest of them),
// so a fork happens because any client needed the name, never because a
// client of one view did: what is sent shows nothing about who asked.

// LocalityConfig configures private locality.
type LocalityConfig struct {
	Exits []locality.Exit
	// ExitTimeout: how long a client waits for its exit's answer before
	// it gets the server's own.
	ExitTimeout time.Duration
	// FanoutQPS bounds the forks per second (a flood of random names under
	// a marked zone); over it, names are asked from the server alone.
	FanoutQPS int
	// Relearn: how long a zone found not to vary stays so before it is
	// checked again.
	Relearn time.Duration
}

const (
	zoneDiffer   = 3                // differing answers in a row that mark a zone
	zoneAgree    = 3                // agreeing ones that clear it
	maxZones     = 20000            // zones followed
	probeEvery   = 20 * time.Second // per zone
	probeRate    = 20               // probes per second, at most
	forkDeadline = 6 * time.Second  // a fork's lookups give up after this
	exitFails    = 8                // timeouts in a row that take an exit out
	// or fork lookups in a row failing through it while the server's succeed
	exitFailedLookups = 3
	exitPause         = 30 * time.Second // first time out; doubles up to exitPauseMax
	exitPauseMax      = 10 * time.Minute
)

// exitPath is one exit: its sockets, what is known about name servers seen
// through it, and its health.
type exitPath struct {
	view  int
	name  string
	ex    locality.Exit
	socks *sockPool
	infra *infra
	// health: timeouts in a row, unused until (unix nanos), times taken
	// out in a row (for the pause), last answer (unix nanos), smoothed
	// round trip (ns)
	fails         atomic.Int32
	failedLookups atomic.Int32
	down          atomic.Int64
	downs         atomic.Int32
	lastOK        atomic.Int64
	rtt           atomic.Int64
	// counters
	queries   atomic.Int64
	timeouts  atomic.Int64
	fallbacks atomic.Int64 // clients given the server's answer because this exit's was late or failed
}

func (e *exitPath) local(a netip.Addr) (netip.Addr, bool) { return e.ex.LocalFor(a) }

// usable reports whether the exit is in use (not taken out after timeouts).
func (e *exitPath) usable(now time.Time) bool { return now.UnixNano() >= e.down.Load() }

func (e *exitPath) result(r *Recursor, err error, rtt time.Duration, now time.Time) {
	e.queries.Add(1)
	if err == nil {
		e.fails.Store(0)
		e.downs.Store(0)
		e.lastOK.Store(now.UnixNano())
		if old := e.rtt.Load(); old == 0 {
			e.rtt.Store(int64(rtt))
		} else {
			e.rtt.Store(old + (int64(rtt)-old)/8)
		}
		return
	}
	if !errors.Is(err, context.DeadlineExceeded) && !isTimeout(err) {
		return
	}
	e.timeouts.Add(1)
	if e.fails.Add(1) >= exitFails {
		e.takeOut(r, now)
	}
}

// lookup notes how a fork's lookup through the exit went, when the
// server's own succeeded: lookups that fail through the exit alone take it
// out too (its servers may no longer be asked at all, after their
// timeouts, so no more timeouts come).
func (e *exitPath) lookup(r *Recursor, ok bool, now time.Time) {
	if ok {
		e.failedLookups.Store(0)
		return
	}
	if e.failedLookups.Add(1) >= exitFailedLookups {
		e.takeOut(r, now)
	}
}

// takeOut stops using the exit for a while: its clients get the server's
// own answers, and forks leave it out.
func (e *exitPath) takeOut(r *Recursor, now time.Time) {
	e.fails.Store(0)
	e.failedLookups.Store(0)
	pause := exitPause << min(e.downs.Add(1)-1, 5)
	pause = min(pause, exitPauseMax)
	e.down.Store(now.Add(pause).UnixNano())
	r.log.Warn("locality: an exit stopped answering; its clients get the server's own answers for now",
		"exit", e.name, "for", pause.String())
}

// locState is private locality while it is on.
type locState struct {
	exits   []*exitPath // view i is exits[i-1]
	timeout atomic.Int64
	relearn atomic.Int64
	fanout  bucket
	probes  bucket
	zones   zoneTable

	mu   sync.Mutex
	runs map[string]*forkRun
	rr   atomic.Uint32 // the next exit to probe through

	Forks, ForksLimited, Probes atomic.Int64
}

func (lc *locState) exit(view int) *exitPath {
	if view <= 0 || view > len(lc.exits) {
		return nil
	}
	return lc.exits[view-1]
}

func (lc *locState) close() {
	for _, e := range lc.exits {
		e.socks.closeAll()
	}
}

func sameExits(a, b []locality.Exit) bool {
	return slices.EqualFunc(a, b, func(x, y locality.Exit) bool {
		return x.Name == y.Name && slices.Equal(x.Local, y.Local)
	})
}

// setLocality applies the locality settings: new exits start afresh (their
// answers and delegations are forgotten); the zones learned are kept.
func (r *Recursor) setLocality(c *LocalityConfig) {
	old := r.loc.Load()
	if c == nil || len(c.Exits) == 0 {
		if old != nil {
			r.loc.Store(nil)
			old.close()
			r.lsets.clear()
			r.vdelegs.clear()
		}
		return
	}
	lc := old
	if old == nil || !sameExits(exitConfigs(old), c.Exits) {
		lc = &locState{runs: map[string]*forkRun{}}
		for i, x := range c.Exits {
			p := &sockPool{exit: true}
			for _, a := range x.Local {
				if a.Is4() {
					p.local[0] = a
				} else {
					p.local[1] = a
				}
			}
			lc.exits = append(lc.exits, &exitPath{view: i + 1, name: x.Name, ex: x, socks: p, infra: newInfra()})
		}
		if old != nil {
			lc.zones.take(&old.zones)
		}
	}
	lc.timeout.Store(int64(max(c.ExitTimeout, 50*time.Millisecond)))
	lc.relearn.Store(int64(max(c.Relearn, time.Hour)))
	lc.fanout.setRate(max(c.FanoutQPS, 1))
	lc.probes.setRate(probeRate)
	if lc != old {
		r.loc.Store(lc)
		if old != nil {
			old.close()
		}
		r.lsets.clear()
		r.vdelegs.clear()
	}
}

func exitConfigs(lc *locState) []locality.Exit {
	out := make([]locality.Exit, len(lc.exits))
	for i, e := range lc.exits {
		out[i] = e.ex
	}
	return out
}

// ---- which path a question takes ----

type exitKey struct{}

func withExit(ctx context.Context, e *exitPath) context.Context {
	return context.WithValue(ctx, exitKey{}, e)
}

// exitOf returns the exit a question is sent through, or nil (from here).
func exitOf(ctx context.Context) *exitPath {
	e, _ := ctx.Value(exitKey{}).(*exitPath)
	return e
}

// pathFor returns the exit a question to zone's servers goes through, or
// nil when it is asked from here.
func (r *Recursor) pathFor(t *task, zone string, qtype uint16) *exitPath {
	if t.view <= 0 {
		return nil
	}
	lc := r.loc.Load()
	if lc == nil || qtype == typeDS || qtype == typeDNSKEY {
		return nil
	}
	switch {
	case t.pinned:
		if labelCount(zone) <= 1 || t.depth > 1 {
			// root and top-level domains answer the same everywhere; name
			// server addresses, DS and keys are looked up from here
			return nil
		}
		return lc.exit(t.view)
	case lc.zones.marked(zone):
		return lc.exit(t.view)
	}
	return nil
}

// storeView is the view whose delegations a lookup keeps apart, or -1 for
// the shared ones: those learned through an exit, or below a zone whose
// answers vary, are kept apart.
func (r *Recursor) storeView(t *task, zone string) int {
	lc := r.loc.Load()
	if lc == nil {
		return -1
	}
	if t.pinned && labelCount(zone) > 1 && t.depth == 1 {
		return t.view
	}
	if lc.zones.marked(zone) {
		return max(t.view, 0)
	}
	return -1
}

// keepShared reports whether what a server of zone said may go into the
// shared cache: not when its answers depend on where it is asked from.
func (r *Recursor) keepShared(zone string) bool {
	lc := r.loc.Load()
	return lc == nil || !lc.zones.marked(zone)
}

func vkey(zone string, view int) string { return zone + string([]byte{0xff, byte(view)}) }

// forkable reports whether a lookup may be resolved for every view: a
// client's own chain (not what is looked up on the way, not a measurement).
func (r *Recursor) forkable(t *task) bool {
	return t.view < 0 && !t.pinned && !t.private && t.depth == 1 && r.loc.Load() != nil
}

// ---- the zones whose answers vary ----

type zoneTable struct {
	mu      sync.RWMutex
	m       map[string]*zoneState
	nmarked atomic.Int32 // zones marked: none, no lookups
}

type zoneState struct {
	varies bool
	run    int       // >0: differed this many times in a row; <0: agreed
	until  time.Time // decided until then (zero: undecided)
	last   time.Time // last probe
}

// take keeps what another table learned.
func (z *zoneTable) take(o *zoneTable) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	z.mu.Lock()
	defer z.mu.Unlock()
	z.m = map[string]*zoneState{}
	n := int32(0)
	for k, v := range o.m {
		c := *v
		z.m[k] = &c
		if c.varies {
			n++
		}
	}
	z.nmarked.Store(n)
}

// marked reports whether answers in zone vary: it or a zone above it is
// marked.
func (z *zoneTable) marked(zone string) bool {
	_, ok := z.markedAt(zone)
	return ok
}

// markedAt returns the marked zone at or above zone.
func (z *zoneTable) markedAt(zone string) (string, bool) {
	if z.nmarked.Load() == 0 {
		return "", false
	}
	z.mu.RLock()
	defer z.mu.RUnlock()
	for n := zone; n != ""; n = parent(n) {
		if st := z.m[n]; st != nil && st.varies {
			return n, true
		}
	}
	return "", false
}

// probeDue reports whether zone may be probed now, and notes it.
func (z *zoneTable) probeDue(zone string, now time.Time) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.m == nil {
		z.m = map[string]*zoneState{}
	}
	st := z.m[zone]
	if st == nil {
		if len(z.m) >= maxZones {
			return false
		}
		st = &zoneState{}
		z.m[zone] = st
	}
	if st.varies || now.Before(st.until) || now.Sub(st.last) < probeEvery {
		return false
	}
	st.last = now
	return true
}

// result notes whether a zone's answers differed from here and there.
func (z *zoneTable) result(zone string, differ bool, now time.Time, relearn time.Duration) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.m == nil {
		z.m = map[string]*zoneState{}
	}
	st := z.m[zone]
	if st == nil {
		if len(z.m) >= maxZones {
			return
		}
		st = &zoneState{}
		z.m[zone] = st
	}
	if differ {
		st.run = max(st.run, 0) + 1
		if st.run >= zoneDiffer && !st.varies {
			st.varies = true
			z.nmarked.Add(1)
		}
		if st.varies {
			st.until = now.Add(relearn)
		}
		return
	}
	st.run = min(st.run, 0) - 1
	if -st.run >= zoneAgree {
		if st.varies {
			st.varies = false
			z.nmarked.Add(-1)
		}
		st.until = now.Add(relearn)
	}
}

// sweep forgets zones decided long ago that do not vary, and undecided
// ones not probed for a while.
func (z *zoneTable) sweep(now time.Time) {
	z.mu.Lock()
	defer z.mu.Unlock()
	for k, st := range z.m {
		if !st.varies && now.After(st.until) && now.Sub(st.last) > time.Hour {
			delete(z.m, k)
		}
	}
}

// counts returns how many zones are marked and how many are followed.
func (z *zoneTable) counts() (marked, known int) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return int(z.nmarked.Load()), len(z.m)
}

// bucket is a token bucket: rate a second, up to rate at once.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
}

func (b *bucket) setRate(r int) {
	b.mu.Lock()
	b.rate = float64(r)
	b.tokens = min(b.tokens, b.rate)
	b.mu.Unlock()
}

func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens = b.rate
	} else {
		b.tokens = min(b.rate, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ---- learning: the same question from here and through an exit ----

// prefixes returns the /24 (IPv4) and /48 (IPv6) networks of the addresses
// a reply gives: its answer's, or for a referral its glue's.
func prefixes(msg *message) (map[netip.Prefix]bool, bool) {
	out := map[netip.Prefix]bool{}
	add := func(rs []rr) {
		for _, x := range rs {
			if x.typ != m.TypeA && x.typ != m.TypeAAAA {
				continue
			}
			if a, ok := netip.AddrFromSlice(x.data); ok {
				a = a.Unmap()
				bits := 48
				if a.Is4() {
					bits = 24
				}
				p, _ := a.Prefix(bits)
				out[p] = true
			}
		}
	}
	add(msg.answer)
	referral := false
	if len(out) == 0 {
		add(msg.additional)
		referral = len(out) > 0
	}
	return out, referral
}

func overlap(a, b map[netip.Prefix]bool) bool {
	for p := range a {
		if b[p] {
			return true
		}
	}
	return false
}

// maybeProbe asks msg's question again through an exit, now and then, to
// learn whether zone's answers depend on where they are asked from.
func (r *Recursor) maybeProbe(lc *locState, d *delegation, name string, qtype uint16, msg *message, minimized bool) {
	if labelCount(d.zone) <= 1 || isSub(d.zone, arpaZone) || qtype == typeDS || qtype == typeDNSKEY {
		return
	}
	now := r.now()
	if !lc.zones.probeDue(d.zone, now) {
		return
	}
	here, referral := prefixes(msg) // (only now: a map for each answer otherwise)
	if len(here) == 0 || !lc.probes.take(now) {
		return
	}
	var ex *exitPath
	for i := 0; i < len(lc.exits) && ex == nil; i++ {
		if e := lc.exits[int(lc.rr.Add(1))%len(lc.exits)]; e.usable(now) {
			ex = e
		}
	}
	if ex == nil {
		return
	}
	lc.Probes.Add(1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		t := newTask()
		t.depth = 1 // what it looks up on the way is never a client's chain
		pm, err := r.queryVia(ctx, t, d, name, qtype, minimized, ex)
		if err != nil {
			return
		}
		there, ref := prefixes(pm)
		if len(there) == 0 || ref != referral {
			return // nothing to compare
		}
		lc.zones.result(d.zone, !overlap(here, there), r.now(), time.Duration(lc.relearn.Load()))
	}()
}

var arpaZone = m.WireName("arpa")

// ---- forks: the rest of a chain for every view ----

// frag is the part of an answer resolved for one view: from the name where
// the chain reached a marked zone to its end.
type frag struct {
	rcode    int
	chain    []*cachedSet
	until    []time.Time
	neg      *negEntry
	negUntil time.Time
}

func fragOf(a *answer) *frag {
	return &frag{rcode: a.rcode, chain: a.chain, until: a.until, neg: a.neg, negUntil: a.negUntil}
}

// clamp returns a copy of f that expires no later than exp.
func (f *frag) clamp(exp time.Time) *frag {
	c := *f
	c.until = make([]time.Time, len(f.until))
	for i, u := range f.until {
		c.until[i] = minTime(u, exp)
	}
	if f.neg != nil {
		c.negUntil = minTime(f.negUntil, exp)
	}
	return &c
}

// expiration is when the first part of f expires (zero: nothing to keep).
func (f *frag) expiry() time.Time {
	var exp time.Time
	for _, u := range f.until {
		if exp.IsZero() || u.Before(exp) {
			exp = u
		}
	}
	if f.neg != nil && (exp.IsZero() || f.negUntil.Before(exp)) {
		exp = f.negUntil
	}
	return exp
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// add puts f at the end of the answer.
func (a *answer) add(f *frag, validate bool) {
	for i, cs := range f.chain {
		a.chain = append(a.chain, cs)
		a.until = append(a.until, f.until[i])
		a.merge(cs.sec, cs.ede, cs.why, validate)
	}
	a.rcode = f.rcode
	if f.neg != nil {
		a.neg, a.negUntil = f.neg, f.negUntil
		a.merge(f.neg.sec, f.neg.ede, f.neg.why, validate)
	}
}

// locEntry is a fork's answers, kept until the first of them expires.
type locEntry struct {
	frags []*frag // by view; nil: that view's lookup failed or was not made
	orig  uint32  // seconds it was kept for
}

func (le *locEntry) frag(view int) *frag {
	if view < len(le.frags) && le.frags[view] != nil {
		return le.frags[view]
	}
	return le.frags[0]
}

// forkRun is a fork in progress.
type forkRun struct {
	start  time.Time
	zone   string // the marked zone reached
	frags  []*frag
	errs   []error
	active []bool
	done   []chan struct{}
}

// splice is where every view's part was put into a lookup's answer: what
// came before it (the same for every view), and the parts.
type splice struct {
	prefix []*cachedSet
	until  []time.Time
	entry  *locEntry
	run    *forkRun
}

// fragFor returns view's part if known, and whether its lookup is over
// (when it is over without a part, the server's own is given).
func (s *splice) fragFor(view int) (*frag, bool) {
	if s.entry != nil {
		return s.entry.frag(view), true
	}
	if view >= len(s.run.done) {
		view = 0
	}
	select {
	case <-s.run.done[view]:
		if f := s.run.frags[view]; f != nil {
			return f, true
		}
		if view == 0 {
			return nil, true
		}
		return s.fragForServer()
	default:
		return nil, false
	}
}

func (s *splice) fragForServer() (*frag, bool) {
	select {
	case <-s.run.done[0]:
		return s.run.frags[0], true
	default:
		return nil, false
	}
}

// errFork: the lookup reached a zone whose answers vary; it goes on for
// every view (step).
type errFork struct{ zone string }

func (e *errFork) Error() string {
	return "answers vary by where they are asked from: " + zoneName(e.zone)
}

// lookupVaried answers name/qtype from a fork kept earlier, for a client's
// lookup.
func (r *Recursor) lookupVaried(t *task, ans *answer, name string, qtype uint16, validate bool) bool {
	le, exp, ok := r.lsets.get(tkey(name, qtype))
	if !ok || !r.fresh(exp, le.orig, true) {
		return false
	}
	f := le.frag(t.clientView)
	if f == nil {
		return false
	}
	t.splice = &splice{prefix: slices.Clone(ans.chain), until: slices.Clone(ans.until), entry: le}
	ans.add(f, validate)
	r.Stats.CacheHits.Add(1)
	return true
}

// fork resolves the rest of the chain from name for every view at once (or
// joins the fork already doing so), and gives the lookup its client's view.
func (r *Recursor) fork(ctx context.Context, t *task, ans *answer, name string, qtype uint16, validate bool, zone string) (string, bool, error) {
	lc := r.loc.Load()
	if lc == nil { // turned off meanwhile: from here (no fork any more)
		return r.stepAsk(ctx, t, ans, name, qtype, validate)
	}
	if t.trace != nil {
		return r.traceFork(ctx, t, lc, ans, name, qtype, validate)
	}
	run := r.startFork(lc, name, qtype, validate, zone)
	v := t.clientView
	if v > 0 && run.active[v] {
		timer := time.NewTimer(max(time.Until(run.start.Add(time.Duration(lc.timeout.Load()))), 0))
		select {
		case <-run.done[v]:
			timer.Stop()
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return "", false, ctx.Err()
		}
	}
	f := (*frag)(nil)
	if v > 0 {
		select {
		case <-run.done[v]:
			f = run.frags[v]
		default:
		}
		if f == nil && run.active[v] {
			lc.exits[v-1].fallbacks.Add(1)
		}
	}
	if f == nil {
		select {
		case <-run.done[0]:
		case <-ctx.Done():
			return "", false, ctx.Err()
		}
		if f = run.frags[0]; f == nil {
			return "", false, run.errs[0]
		}
	}
	t.splice = &splice{prefix: slices.Clone(ans.chain), until: slices.Clone(ans.until), run: run}
	ans.add(f, validate)
	return "", true, nil
}

// startFork starts the lookups of a fork, or returns the one in progress.
func (r *Recursor) startFork(lc *locState, name string, qtype uint16, validate bool, zone string) *forkRun {
	key := tkey(name, qtype)
	lc.mu.Lock()
	if run := lc.runs[key]; run != nil {
		lc.mu.Unlock()
		return run
	}
	n := len(lc.exits) + 1
	now := r.now()
	run := &forkRun{start: time.Now(), zone: zone, frags: make([]*frag, n), errs: make([]error, n),
		active: make([]bool, n), done: make([]chan struct{}, n)}
	all := lc.fanout.take(now)
	if all {
		lc.Forks.Add(1)
	} else {
		lc.ForksLimited.Add(1)
	}
	for v := range n {
		run.done[v] = make(chan struct{})
		// over the fan-out limit, from here alone: never through the
		// client's exit only, which would tell where the client is
		run.active[v] = v == 0 || (all && lc.exits[v-1].usable(now))
		if !run.active[v] {
			run.errs[v] = ErrUnreachable
			close(run.done[v])
		}
	}
	lc.runs[key] = run
	lc.mu.Unlock()

	var wg sync.WaitGroup
	for v := range n {
		if !run.active[v] {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(run.done[v])
			ctx, cancel := context.WithTimeout(context.Background(), forkDeadline)
			defer cancel()
			tv := newTask()
			tv.view = v
			a, err := r.resolve(ctx, tv, name, qtype, validate)
			if err != nil {
				run.errs[v] = err
				return
			}
			run.frags[v] = fragOf(a)
		}()
	}
	go func() {
		wg.Wait()
		r.keepFork(lc, key, run)
		lc.mu.Lock()
		delete(lc.runs, key)
		lc.mu.Unlock()
	}()
	return run
}

// keepFork keeps a finished fork's answers until the first expires, and
// learns from them whether the zone still varies.
func (r *Recursor) keepFork(lc *locState, key string, run *forkRun) {
	if run.frags[0] == nil {
		return // the server's own lookup failed: nothing for its clients
	}
	for v := 1; v < len(run.frags); v++ {
		if run.active[v] {
			lc.exits[v-1].lookup(r, run.frags[v] != nil, r.now())
		}
	}
	var exp time.Time
	for _, f := range run.frags {
		if f == nil {
			continue
		}
		if e := f.expiry(); !e.IsZero() && (exp.IsZero() || e.Before(exp)) {
			exp = e
		}
	}
	now := r.now()
	if exp.After(now) {
		le := &locEntry{frags: make([]*frag, len(run.frags)), orig: uint32(exp.Sub(now) / time.Second)}
		for v, f := range run.frags {
			if f != nil {
				le.frags[v] = f.clamp(exp)
			}
		}
		r.lsets.set(key, le, exp)
	}
	// still varying? compared as a probe would be
	here := chainPrefixes(run.frags[0])
	if len(here) == 0 {
		return
	}
	compared, differ := false, false
	for v := 1; v < len(run.frags); v++ {
		if f := run.frags[v]; f != nil {
			if there := chainPrefixes(f); len(there) > 0 {
				compared = true
				differ = differ || !overlap(here, there)
			}
		}
	}
	if compared {
		lc.zones.result(run.zone, differ, now, time.Duration(lc.relearn.Load()))
	}
}

func chainPrefixes(f *frag) map[netip.Prefix]bool {
	var rs []rr
	for _, cs := range f.chain {
		if cs.set.typ == m.TypeA || cs.set.typ == m.TypeAAAA {
			rs = append(rs, cs.set.records()...)
		}
	}
	p, _ := prefixes(&message{answer: rs})
	return p
}

// variants builds the response for every view whose part is known.
func (r *Recursor) variants(q *m.Query, flags uint16, s *splice, dnssec, validate bool) [][]byte {
	lc := r.loc.Load()
	if lc == nil {
		return nil
	}
	out := make([][]byte, len(lc.exits)+1)
	for v := range out {
		f, _ := s.fragFor(v)
		if f == nil {
			continue
		}
		a := &answer{rcode: m.RcodeNoError, sec: secSecure}
		if !dnssec {
			a.sec = secUnchecked
		}
		for i, cs := range s.prefix {
			a.chain = append(a.chain, cs)
			a.until = append(a.until, s.until[i])
			a.merge(cs.sec, cs.ede, cs.why, dnssec)
		}
		a.add(f, dnssec)
		out[v] = r.message(q, flags, a, validate)
	}
	return out
}

// traceFork resolves the rest of the chain for every view in turn, each
// step labeled with its view, and lists every view's answer.
func (r *Recursor) traceFork(ctx context.Context, t *task, lc *locState, ans *answer, name string, qtype uint16, validate bool) (string, bool, error) {
	var f0 *frag
	var err0 error
	for v := 0; v <= len(lc.exits); v++ {
		via := locality.ServerName
		if v > 0 {
			via = lc.exits[v-1].name
			if !lc.exits[v-1].usable(r.now()) {
				t.trace.views = append(t.trace.views, TraceView{Via: via, Error: "not used: it stopped answering"})
				continue
			}
		}
		// the trace's own task, set to this view for the while: a new task
		// holding the trace would let every task's contents escape to the
		// heap (a cost on every query)
		t.view, t.trace.via = v, via
		a, err := r.resolve(ctx, t, name, qtype, validate)
		t.view, t.trace.via = -1, ""
		tview := TraceView{Via: via}
		if err != nil {
			tview.Error = err.Error()
		} else {
			tview.Rcode = m.RcodeString(a.rcode)
			for _, cs := range a.chain {
				for _, rec := range cs.set.records() {
					tview.Answers = append(tview.Answers, describeRR(rec))
				}
			}
		}
		t.trace.views = append(t.trace.views, tview)
		if v == 0 {
			if err != nil {
				err0 = err
			} else {
				f0 = fragOf(a)
			}
		}
	}
	if f0 == nil {
		if err0 == nil {
			err0 = ErrUnreachable
		}
		return "", false, err0
	}
	ans.add(f0, validate)
	return "", true, nil
}

// ---- measurements through one exit ----

// ErrNoExit: no exit by that name.
var ErrNoExit = errors.New("no such exit")

// ExchangeExit answers msg as asked from exit (by name): every zone below
// the top-level domains is asked through it, and the answer is neither
// taken from nor kept in the shared cache. It is for tools that measure
// how names resolve there (locality.measure_path).
func (r *Recursor) ExchangeExit(ctx context.Context, msg []byte, exit string) ([]byte, error) {
	lc := r.loc.Load()
	if lc == nil {
		return nil, ErrNoExit
	}
	for _, e := range lc.exits {
		if e.name == exit {
			return r.answerQuery(ctx, msg, true, e)
		}
	}
	return nil, ErrNoExit
}

// ---- what the admin interface shows ----

// ExitStatus is one exit's state.
type ExitStatus struct {
	Name      string    `json:"name"`
	Up        bool      `json:"up"`
	DownUntil time.Time `json:"down_until,omitzero"`
	RTTMS     float64   `json:"rtt_ms"`
	LastOK    time.Time `json:"last_ok,omitzero"`
	Queries   int64     `json:"queries"`
	Timeouts  int64     `json:"timeouts"`
	Fallbacks int64     `json:"fallbacks"`
}

// LocalityStatus is private locality's state; nil when it is off.
type LocalityStatus struct {
	Exits        []ExitStatus `json:"exits"`
	ZonesVarying int          `json:"zones_varying"`
	ZonesKnown   int          `json:"zones_known"`
	Forks        int64        `json:"forks"`
	ForksLimited int64        `json:"forks_limited"`
	Probes       int64        `json:"probes"`
}

// Locality returns private locality's state, or nil when it is off.
func (r *Recursor) Locality() *LocalityStatus {
	lc := r.loc.Load()
	if lc == nil {
		return nil
	}
	now := r.now()
	st := &LocalityStatus{Forks: lc.Forks.Load(), ForksLimited: lc.ForksLimited.Load(), Probes: lc.Probes.Load()}
	st.ZonesVarying, st.ZonesKnown = lc.zones.counts()
	for _, e := range lc.exits {
		es := ExitStatus{Name: e.name, Up: e.usable(now), RTTMS: float64(e.rtt.Load()) / 1e6,
			Queries: e.queries.Load(), Timeouts: e.timeouts.Load(), Fallbacks: e.fallbacks.Load()}
		if !es.Up {
			es.DownUntil = time.Unix(0, e.down.Load())
		}
		if ok := e.lastOK.Load(); ok != 0 {
			es.LastOK = time.Unix(0, ok)
		}
		st.Exits = append(st.Exits, es)
	}
	return st
}

// VaryingZones returns the zones found to answer by where they are asked
// from.
func (r *Recursor) VaryingZones() []string {
	lc := r.loc.Load()
	if lc == nil {
		return nil
	}
	lc.zones.mu.RLock()
	defer lc.zones.mu.RUnlock()
	var out []string
	for z, st := range lc.zones.m {
		if st.varies {
			out = append(out, m.NameString(z))
		}
	}
	slices.Sort(out)
	return out
}

// ---- keeping what was learned across a restart ----
//
// The file holds the zones whose answers vary, and until when: names of
// zones (content networks, mostly), no clients, no answers.

var zonesMagic = [8]byte{'D', 'N', 'S', 'N', 'L', 'O', 'C', 1}

// ErrZonesFile is returned for a file that is damaged or not one.
var ErrZonesFile = errors.New("not a locality zones file, or damaged")

// SaveZones writes the zones whose answers vary to w and returns how many.
func (r *Recursor) SaveZones(w io.Writer) (int, error) {
	lc := r.loc.Load()
	if lc == nil {
		return 0, nil
	}
	lc.zones.mu.RLock()
	b := append([]byte(nil), zonesMagic[:]...)
	b = binary.BigEndian.AppendUint32(b, 0)
	n := 0
	for z, st := range lc.zones.m {
		if !st.varies || len(z) > 255 {
			continue
		}
		b = append(b, byte(len(z)))
		b = append(b, z...)
		b = binary.BigEndian.AppendUint64(b, uint64(st.until.Unix()))
		n++
	}
	lc.zones.mu.RUnlock()
	binary.BigEndian.PutUint32(b[8:], uint32(n))
	b = binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
	_, err := w.Write(b)
	return n, err
}

// LoadZones reads a file written by SaveZones and returns how many zones
// it marked. Zones past their time are checked again.
func (r *Recursor) LoadZones(rd io.Reader) (int, error) {
	lc := r.loc.Load()
	if lc == nil {
		return 0, nil
	}
	b, err := io.ReadAll(io.LimitReader(rd, 16<<20))
	if err != nil {
		return 0, err
	}
	if len(b) < 16 || [8]byte(b[:8]) != zonesMagic ||
		crc32.ChecksumIEEE(b[:len(b)-4]) != binary.BigEndian.Uint32(b[len(b)-4:]) {
		return 0, ErrZonesFile
	}
	count := int(binary.BigEndian.Uint32(b[8:]))
	body := b[12 : len(b)-4]
	z := &lc.zones
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.m == nil {
		z.m = map[string]*zoneState{}
	}
	n := 0
	for i := 0; i < count; i++ {
		if len(body) < 1 || len(body) < 1+int(body[0])+8 {
			return n, ErrZonesFile
		}
		l := int(body[0])
		name := string(body[1 : 1+l])
		until := time.Unix(int64(binary.BigEndian.Uint64(body[1+l:])), 0)
		body = body[1+l+8:]
		if !validWireName(name) || len(z.m) >= maxZones {
			continue
		}
		if st := z.m[name]; st != nil && st.varies {
			continue
		}
		z.m[name] = &zoneState{varies: true, run: zoneDiffer, until: until}
		z.nmarked.Add(1)
		n++
	}
	return n, nil
}

// validWireName checks a wire-format name without its final zero byte.
func validWireName(s string) bool {
	if len(s) == 0 || len(s) > 254 {
		return false
	}
	for i := 0; i < len(s); {
		l := int(s[i])
		if l == 0 || l > 63 || i+1+l > len(s) {
			return false
		}
		i += 1 + l
	}
	return true
}

// usableAddrs drops the addresses of a family the exit has no source
// address for (nil: from here, all).
func (e *exitPath) usableAddrs(addrs []netip.Addr) []netip.Addr {
	if e == nil {
		return addrs
	}
	return slices.DeleteFunc(addrs, func(a netip.Addr) bool {
		_, ok := e.local(a)
		return !ok
	})
}
