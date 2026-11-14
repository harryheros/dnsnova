package insight

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// NOD tells when a domain is looked up here for the first time (a newly
// observed domain): phishing and malware mostly use domains registered
// days before, which nobody on a network has asked for until then.
//
// It keeps no names: only two Bloom filters (bits set by hashes of the
// domains, under a random key), one for the current period and one for the
// previous, so a domain is remembered for one to two periods. The filters
// can be saved and loaded, so a restart does not make every domain new.
// After it starts with nothing saved, it learns quietly for a while before
// reporting anything.

const (
	nodBits    = 1 << 24 // per filter: 2 MB
	nodHashes  = 7       // about 0.05% false "seen" at a million domains
	nodRecent  = 500     // newly seen domains kept for the admin page
	nodPending = 200     // at most this many waiting for the next alert
	nodMagic   = "DNSNOD1\n"
)

// NODPeriod is how long one filter collects domains.
const NODPeriod = 30 * 24 * time.Hour

// NewDomain is one newly observed domain.
type NewDomain struct {
	Time   time.Time `json:"time"`
	Domain string    `json:"domain"`
	Name   string    `json:"name"`   // the name looked up
	Client string    `json:"client"` // who asked first (shortened unless full addresses are kept)
	Type   string    `json:"type"`
}

type bloom struct {
	bits  []atomic.Uint64
	start time.Time
}

func newBloom(start time.Time) *bloom {
	return &bloom{bits: make([]atomic.Uint64, nodBits/64), start: start}
}

// NOD is safe for concurrent use; Observe takes no lock unless the domain
// is new.
type NOD struct {
	key        atomic.Pointer[[16]byte]
	cur, prev  atomic.Pointer[bloom]
	learnUntil atomic.Int64 // unix ns; nothing is reported before
	ignore     atomic.Pointer[[]string]

	mu      sync.Mutex
	recent  []NewDomain
	pending []NewDomain
	total   atomic.Uint64
	now     func() time.Time
}

// NewNOD returns a detector with empty filters that learns for learn
// before reporting.
func NewNOD(learn time.Duration) *NOD {
	n := &NOD{now: time.Now}
	var key [16]byte
	rand.Read(key[:])
	n.key.Store(&key)
	now := n.now()
	n.cur.Store(newBloom(now))
	n.prev.Store(newBloom(now))
	n.learnUntil.Store(now.Add(learn).UnixNano())
	n.SetIgnore(nil)
	return n
}

// SetIgnore sets domains never reported, with everything under them.
func (n *NOD) SetIgnore(list []string) {
	out := make([]string, 0, len(list))
	for _, d := range list {
		if d = strings.ToLower(strings.Trim(strings.TrimSpace(d), ".")); d != "" {
			out = append(out, d)
		}
	}
	n.ignore.Store(&out)
}

func (n *NOD) ignored(domain string) bool {
	for _, d := range *n.ignore.Load() {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func (n *NOD) hashes(domain string) (uint64, uint64) {
	// FNV-1a over the key and the domain, then one more byte for the
	// second hash (double hashing), without allocating.
	const prime = 1099511628211
	h := uint64(14695981039346656037)
	for _, c := range n.key.Load() {
		h = (h ^ uint64(c)) * prime
	}
	for i := 0; i < len(domain); i++ {
		h = (h ^ uint64(domain[i])) * prime
	}
	return h, (h * prime) | 1
}

func (b *bloom) has(h1, h2 uint64) bool {
	for i := uint64(0); i < nodHashes; i++ {
		bit := (h1 + i*h2) % nodBits
		if b.bits[bit/64].Load()&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
}

func (b *bloom) add(h1, h2 uint64) {
	for i := uint64(0); i < nodHashes; i++ {
		bit := (h1 + i*h2) % nodBits
		b.bits[bit/64].Or(1 << (bit % 64))
	}
}

// Observe notes that name (whose domain is domain, lowercase, no final
// dot) was looked up by client, and reports whether the domain is new.
func (n *NOD) Observe(domain, name, qtype, client string) bool {
	if domain == "" || strings.HasSuffix(domain, "arpa") || strings.HasSuffix(domain, "(reverse lookups)") {
		return false
	}
	now := n.now()
	n.rotate(now)
	h1, h2 := n.hashes(domain)
	cur := n.cur.Load()
	if cur.has(h1, h2) {
		return false
	}
	if n.prev.Load().has(h1, h2) {
		cur.add(h1, h2) // still in use: keep it for the next period
		return false
	}
	cur.add(h1, h2)
	if now.UnixNano() < n.learnUntil.Load() || n.ignored(domain) {
		return false
	}
	n.total.Add(1)
	d := NewDomain{Time: now, Domain: domain, Name: name, Client: client, Type: qtype}
	n.mu.Lock()
	n.recent = append(n.recent, d)
	if len(n.recent) > nodRecent {
		n.recent = n.recent[len(n.recent)-nodRecent:]
	}
	if len(n.pending) < nodPending {
		n.pending = append(n.pending, d)
	}
	n.mu.Unlock()
	return true
}

// rotate starts a new period once the current one is over.
func (n *NOD) rotate(now time.Time) {
	cur := n.cur.Load()
	if now.Sub(cur.start) < NODPeriod {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if cur != n.cur.Load() {
		return // rotated meanwhile
	}
	n.prev.Store(cur)
	n.cur.Store(newBloom(now))
}

// Recent returns the newly observed domains, newest first.
func (n *NOD) Recent() []NewDomain {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]NewDomain, len(n.recent))
	for i, d := range n.recent {
		out[len(n.recent)-1-i] = d
	}
	return out
}

// TakePending returns the domains seen since the last call, for an alert.
func (n *NOD) TakePending() []NewDomain {
	n.mu.Lock()
	defer n.mu.Unlock()
	p := n.pending
	n.pending = nil
	return p
}

// NODState describes the detector.
type NODState struct {
	Learning   bool      `json:"learning"`
	LearnUntil time.Time `json:"learn_until,omitzero"`
	Total      uint64    `json:"total"` // reported since the start
	Since      time.Time `json:"since"` // the current period began
}

// State describes the detector now.
func (n *NOD) State() NODState {
	until := time.Unix(0, n.learnUntil.Load())
	st := NODState{Learning: n.now().Before(until), Total: n.total.Load(), Since: n.prev.Load().start}
	if st.Learning {
		st.LearnUntil = until.UTC()
	}
	return st
}

// ---- saving ----

// Save writes the filters (and the key, the periods and the end of
// learning) to w: no names.
func (n *NOD) Save(w io.Writer) error {
	cur, prev := n.cur.Load(), n.prev.Load()
	var hdr bytes.Buffer
	hdr.WriteString(nodMagic)
	hdr.Write(n.key.Load()[:])
	for _, t := range []int64{cur.start.UnixNano(), prev.start.UnixNano(), n.learnUntil.Load()} {
		binary.Write(&hdr, binary.BigEndian, t)
	}
	if _, err := w.Write(hdr.Bytes()); err != nil {
		return err
	}
	buf := make([]byte, 8*len(cur.bits))
	for _, b := range []*bloom{cur, prev} {
		for i := range b.bits {
			binary.LittleEndian.PutUint64(buf[8*i:], b.bits[i].Load())
		}
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// Load reads what Save wrote; on error n is unchanged.
func (n *NOD) Load(r io.Reader) error {
	hdr := make([]byte, len(nodMagic)+16+24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return err
	}
	if string(hdr[:len(nodMagic)]) != nodMagic {
		return errors.New("not a saved NOD state")
	}
	var key [16]byte
	copy(key[:], hdr[len(nodMagic):])
	ts := hdr[len(nodMagic)+16:]
	curStart := time.Unix(0, int64(binary.BigEndian.Uint64(ts)))
	prevStart := time.Unix(0, int64(binary.BigEndian.Uint64(ts[8:])))
	learn := int64(binary.BigEndian.Uint64(ts[16:]))
	cur, prev := newBloom(curStart), newBloom(prevStart)
	buf := make([]byte, 8*len(cur.bits))
	for _, b := range []*bloom{cur, prev} {
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		for i := range b.bits {
			b.bits[i].Store(binary.LittleEndian.Uint64(buf[8*i:]))
		}
	}
	n.mu.Lock()
	n.key.Store(&key)
	n.cur.Store(cur)
	n.prev.Store(prev)
	n.learnUntil.Store(learn)
	n.mu.Unlock()
	return nil
}

// SaveFile writes the state to path atomically (mode 0600).
func (n *NOD) SaveFile(path string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := n.Save(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// LoadFile reads a state saved with SaveFile.
func (n *NOD) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return n.Load(f)
}
