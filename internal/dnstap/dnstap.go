// Package dnstap sends queries and answers, as dnstap
// (https://dnstap.info), to a log collector such as Vector, dnscollector
// or Splunk's dnstap input, over a Unix socket or TCP.
//
// It speaks the bidirectional Frame Streams protocol, as the fstrm library
// does: READY, ACCEPT, START, then data frames. Sending never delays an
// answer: messages wait in a queue, and when the collector is gone or slow
// they are dropped and counted.
package dnstap

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ContentType is the Frame Streams content type of dnstap.
const ContentType = "protobuf:dnstap.Dnstap"

const queueSize = 1 << 15

// Settings configure the sender.
type Settings struct {
	// Target is "unix:/path" or "tcp:host:port"; empty is off.
	Target    string
	Queries   bool // send CLIENT_QUERY messages
	Responses bool // send CLIENT_RESPONSE messages
	FullIP    bool // whole client addresses (else 203.0.113.0, 2001:db8:1::)
	Identity  string
	Version   string
}

// ParseTarget checks a target and returns its network and address.
func ParseTarget(t string) (network, addr string, err error) {
	network, addr, ok := strings.Cut(t, ":")
	switch {
	case !ok || addr == "":
	case network == "unix" && strings.HasPrefix(addr, "/"):
		return network, addr, nil
	case network == "tcp":
		if _, _, err := net.SplitHostPort(addr); err == nil {
			return network, addr, nil
		}
	}
	return "", "", fmt.Errorf("%q: write unix:/path/to/socket or tcp:host:port", t)
}

// Event is one answered query.
type Event struct {
	Proto    string // udp, tcp, dot, doh, doh3, doq
	Client   netip.AddrPort
	Query    []byte // as received
	Response []byte // as sent; nil if none
	Start    time.Time
	End      time.Time
}

// Sender is safe for concurrent use.
type Sender struct {
	mu   sync.Mutex
	set  Settings
	gen  uint64 // bumped when the target changes: the connection is redone
	on   atomic.Bool
	q, r atomic.Bool // queries, responses
	full atomic.Bool
	ch   chan []byte
	kick chan struct{}

	sent, dropped, errors atomic.Uint64
	connected             atomic.Bool
	lastErr               atomic.Pointer[string]

	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout time.Duration
}

// New returns a sender that is off until Configure.
func New() *Sender {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &Sender{ch: make(chan []byte, queueSize), kick: make(chan struct{}, 1), dial: d.DialContext, timeout: 5 * time.Second}
}

// Configure applies settings (already checked with ParseTarget).
func (s *Sender) Configure(set Settings) {
	s.mu.Lock()
	if set.Target != s.set.Target {
		s.gen++
	}
	s.set = set
	s.mu.Unlock()
	s.q.Store(set.Queries)
	s.r.Store(set.Responses)
	s.full.Store(set.FullIP)
	s.on.Store(set.Target != "" && (set.Queries || set.Responses))
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// On reports whether events are sent.
func (s *Sender) On() bool { return s.on.Load() }

// Add queues ev; it never blocks.
func (s *Sender) Add(ev Event) {
	if !s.on.Load() {
		return
	}
	s.mu.Lock()
	id, ver := s.set.Identity, s.set.Version
	s.mu.Unlock()
	client := ev.Client
	if !s.full.Load() {
		client = netip.AddrPortFrom(shorten(client.Addr()), 0)
	}
	if s.q.Load() && ev.Query != nil {
		s.queue(encode(id, ver, msgClientQuery, ev, client))
	}
	if s.r.Load() && ev.Response != nil {
		s.queue(encode(id, ver, msgClientResponse, ev, client))
	}
}

func (s *Sender) queue(frame []byte) {
	select {
	case s.ch <- frame:
	default:
		s.dropped.Add(1)
	}
}

// State describes the sender.
type State struct {
	On        bool   `json:"on"`
	Target    string `json:"target,omitempty"`
	Connected bool   `json:"connected"`
	Sent      uint64 `json:"sent"`
	Dropped   uint64 `json:"dropped"`
	Errors    uint64 `json:"errors"`
	LastError string `json:"last_error,omitempty"`
	FullIP    bool   `json:"full_ip"`
}

// State describes the sender now.
func (s *Sender) State() State {
	s.mu.Lock()
	target := s.set.Target
	s.mu.Unlock()
	st := State{On: s.on.Load(), Target: target, Connected: s.connected.Load(), Sent: s.sent.Load(),
		Dropped: s.dropped.Load(), Errors: s.errors.Load(), FullIP: s.full.Load() && s.on.Load()}
	if p := s.lastErr.Load(); p != nil {
		st.LastError = *p
	}
	return st
}

func (s *Sender) fail(err error) {
	s.errors.Add(1)
	m := err.Error()
	s.lastErr.Store(&m)
}

// Run connects and sends until ctx is done, reconnecting after failures
// (after 1s, doubling up to 30s).
func (s *Sender) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		s.mu.Lock()
		target, gen := s.set.Target, s.gen
		s.mu.Unlock()
		if !s.on.Load() {
			s.discard()
			select {
			case <-ctx.Done():
				return
			case <-s.kick:
			}
			continue
		}
		network, addr, err := ParseTarget(target)
		if err == nil {
			err = s.session(ctx, network, addr, gen)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, errReconfigured) {
			s.fail(err)
			select {
			case <-ctx.Done():
				return
			case <-s.kick:
				backoff = time.Second
			case <-time.After(backoff):
				backoff = min(2*backoff, 30*time.Second)
			}
			continue
		}
		backoff = time.Second
	}
}

// discard empties the queue while off.
func (s *Sender) discard() {
	for {
		select {
		case <-s.ch:
		default:
			return
		}
	}
}

var errReconfigured = errors.New("reconfigured")

// session runs one connection: the handshake, then frames until an error,
// a change of target, or ctx is done (then STOP is sent).
func (s *Sender) session(ctx context.Context, network, addr string, gen uint64) error {
	conn, err := s.dial(ctx, network, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(s.timeout))
	if err := writeControl(conn, ctrlReady, ContentType); err != nil {
		return err
	}
	typ, ct, err := readControl(conn)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	if typ != ctrlAccept || (ct != "" && ct != ContentType) {
		return fmt.Errorf("handshake: the collector did not accept %s", ContentType)
	}
	if err := writeControl(conn, ctrlStart, ContentType); err != nil {
		return err
	}
	conn.SetDeadline(time.Time{})
	s.connected.Store(true)
	defer s.connected.Store(false)

	// The collector sends nothing more until STOP: a read that ends means
	// the connection is gone.
	gone := make(chan struct{})
	go func() { io.Copy(io.Discard, conn); close(gone) }()

	w := bufio.NewWriterSize(conn, 64<<10)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	write := func(frame []byte) error {
		conn.SetWriteDeadline(time.Now().Add(s.timeout))
		if _, err := w.Write(frame); err != nil {
			return err
		}
		s.sent.Add(1)
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			w.Flush()
			writeControl(conn, ctrlStop, "")
			return nil
		case <-gone:
			return errors.New("the collector closed the connection")
		case frame := <-s.ch:
			if err := write(frame); err != nil {
				return err
			}
		case <-tick.C:
			if w.Buffered() > 0 {
				conn.SetWriteDeadline(time.Now().Add(s.timeout))
				if err := w.Flush(); err != nil {
					return err
				}
			}
		case <-s.kick:
			s.mu.Lock()
			changed := s.gen != gen
			s.mu.Unlock()
			if changed || !s.on.Load() {
				w.Flush()
				writeControl(conn, ctrlStop, "")
				return errReconfigured
			}
		}
	}
}

// ---- Frame Streams ----

const (
	ctrlAccept = 0x01
	ctrlStart  = 0x02
	ctrlStop   = 0x03
	ctrlReady  = 0x04
	ctrlFinish = 0x05

	fieldContentType = 0x01
	maxControl       = 512
)

func writeControl(w io.Writer, typ uint32, contentType string) error {
	body := binary.BigEndian.AppendUint32(nil, typ)
	if contentType != "" {
		body = binary.BigEndian.AppendUint32(body, fieldContentType)
		body = binary.BigEndian.AppendUint32(body, uint32(len(contentType)))
		body = append(body, contentType...)
	}
	b := binary.BigEndian.AppendUint32(nil, 0) // escape: a control frame follows
	b = binary.BigEndian.AppendUint32(b, uint32(len(body)))
	_, err := w.Write(append(b, body...))
	return err
}

// readControl reads one control frame and returns its type and content
// type (the first, if several).
func readControl(r io.Reader) (uint32, string, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, "", err
	}
	if binary.BigEndian.Uint32(hdr[:4]) != 0 {
		return 0, "", errors.New("expected a control frame")
	}
	n := binary.BigEndian.Uint32(hdr[4:])
	if n < 4 || n > maxControl {
		return 0, "", errors.New("bad control frame length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, "", err
	}
	typ := binary.BigEndian.Uint32(body)
	var ct string
	for b := body[4:]; len(b) >= 8; {
		ft, fl := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
		if uint64(fl) > uint64(len(b)-8) {
			return 0, "", errors.New("bad control field")
		}
		if ft == fieldContentType && ct == "" {
			ct = string(b[8 : 8+fl])
		}
		b = b[8+fl:]
	}
	return typ, ct, nil
}

// ---- dnstap protobuf ----

const (
	msgClientQuery    = 5
	msgClientResponse = 6
)

var socketProtocol = map[string]uint64{"udp": 1, "tcp": 2, "dot": 3, "doh": 4, "doh3": 4, "doq": 7}

// encode returns one data frame: length, then a Dnstap message.
func encode(identity, version string, typ uint64, ev Event, client netip.AddrPort) []byte {
	var m []byte
	m = pbVarint(m, 1, typ)
	a := client.Addr()
	if a.IsValid() {
		a = a.Unmap()
		fam := uint64(1)
		if a.Is6() {
			fam = 2
		}
		m = pbVarint(m, 2, fam)
	}
	if p, ok := socketProtocol[ev.Proto]; ok {
		m = pbVarint(m, 3, p)
	}
	if a.IsValid() {
		m = pbBytes(m, 4, a.AsSlice())
		if client.Port() != 0 {
			m = pbVarint(m, 6, uint64(client.Port()))
		}
	}
	m = pbVarint(m, 8, uint64(ev.Start.Unix()))
	m = pbFixed32(m, 9, uint32(ev.Start.Nanosecond()))
	if typ == msgClientQuery || ev.Query != nil {
		m = pbBytes(m, 10, ev.Query)
	}
	if typ == msgClientResponse {
		m = pbVarint(m, 12, uint64(ev.End.Unix()))
		m = pbFixed32(m, 13, uint32(ev.End.Nanosecond()))
		m = pbBytes(m, 14, ev.Response)
	}
	if ev.Proto == "doh" || ev.Proto == "doh3" {
		h := uint64(2)
		if ev.Proto == "doh3" {
			h = 3
		}
		m = pbVarint(m, 16, h)
	}
	var d []byte
	if identity != "" {
		d = pbBytes(d, 1, []byte(identity))
	}
	if version != "" {
		d = pbBytes(d, 2, []byte(version))
	}
	d = pbBytes(d, 14, m)
	d = pbVarint(d, 15, 1) // MESSAGE
	return append(binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(d)), uint32(len(d))), d...)
}

func pbKey(b []byte, field, wire uint64) []byte { return binary.AppendUvarint(b, field<<3|wire) }

func pbVarint(b []byte, field, v uint64) []byte {
	return binary.AppendUvarint(pbKey(b, field, 0), v)
}

func pbBytes(b []byte, field uint64, v []byte) []byte {
	b = binary.AppendUvarint(pbKey(b, field, 2), uint64(len(v)))
	return append(b, v...)
}

func pbFixed32(b []byte, field uint64, v uint32) []byte {
	return binary.LittleEndian.AppendUint32(pbKey(b, field, 5), v)
}

// shorten keeps the network of a: /24 for IPv4, /48 for IPv6.
func shorten(a netip.Addr) netip.Addr {
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return a
	}
	return p.Addr()
}
