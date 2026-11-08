package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/dnsmsg"
)

// Dialer connects to upstreams. IP addresses are dialled directly; host names
// use a pinned address when one is configured, otherwise the bootstrap
// resolver. The system resolver is never used, so dnsnova keeps working when
// it is the system resolver itself.
type Dialer struct {
	net  net.Dialer
	boot *Bootstrap
}

// NewDialer returns a dialer that resolves host names with boot (may be nil
// when every upstream is an IP address or pinned).
func NewDialer(boot *Bootstrap) *Dialer {
	return &Dialer{net: net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}, boot: boot}
}

// DialFunc returns a dial function bound to an optional pinned address.
func (d *Dialer) DialFunc(pin netip.Addr) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return d.net.DialContext(ctx, network, addr)
		}
		if pin.IsValid() {
			return d.net.DialContext(ctx, network, net.JoinHostPort(pin.String(), port))
		}
		if d.boot == nil {
			return nil, fmt.Errorf("cannot resolve %s: no bootstrap servers", host)
		}
		addrs, err := d.boot.Lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, a := range addrs {
			c, err := d.net.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
			if err == nil {
				return c, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
}

// Bootstrap resolves upstream host names through fixed servers, which may be
// plain DNS or encrypted (DoH/DoT) IP endpoints. Results are cached for their
// TTL (between one minute and one hour) and served stale for up to a day if
// the bootstrap servers fail.
type Bootstrap struct {
	ups []Upstream
	mu  sync.Mutex
	c   map[string]bootEntry
	now func() time.Time
}

type bootEntry struct {
	addrs  []netip.Addr
	expire time.Time
}

// NewBootstrap builds a bootstrap resolver from IP-only specs.
func NewBootstrap(specs []string) (*Bootstrap, error) {
	b := &Bootstrap{c: map[string]bootEntry{}, now: time.Now}
	direct := NewDialer(nil)
	for _, raw := range specs {
		s, err := ParseSpec(raw)
		if err != nil {
			return nil, err
		}
		if !s.HostIsIP() {
			return nil, fmt.Errorf("bootstrap %q must be an IP address", raw)
		}
		u, err := New(s, direct, nil)
		if err != nil {
			return nil, err
		}
		b.ups = append(b.ups, u)
	}
	return b, nil
}

var errNoAddrs = errors.New("no addresses")

// Lookup returns the IPv4 and IPv6 addresses of host, IPv4 first.
func (b *Bootstrap) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	now := b.now()
	b.mu.Lock()
	e, ok := b.c[host]
	b.mu.Unlock()
	if ok && now.Before(e.expire) {
		return e.addrs, nil
	}
	addrs, ttl, err := b.resolve(ctx, host)
	if err != nil {
		if ok && now.Before(e.expire.Add(24*time.Hour)) {
			return e.addrs, nil // stale is better than nothing
		}
		return nil, fmt.Errorf("bootstrap lookup of %s: %w", host, err)
	}
	ttl = max(ttl, time.Minute)
	ttl = min(ttl, time.Hour)
	b.mu.Lock()
	b.c[host] = bootEntry{addrs: addrs, expire: now.Add(ttl)}
	b.mu.Unlock()
	return addrs, nil
}

func (b *Bootstrap) resolve(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	labels := strings.Split(host, ".")
	name := dnsmsg.WireName(labels...)
	type res struct {
		addrs []netip.Addr
		ttl   uint32
		err   error
	}
	ch := make(chan res, 2)
	for _, t := range []uint16{dnsmsg.TypeA, dnsmsg.TypeAAAA} {
		go func(t uint16) {
			q := &dnsmsg.Query{Name: name, Type: t, Class: dnsmsg.ClassIN}
			msg := dnsmsg.BuildUpstreamQuery(q)
			var lastErr error = errNoAddrs
			for _, u := range b.ups {
				resp, err := u.Exchange(ctx, msg)
				if err != nil {
					lastErr = err
					continue
				}
				addrs, ttl, err := extractAddrs(resp, t)
				ch <- res{addrs, ttl, err}
				return
			}
			ch <- res{err: lastErr}
		}(t)
	}
	var v4, v6 []netip.Addr
	var ttl uint32 = 3600
	var lastErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err != nil {
			lastErr = r.err
			continue
		}
		for _, a := range r.addrs {
			if a.Is4() {
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
		}
		if len(r.addrs) > 0 {
			ttl = min(ttl, r.ttl)
		}
	}
	all := append(v4, v6...)
	if len(all) == 0 {
		if lastErr == nil {
			lastErr = errNoAddrs
		}
		return nil, 0, lastErr
	}
	return all, time.Duration(ttl) * time.Second, nil
}

// extractAddrs reads A or AAAA records from the answer section.
func extractAddrs(resp []byte, t uint16) ([]netip.Addr, uint32, error) {
	if dnsmsg.Rcode(resp) != dnsmsg.RcodeNoError {
		return nil, 0, fmt.Errorf("lookup failed: %s", dnsmsg.RcodeString(dnsmsg.Rcode(resp)))
	}
	off, err := dnsmsg.SkipName(resp, dnsmsg.HeaderLen)
	if err != nil || off+4 > len(resp) {
		return nil, 0, dnsmsg.ErrMalformed
	}
	var out []netip.Addr
	var ttl uint32 = 3600
	_, err = dnsmsg.WalkRRs(resp, off+4, int(dnsmsg.U16(resp, 6)), func(rr dnsmsg.RR) error {
		if rr.Type != t || rr.Class != dnsmsg.ClassIN {
			return nil // CNAME and friends
		}
		var a netip.Addr
		var ok bool
		if t == dnsmsg.TypeA && rr.RDLen == 4 {
			a, ok = netip.AddrFrom4([4]byte(resp[rr.RDOff:rr.RDOff+4])), true
		} else if t == dnsmsg.TypeAAAA && rr.RDLen == 16 {
			a, ok = netip.AddrFrom16([16]byte(resp[rr.RDOff:rr.RDOff+16])), true
		}
		if ok {
			out = append(out, a)
			ttl = min(ttl, dnsmsg.U32(resp, rr.TTLOff))
		}
		return nil
	})
	return out, ttl, err
}
