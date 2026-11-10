package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/admin"
	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/upstream"
)

// Addresses implements admin.Backend: the host's IP addresses, for the setup
// wizard to offer as DNS listen addresses.
func (s *Server) Addresses() []admin.HostAddress {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []admin.HostAddress
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr().Unmap()
			if ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				continue
			}
			out = append(out, admin.HostAddress{Address: ip.String(), Interface: ifc.Name,
				Public: ip.IsGlobalUnicast() && !ip.IsPrivate(), Loopback: ip.IsLoopback()})
		}
	}
	return out
}

// Lookup implements admin.Backend: ask each upstream directly, bypassing the
// cache, and report what it answered and how long it took. With no specs
// the configured upstreams are asked.
func (s *Server) Lookup(ctx context.Context, name string, qtype uint16, specs []string) []admin.LookupResult {
	cfg := s.state.Load().cfg
	if len(specs) == 0 {
		specs = append(append([]string{}, cfg.Upstream.Primary...), cfg.Upstream.Fallback...)
	}
	var boot *upstream.Bootstrap
	if len(cfg.Upstream.Bootstrap) > 0 {
		boot, _ = upstream.NewBootstrap(cfg.Upstream.Bootstrap)
	}
	dialer := upstream.NewDialer(boot)
	q := m.BuildUpstreamQuery(&m.Query{ID: 0, Name: name, Type: qtype, Class: 1}, ecsOption(cfg))
	out := make([]admin.LookupResult, len(specs))
	var wg sync.WaitGroup
	for i, raw := range specs {
		out[i].Upstream = raw
		wg.Add(1)
		go func(r *admin.LookupResult) {
			defer wg.Done()
			sp, err := upstream.ParseSpec(raw)
			if err != nil {
				r.Error = err.Error()
				return
			}
			u, err := upstream.New(sp, dialer, s.TLS)
			if err != nil {
				r.Error = err.Error()
				return
			}
			defer u.Close()
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			start := time.Now()
			resp, err := u.Exchange(cctx, m.WithID(q, uint16(time.Now().UnixNano())))
			r.MS = float64(time.Since(start).Microseconds()) / 1000
			if err != nil {
				r.Error = err.Error()
				if cctx.Err() != nil {
					r.Error = "no answer within 5 seconds"
				}
				return
			}
			r.Rcode = m.RcodeString(m.Rcode(resp))
			r.Answers = describeAnswers(resp)
		}(&out[i])
	}
	wg.Wait()
	return out
}

// describeAnswers renders the answer section briefly: addresses, names and
// otherwise the record type.
func describeAnswers(msg []byte) []string {
	out := []string{}
	if len(msg) < m.HeaderLen {
		return out
	}
	off := m.HeaderLen
	for i := 0; i < int(m.U16(msg, 4)); i++ {
		next, err := m.SkipName(msg, off)
		if err != nil {
			return out
		}
		off = next + 4
	}
	m.WalkRRs(msg, off, int(m.U16(msg, 6)), func(rr m.RR) error {
		rd := msg[rr.RDOff : rr.RDOff+rr.RDLen]
		ttl := binary.BigEndian.Uint32(msg[rr.TTLOff:])
		var v string
		switch {
		case rr.Type == 1 && len(rd) == 4, rr.Type == 28 && len(rd) == 16:
			a, _ := netip.AddrFromSlice(rd)
			v = a.String()
		case rr.Type == 5 || rr.Type == 2 || rr.Type == 12:
			v = readName(msg, rr.RDOff)
		default:
			v = fmt.Sprintf("%d bytes", len(rd))
		}
		out = append(out, fmt.Sprintf("%s %s (TTL %d)", m.TypeString(rr.Type), v, ttl))
		return nil
	})
	return out
}

// readName reads a possibly compressed name for display.
func readName(msg []byte, off int) string {
	var labels []string
	for jumps := 0; off < len(msg) && jumps < 20; {
		c := int(msg[off])
		switch {
		case c == 0:
			return strings.Join(labels, ".") + "."
		case c&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "?"
			}
			off = int(m.U16(msg, off) & 0x3FFF)
			jumps++
		default:
			if off+1+c > len(msg) {
				return "?"
			}
			labels = append(labels, string(msg[off+1:off+1+c]))
			off += 1 + c
		}
	}
	return "?"
}
