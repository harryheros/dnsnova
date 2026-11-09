package resolver

import (
	"context"
	"encoding/binary"
	"testing"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
	"github.com/harryheros/dnsnova/internal/dnstest"
	"github.com/harryheros/dnsnova/internal/stats"
)

// optUpstream answers with one A record and an OPT record carrying the
// given options, as a DoH upstream that pads or reports errors would.
type optUpstream struct {
	rcode int
	opts  []byte
}

func (u optUpstream) Exchange(_ context.Context, msg []byte) ([]byte, error) {
	q, _, _ := m.ParseQuery(msg)
	an := byte(1)
	if u.rcode != 0 {
		an = 0
	}
	b := []byte{msg[0], msg[1], 0x81, 0x80 | byte(u.rcode), 0, 1, 0, an, 0, 0, 0, 1}
	b = append(b, msg[m.HeaderLen:q.QEnd]...)
	if an == 1 {
		b = append(b, 0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 1)
	}
	b = append(b, 0, 0, 41, 4, 208, 0, 0, 0, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(u.opts)))
	return append(b, u.opts...), nil
}

func padding(n int) []byte {
	b := binary.BigEndian.AppendUint16(nil, m.OptPadding)
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	return append(b, make([]byte, n)...)
}

// paddedQuery is a query whose OPT record carries a Padding option.
func paddedQuery(id uint16, name string) []byte {
	q := dnstest.Query(id, name, 1, true, false)
	q = m.AddOptions(q, padding(8))
	return q
}

func TestUpstreamOptionsDoNotReachClients(t *testing.T) {
	r := New(settings(), optUpstream{opts: padding(400)}, stats.New())
	res := r.Resolve(dnstest.Query(1, "a.test", 1, true, false), true)
	if len(res.Resp) > 100 {
		t.Fatalf("plain UDP answer is %d bytes: the upstream's padding was passed on", len(res.Resp))
	}
	if p := dnstest.Parse(t, res.Resp); !p.HasOPT || p.AN != 1 {
		t.Fatalf("answer lost its record or OPT: %+v", p)
	}
	// A client without EDNS gets no OPT at all.
	if p := dnstest.Parse(t, r.Resolve(dnstest.Query(2, "a.test", 1, false, false), true).Resp); p.HasOPT {
		t.Fatal("OPT sent to a client that did not use EDNS")
	}
}

func TestUpstreamEDEIsPassedOn(t *testing.T) {
	// e.g. Cloudflare's "DNSSEC Bogus" (6) with a SERVFAIL
	r := New(settings(), optUpstream{rcode: m.RcodeServFail, opts: m.EDE(6, "bogus")}, stats.New())
	res := r.Resolve(dnstest.Query(1, "a.test", 1, true, false), true)
	if code, ok := edeCode(res.Resp); !ok || code != 6 {
		t.Fatalf("EDE %d %v, want 6 from the upstream", code, ok)
	}
	// still there when answered from the failure cache
	res = r.Resolve(dnstest.Query(2, "a.test", 1, true, false), true)
	if code, ok := edeCode(res.Resp); res.Source != stats.SourceCache || !ok || code != 6 {
		t.Fatalf("cached failure: source %d, EDE %d %v", res.Source, code, ok)
	}
}

func TestPaddingOnEncryptedTransports(t *testing.T) {
	r := New(settings(), optUpstream{}, stats.New())
	enc := r.ResolveOpts(paddedQuery(1, "a.test"), Opts{Encrypted: true})
	if len(enc.Resp)%m.PaddingBlock != 0 {
		t.Fatalf("encrypted answer to a padded query is %d bytes, not a multiple of %d", len(enc.Resp), m.PaddingBlock)
	}
	dnstest.Parse(t, enc.Resp)
	if res := r.ResolveOpts(paddedQuery(2, "a.test"), Opts{UDP: true}); len(res.Resp)%m.PaddingBlock == 0 {
		t.Fatal("plain UDP answer was padded")
	}
	if res := r.ResolveOpts(dnstest.Query(3, "a.test", 1, true, false), Opts{Encrypted: true}); len(res.Resp)%m.PaddingBlock == 0 {
		t.Fatal("answer padded for a client that did not pad")
	}
}

func TestBadVers(t *testing.T) {
	r := New(settings(), optUpstream{}, stats.New())
	q := dnstest.Query(7, "a.test", 1, true, false)
	q[len(q)-5] = 1 // EDNS version 1 (OPT: name, type, class, ext-rcode, VERSION, flags, rdlen)
	res := r.Resolve(q, true)
	p := dnstest.Parse(t, res.Resp)
	if res.Status != "badvers" || !p.HasOPT || p.AN != 0 {
		t.Fatalf("status %q, %+v", res.Status, p)
	}
	o := len(res.Resp) - 11
	if ext := res.Resp[o+5]; int(ext)<<4|p.Rcode != m.RcodeBadVers {
		t.Fatalf("extended rcode %d, want BADVERS", int(ext)<<4|p.Rcode)
	}
	if v := res.Resp[o+6]; v != 0 {
		t.Fatalf("OPT version %d in the reply, want 0", v)
	}
}

func TestStaticAnswersCarryEDE(t *testing.T) {
	r := New(settings(), optUpstream{}, stats.New())
	res := r.Resolve(dnstest.Query(1, "a.test", m.TypeANY, true, false), true)
	if code, ok := edeCode(res.Resp); !ok || code != m.EDENotSupported {
		t.Fatalf("ANY: EDE %d %v", code, ok)
	}
	if code, ok := edeCode(r.Resolve(dnstest.Query(1, "a.test", m.TypeANY, false, false), true).Resp); ok {
		t.Fatalf("EDE %d sent without EDNS", code)
	}
}
