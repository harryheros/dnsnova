package guard

import (
	"net/netip"
	"sync/atomic"
)

// RRL is response rate limiting for UDP: when one network keeps receiving the
// same answer faster than the limit, the extra responses are dropped, except
// that every Slip-th one is sent truncated (TC=1). A real client then retries
// over TCP, which cannot be spoofed, while a reflection attack aimed at a
// victim gets almost nothing.
type RRL struct {
	b    *Bucket[rrlKey]
	slip int
	n    atomic.Uint64
}

type rrlKey struct {
	net   netip.Addr
	name  string
	qtype uint16
	rcode uint8
}

// RRLAction is what to do with a UDP response.
type RRLAction int

const (
	Send RRLAction = iota
	Slip           // send a truncated response
	Drop
)

// NewRRL returns a limiter allowing rate identical responses per second per
// network; rate 0 disables it (nil). slip 0 means never slip.
func NewRRL(rate float64, slip int) *RRL {
	if rate <= 0 {
		return nil
	}
	return &RRL{
		b: NewBucket[rrlKey](rate, rate, 1<<18, func(k rrlKey) uint32 {
			h := hashAddr(k.net)
			for i := 0; i < len(k.name); i++ {
				h ^= uint32(k.name[i])
				h *= 16777619
			}
			return h ^ uint32(k.qtype)<<8 ^ uint32(k.rcode)
		}),
		slip: slip,
	}
}

// Check decides the fate of one response. name is the wire-format query name;
// NXDOMAIN answers are grouped by rcode only, so random-subdomain floods
// share one budget.
func (r *RRL) Check(ip netip.Addr, name string, qtype uint16, rcode int) RRLAction {
	if r == nil {
		return Send
	}
	k := rrlKey{net: NetworkKey(ip), qtype: qtype, rcode: uint8(rcode)}
	if rcode != 3 { // NXDOMAIN
		k.name = name
	}
	if r.b.Allow(k) {
		return Send
	}
	if r.slip > 0 && r.n.Add(1)%uint64(r.slip) == 0 {
		return Slip
	}
	return Drop
}

// Sweep drops idle state.
func (r *RRL) Sweep() {
	if r != nil {
		r.b.Sweep()
	}
}
