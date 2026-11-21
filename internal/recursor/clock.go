package recursor

import (
	"errors"
	"fmt"
	"time"
)

// A machine without a battery-backed clock (a Raspberry Pi) can start with
// a time days or years off. DNSSEC then fails for every signed name, which
// shows only as SERVFAIL. The root's own key set tells: if its signature
// is genuine but "not yet valid" or "expired", the clock is wrong, and by
// at least how much (the signature is valid for about three weeks).

// noteClock looks at the root key set's validation: a good one clears a
// clock error; one that failed only for time is checked without the time,
// and if genuine, says how far off the clock is.
func (r *Recursor) noteClock(keyset *rrset, keys []*dnskey, now time.Time, err error) {
	if err == nil {
		if r.clockOff.Swap(0) != 0 && r.log != nil {
			r.log.Info("the clock is right again: DNSSEC answers validate")
		}
		return
	}
	if !errors.Is(err, errSigNotYet) && !errors.Is(err, errSigExpired) {
		return
	}
	tries := 4 // a bounded number of checks (KeyTrap)
	for _, raw := range keyset.sigs {
		s, ok := parseSig(raw)
		if !ok || s.covered != typeDNSKEY || s.signer != "" {
			continue
		}
		for _, k := range keys {
			if k.tag != s.tag || k.alg != s.alg {
				continue
			}
			if tries == 0 {
				return
			}
			tries--
			if !verify(keyset, s, k) {
				continue
			}
			t := now.Unix()
			var off time.Duration
			switch {
			case t < int64(s.inc):
				off = time.Duration(int64(s.inc)-t) * time.Second // behind
			case t > int64(s.exp):
				off = -time.Duration(t-int64(s.exp)) * time.Second // ahead
			default:
				return
			}
			if r.clockOff.Swap(int64(off)) == 0 && r.log != nil {
				r.log.Error("this machine's clock is wrong: DNSSEC answers fail until it is set (NTP)", "clock", now.UTC().Format(time.RFC3339), "off_by_at_least", ClockText(off))
			}
			return
		}
	}
}

// ClockOff says how far this machine's clock is from the time the root's
// signatures show: positive when it is behind (at least this much),
// negative when ahead, zero when it looks right or is not known.
func (r *Recursor) ClockOff() time.Duration { return time.Duration(r.clockOff.Load()) }

// ClockText says how far off the clock is, in words: "3 days behind".
func ClockText(off time.Duration) string {
	way := "behind"
	if off < 0 {
		off, way = -off, "ahead"
	}
	switch {
	case off >= 48*time.Hour:
		return fmt.Sprintf("%d days %s", int(off.Hours()/24), way)
	case off >= 2*time.Hour:
		return fmt.Sprintf("%d hours %s", int(off.Hours()), way)
	}
	return fmt.Sprintf("%d minutes %s", int(off.Minutes()), way)
}
