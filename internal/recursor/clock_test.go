package recursor

import (
	"testing"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// A clock far off makes the root's genuine signatures "not yet valid" or
// "expired": the recursor says so, and by how much; once the clock is
// right the error clears.
func TestClockOffDetected(t *testing.T) {
	for _, c := range []struct {
		shift  time.Duration
		behind bool
	}{
		{-400 * 24 * time.Hour, true}, // started with last year's time
		{+400 * 24 * time.Hour, false},
	} {
		r, n := newSignedTest(t)
		good := n.f.now
		r.now = func() time.Time { return good.Add(c.shift) }
		askDO(t, r, "www.ed.com.", m.TypeA)
		off := r.ClockOff()
		if c.behind && off < 300*24*time.Hour || !c.behind && off > -300*24*time.Hour {
			t.Fatalf("shift %v: clock off %v", c.shift, off)
		}
		if txt := ClockText(off); c.behind && txt[len(txt)-6:] != "behind" || !c.behind && txt[len(txt)-5:] != "ahead" {
			t.Fatalf("text %q", txt)
		}
		r.now = func() time.Time { return good }
		r.ClearCache()
		askDO(t, r, "www.ed.com.", m.TypeA)
		if r.ClockOff() != 0 {
			t.Fatalf("still off after the clock was set: %v", r.ClockOff())
		}
	}
	// a right clock: nothing to report
	r, _ := newSignedTest(t)
	askDO(t, r, "www.ed.com.", m.TypeA)
	if r.ClockOff() != 0 {
		t.Fatal("clock reported off")
	}
}
