package upstream

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errTimeout = errors.New("timeout")

// A fallback that answers in 4 ms but once timed out: its latency is still
// 4 ms. Mixed into the latency, the 3 s penalty took dozens of answers to
// wear off, and a fallback gets few, so it showed seconds for days.
func TestLatencyCountsAnswersOnly(t *testing.T) {
	m := &Member{}
	m.observe(4*time.Millisecond, nil, 3*time.Second)
	m.observe(3*time.Second, errTimeout, 3*time.Second)
	m.observe(4*time.Millisecond, nil, 3*time.Second)
	if got := m.Latency(); got != 4*time.Millisecond {
		t.Fatalf("latency %v, want 4ms", got)
	}
	// ranking still holds the failure against it
	if score := time.Duration(m.ewma.Load()) * time.Microsecond; score < time.Second {
		t.Fatalf("ranking score %v forgot the failure", score)
	}
}

func TestLatencyUnknownBeforeAnAnswer(t *testing.T) {
	m := &Member{}
	m.observe(3*time.Second, errTimeout, 3*time.Second)
	if m.Latency() != 0 {
		t.Fatalf("latency %v with no answer yet", m.Latency())
	}
}

func TestLostRaceIsNotObserved(t *testing.T) {
	m := &Member{}
	m.observe(time.Millisecond, context.Canceled, 3*time.Second)
	if m.Errors() != 0 || m.Latency() != 0 || !m.Healthy() {
		t.Fatal("a canceled query counted")
	}
}

func TestIdleAfterAnOldFailure(t *testing.T) {
	m := &Member{}
	now := time.Now()
	if m.Idle(now) {
		t.Fatal("never asked: healthy, not idle")
	}
	m.observe(time.Millisecond, nil, time.Second)
	m.observe(time.Second, errTimeout, time.Second)
	if m.Healthy() || m.Idle(time.Now()) {
		t.Fatal("a fresh failure is failing, not idle")
	}
	if !m.Idle(time.Now().Add(IdleAfter + time.Second)) {
		t.Fatal("a failure long ago, nothing since: idle")
	}
	m.observe(time.Millisecond, nil, time.Second)
	if m.Idle(time.Now().Add(IdleAfter + time.Second)) {
		t.Fatal("answered since: healthy, not idle")
	}
}

func TestAdoptKeepsWhatIsKnownAboutUnchangedUpstreams(t *testing.T) {
	a, b, gone := &fake{name: "a"}, &fake{name: "b"}, &fake{name: "gone"}
	old := group([]*fake{a, gone}, []*fake{b}, 0, time.Second)
	old.primary[0].observe(5*time.Millisecond, nil, time.Second)
	old.primary[0].observe(time.Second, errTimeout, time.Second)
	old.fallback[0].observe(7*time.Millisecond, nil, time.Second)

	// a stays a primary, b becomes a primary, c is new
	c := &fake{name: "c"}
	g := group([]*fake{a, b, c}, nil, 0, time.Second)
	g.Adopt(old)
	ga, gb, gc := g.primary[0], g.primary[1], g.primary[2]
	if ga.Errors() != 1 || ga.Healthy() || ga.Latency() != 5*time.Millisecond || ga.ewma.Load() == 0 {
		t.Fatalf("a not carried over: errors %d healthy %v latency %v", ga.Errors(), ga.Healthy(), ga.Latency())
	}
	if gb.Latency() != 0 || gc.Latency() != 0 {
		t.Fatal("a changed role or a new upstream starts afresh")
	}
	g.Adopt(nil)
}
