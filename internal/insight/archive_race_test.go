package insight

import (
	"testing"
	"time"
)

// A record the writer had already taken when a search started is found by
// that search. drain used to check whether anything was pending after
// letting go of the lock: if the writer wrote the record just then, drain
// saw nothing pending and returned without flushing it, and the search
// missed it (a record missing in TestArchiveWritesAndSearches on 32-bit ARM
// in CI, where the emulator is slow enough to hit that moment).
// The hooks force that moment every time.
func TestArchiveSearchFindsTheRecordTheWriterHeld(t *testing.T) {
	took := make(chan struct{}, 1)
	release := make(chan struct{})
	testHookWriterTook = func() { took <- struct{}{}; <-release }
	var a *Archive
	first := true
	testHookDrainUnlocked = func() {
		if !first {
			return
		}
		first = false
		close(release) // the writer writes the record now, between unlock and check
		for a.pending.Load() > 0 {
			time.Sleep(time.Millisecond)
		}
	}
	t.Cleanup(func() { testHookWriterTook, testHookDrainUnlocked = nil, nil })

	var now *fakeClock
	a, _, now, _ = testArchive(t, 7, true)
	a.Add(q(now.get(), "held.example", "NOERROR", "cache"), alice)
	<-took // the writer has it and waits
	if got := names(search(t, a, ArchiveQuery{})); got != "held.example" {
		t.Fatalf("the record the writer held is missing: %q", got)
	}
}
