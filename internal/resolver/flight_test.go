package resolver

import (
	"testing"
	"time"
)

// A panic in the leader (recovered further up, as net/http does for DoH)
// must release its waiters and the key.
func TestFlightReleasesKeyAfterPanic(t *testing.T) {
	var g flightGroup
	started, release := make(chan struct{}), make(chan struct{})
	go func() {
		defer func() { recover() }()
		g.do("k", func() (*entry, error) { close(started); <-release; panic("boom") })
	}()
	<-started
	waiter := make(chan error, 1)
	go func() { _, err := g.do("k", func() (*entry, error) { return nil, nil }); waiter <- err }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	select {
	case err := <-waiter:
		if err == nil {
			t.Error("waiter got no error from a leader that panicked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter stuck after the leader panicked")
	}
	done := make(chan struct{})
	go func() { g.do("k", func() (*entry, error) { return &entry{}, nil }); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("key still blocked after the leader panicked")
	}
}
