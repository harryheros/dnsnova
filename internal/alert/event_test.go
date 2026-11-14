package alert

import (
	"strings"
	"testing"
)

func TestEvent(t *testing.T) {
	e, _, f := newTestEngine()
	e.Event("new_domains", "node-a", "2 newly seen domains", []string{"fresh.example", "other.example"})
	waitFor(t, "the event", func() bool { return len(f.statuses()) == 1 })
	f.mu.Lock()
	n := f.got[0]
	f.mu.Unlock()
	if n.Status != EventStatus || n.Severity != Info || n.Kind != "new_domains" || n.Server != "node-a" || len(n.Details) != 2 {
		t.Fatalf("%+v", n)
	}
	title, body := text(n)
	if !strings.HasPrefix(title, "[NOTICE] node-a: 2 newly seen domains") || strings.Contains(body, "Since") {
		t.Fatalf("%q %q", title, body)
	}
	// An event is not a condition: nothing to resolve later.
	if len(e.Active()) != 0 {
		t.Fatal("an event became a condition")
	}
}
