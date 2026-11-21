package resolver

import (
	"testing"
	"time"
)

// Eviction takes an answer no client used since it was last looked at,
// even one that expires later than a used one; the used ones lose their
// mark (a second chance) and go next time if still not used.
func TestEvictionKeepsUsedAnswers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := &cacheShard{m: map[string]*entry{}}
	popular := &entry{expire: now.Add(time.Minute)} // a CDN's short TTL
	once := &entry{expire: now.Add(24 * time.Hour)}
	popular.touch()
	s.m["popular"], s.m["once"] = popular, once
	if v := victim(s); v != "once" {
		t.Fatalf("evicted %s", v)
	}
	if popular.used.Load() {
		t.Fatal("the used answer kept its mark")
	}
	delete(s.m, "once")
	if v := victim(s); v != "popular" {
		t.Fatalf("evicted %s, want the answer no longer used", v)
	}

	// a refresh keeps the mark
	c := newCache(256)
	e := &entry{expire: now.Add(time.Minute)}
	c.set("k", e)
	c.get("k").touch()
	c.set("k", &entry{expire: now.Add(2 * time.Minute)})
	if !c.get("k").used.Load() {
		t.Fatal("refresh lost the mark")
	}
}
