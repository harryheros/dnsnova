package recursor

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func setServer(r *Recursor, a netip.Addr, f func(s *server)) {
	r.infra.mu.Lock()
	f(r.infra.get(a))
	r.infra.mu.Unlock()
}

func getServer(r *Recursor, a netip.Addr) (server, bool) {
	r.infra.mu.Lock()
	defer r.infra.mu.Unlock()
	s, ok := r.infra.m[a]
	if !ok {
		return server{}, false
	}
	return *s, true
}

// What is learnt about name servers comes back after a restart: round
// trips still current and quirks still in force. Failures, stale round
// trips, lame zones and cookies do not.
func TestServersSurviveRestart(t *testing.T) {
	n := world()
	r := newTest(t, n, true)
	now := r.now()
	fast, quirky, failing, stale := exA, ex2A, bankA, netip.MustParseAddr("2001:db8::53")
	setServer(r, fast, func(s *server) {
		s.srtt, s.lastUsed = 12*time.Millisecond, now.Add(-time.Minute)
		s.lame = map[string]time.Time{"example.com.": now.Add(time.Minute)}
		s.scookie, s.ccookie = []byte("12345678"), []byte("abcdefgh")
	})
	setServer(r, quirky, func(s *server) {
		s.srtt, s.lastUsed = 40*time.Millisecond, now.Add(-time.Minute)
		s.plainUntil, s.noTCPUntil = now.Add(30*time.Minute), now.Add(50*time.Minute)
	})
	setServer(r, failing, func(s *server) { s.srtt, s.fails, s.until, s.lastUsed = 2*time.Second, 3, now.Add(time.Minute), now })
	setServer(r, stale, func(s *server) { s.srtt, s.lastUsed = 9*time.Millisecond, now.Add(-time.Hour) })

	var buf bytes.Buffer
	saved, err := r.SaveServers(&buf)
	if err != nil || saved != 2 {
		t.Fatalf("saved %d, %v", saved, err)
	}
	r2 := newTest(t, world(), true)
	loaded, err := r2.LoadServers(bytes.NewReader(buf.Bytes()))
	if err != nil || loaded != 2 {
		t.Fatalf("loaded %d, %v", loaded, err)
	}
	s, ok := getServer(r2, fast)
	if !ok || s.srtt != 12*time.Millisecond || s.lame != nil || s.scookie != nil || s.ccookie != nil {
		t.Fatalf("fast server: %+v", s)
	}
	s, _ = getServer(r2, quirky)
	if !r2.infra.plain(quirky, now) || !r2.infra.noTCP(quirky, now) || s.srtt != 40*time.Millisecond {
		t.Fatalf("quirky server: %+v", s)
	}
	for _, a := range []netip.Addr{failing, stale} {
		if _, ok := getServer(r2, a); ok {
			t.Fatalf("%v kept", a)
		}
	}
	// the fastest is asked first straight away
	if a, b := r2.infra.score(fast, "example.com.", now), r2.infra.score(quirky, "example.com.", now); a >= b {
		t.Fatalf("scores %v %v", a, b)
	}
}

// A damaged or foreign file teaches nothing; values that could not have
// been learnt (a quirk lasting longer than an hour, a round trip from the
// future) are left out.
func TestServersFileChecked(t *testing.T) {
	r := newTest(t, world(), true)
	now := r.now()
	setServer(r, exA, func(s *server) { s.srtt, s.lastUsed = 10*time.Millisecond, now })
	var buf bytes.Buffer
	if _, err := r.SaveServers(&buf); err != nil {
		t.Fatal(err)
	}
	good := buf.Bytes()
	for name, b := range map[string][]byte{
		"empty":     nil,
		"truncated": good[:len(good)-1],
		"flipped":   append(append([]byte{}, good[:20]...), append([]byte{good[20] ^ 1}, good[21:]...)...),
		"foreign":   append([]byte("not a servers file at all"), good...),
	} {
		r2 := newTest(t, world(), true)
		if n, err := r2.LoadServers(bytes.NewReader(b)); !errors.Is(err, ErrServersFile) || n != 0 {
			t.Fatalf("%s: %d, %v", name, n, err)
		}
	}

	// saved by a server whose clock was ahead, read after it went back
	r3 := newTest(t, world(), true)
	setServer(r3, exA, func(s *server) { s.srtt, s.lastUsed = 10*time.Millisecond, now.Add(10*time.Minute) })
	setServer(r3, ex2A, func(s *server) { s.lastUsed, s.plainUntil = now, now.Add(3*time.Hour) })
	buf.Reset()
	r3.now = func() time.Time { return now.Add(9 * time.Minute) }
	if _, err := r3.SaveServers(&buf); err != nil {
		t.Fatal(err)
	}
	r4 := newTest(t, world(), true)
	if n, err := r4.LoadServers(bytes.NewReader(buf.Bytes())); err != nil || n != 0 {
		t.Fatalf("loaded %d, %v: values from the future", n, err)
	}
}

// What a server learnt since it started is newer than the file.
func TestServersFileDoesNotOverwrite(t *testing.T) {
	r := newTest(t, world(), true)
	now := r.now()
	setServer(r, exA, func(s *server) { s.srtt, s.lastUsed = 10*time.Millisecond, now })
	var buf bytes.Buffer
	r.SaveServers(&buf)
	r2 := newTest(t, world(), true)
	setServer(r2, exA, func(s *server) { s.srtt, s.lastUsed = 30*time.Millisecond, now })
	if n, _ := r2.LoadServers(bytes.NewReader(buf.Bytes())); n != 0 {
		t.Fatalf("loaded %d", n)
	}
	if s, _ := getServer(r2, exA); s.srtt != 30*time.Millisecond {
		t.Fatalf("srtt %v", s.srtt)
	}
}

// A file of any content is refused or read into sane values, never a
// panic.
func FuzzLoadServers(f *testing.F) {
	r := newTest(&testing.T{}, world(), true)
	now := r.now()
	setServer(r, exA, func(s *server) { s.srtt, s.lastUsed, s.noTCPUntil = 10*time.Millisecond, now, now.Add(time.Minute) })
	var buf bytes.Buffer
	r.SaveServers(&buf)
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := &Recursor{infra: newInfra(), now: func() time.Time { return now }} // all LoadServers uses
		n, err := r.LoadServers(bytes.NewReader(b))
		if err != nil && n != 0 {
			t.Fatal("servers taught from a refused file")
		}
		r.infra.mu.Lock()
		defer r.infra.mu.Unlock()
		for a, s := range r.infra.m {
			if s.srtt < 0 || s.srtt > maxSavedRTT || s.plainUntil.After(now.Add(time.Hour+time.Minute)) || a.IsUnspecified() {
				t.Fatalf("%v: %+v", a, s)
			}
		}
	})
}
