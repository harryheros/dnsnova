package server

import (
	"bytes"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/dnstest"
)

// syncBuf is a log sink safe for the server's goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// startEdited starts a server from the test configuration with edit
// applied to its text, logging into the returned buffer.
func startEdited(t *testing.T, edit func(string) string) (*Server, *syncBuf, error) {
	t.Helper()
	auth := dnstest.Serve(t)
	path := filepath.Join(t.TempDir(), "dnsnova.toml")
	writeConfig(t, path, auth.Addr, "")
	src, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(edit(string(src))), 0o640); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	s, err := New(config.NewStore(path), slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		return nil, logs, err
	}
	t.Cleanup(s.Shutdown)
	return s, logs, nil
}

func answers(t *testing.T, s *Server) {
	t.Helper()
	udp, _, _, _ := s.Addrs()
	if _, err := udpAsk(t, udp[0], dnstest.Query(1, "up.test", 1, false, false), 2*time.Second); err != nil {
		t.Fatalf("DNS does not answer: %v", err)
	}
}

// An address that is not on the machine yet (at boot: DHCP, or IPv6 still
// checking that the address is unique; or one that changed) used to stop
// the server, every other address with it.
func TestStartsWhenAListenAddressIsNotUpYet(t *testing.T) {
	s, logs, err := startEdited(t, func(c string) string {
		return strings.Replace(c, `listen = ["127.0.0.1:0"]`, `listen = ["127.0.0.1:0", "192.0.2.77:0"]`, 1)
	})
	if err != nil {
		t.Fatalf("did not start: %v", err)
	}
	answers(t, s)
	if !strings.Contains(logs.String(), "listen address not on this machine (yet)") ||
		!strings.Contains(logs.String(), "192.0.2.77:0") {
		t.Fatalf("no warning about the missing address:\n%s", logs)
	}
}

// Another program on the metrics port (9153 is also CoreDNS's) used to
// stop the whole server.
func TestStartsWhenTheMetricsPortIsTaken(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	s, logs, err := startEdited(t, func(c string) string {
		return strings.Replace(c, "[metrics]\nlisten = \"127.0.0.1:0\"", "[metrics]\nlisten = \""+busy.Addr().String()+"\"", 1)
	})
	if err != nil {
		t.Fatalf("did not start: %v", err)
	}
	answers(t, s)
	if !strings.Contains(logs.String(), "metrics not available") {
		t.Fatalf("no error logged:\n%s", logs)
	}
	// a reload that keeps the address does not fail either
	snap, _ := s.Store.Load()
	if err := s.Apply(snap); err != nil {
		t.Fatalf("reload with the same metrics address: %v", err)
	}
}

func TestStartsWhenTheAdminPortIsTaken(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	s, logs, err := startEdited(t, func(c string) string {
		return c + "\n[admin]\nlisten = \"" + busy.Addr().String() + "\"\n"
	})
	if err != nil {
		t.Fatalf("did not start: %v", err)
	}
	answers(t, s)
	if !strings.Contains(logs.String(), "admin not available") {
		t.Fatalf("no error logged:\n%s", logs)
	}
}

// Changing the metrics address now to a port that is taken is refused, as
// before: that is a mistake made now, which the person making it should see.
func TestChangingMetricsToATakenPortIsRefused(t *testing.T) {
	s, _, err := startEdited(t, func(c string) string { return c })
	if err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	snap, _ := s.Store.Load()
	out, err := snap.Doc.Set("metrics", "listen", config.Str(busy.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyConfig(out, snap.Hash); err == nil || !strings.Contains(err.Error(), "metrics") {
		t.Fatalf("taken metrics port accepted: %v", err)
	}
}

// Saving a new address that is not on this machine in the web interface is
// refused (most likely a typo), and the file is put back.
func TestSavingAnAddressThatIsNotHereIsRefused(t *testing.T) {
	s, _, err := startEdited(t, func(c string) string { return c })
	if err != nil {
		t.Fatal(err)
	}
	orig := hostAddrs
	hostAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} }
	defer func() { hostAddrs = orig }()
	snap, _ := s.Store.Load()
	out, err := snap.Doc.Set("server", "listen", config.StrList(append(snap.Config.Server.Listen, "198.51.100.9:0")))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ApplyConfig(out, snap.Hash)
	if err == nil || !strings.Contains(err.Error(), "198.51.100.9:0: not an address of this machine") {
		t.Fatalf("got %v", err)
	}
	if now, _ := s.Store.Load(); string(now.Doc.Src) != string(snap.Doc.Src) {
		t.Fatal("the file was not put back")
	}
	// an address that is here is accepted
	hostAddrs = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}
	}
	out, _ = snap.Doc.Set("server", "listen", config.StrList(append(snap.Config.Server.Listen, "127.0.0.2:0")))
	if _, err := s.ApplyConfig(out, snap.Hash); err != nil {
		t.Fatalf("a local address refused: %v", err)
	}
}

func TestMissingListen(t *testing.T) {
	orig := hostAddrs
	hostAddrs = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::5")}
	}
	defer func() { hostAddrs = orig }()
	c := &config.Config{}
	c.Server.Listen = []string{"203.0.113.5:53", "[2001:db8::5]:53", "127.0.0.1:53", ":53", "[::]:53", "203.0.113.6:53"}
	c.DoT.Listen = []string{"203.0.113.7:853"}
	got := missingListen(c, nil)
	if strings.Join(got, " ") != "203.0.113.6:53 203.0.113.7:853" {
		t.Fatalf("missing %v", got)
	}
	prev := &config.Config{}
	prev.Server.Listen = []string{"203.0.113.6:53"}
	if got := missingListen(c, prev); strings.Join(got, " ") != "203.0.113.7:853" {
		t.Fatalf("an address already configured counted as new: %v", got)
	}
}
