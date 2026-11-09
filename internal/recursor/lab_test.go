package recursor

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLabServe answers on DNSNOVA_LAB_LISTEN for DNSNOVA_LAB_SECONDS, using
// the lab hierarchy (root hints and anchor from DNSNOVA_LAB_DIR). Only for
// manual comparison with a reference resolver; skipped otherwise.
func TestLabServe(t *testing.T) {
	dir := os.Getenv("DNSNOVA_LAB_DIR")
	if dir == "" {
		t.Skip("DNSNOVA_LAB_DIR not set")
	}
	ds, err := os.ReadFile(dir + "/root.ds")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(ds))
	cfg := Config{DNSSEC: true, QNameMinimisation: os.Getenv("DNSNOVA_LAB_NOMIN") == "", IPv6: false,
		Allow:        []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		RootHints:    []netip.Addr{netip.MustParseAddr("127.1.0.1"), netip.MustParseAddr("127.1.0.2")},
		TrustAnchors: []string{strings.Join(f[len(f)-4:], " ")}}
	r := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	pc, err := net.ListenPacket("udp", os.Getenv("DNSNOVA_LAB_LISTEN"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	secs, _ := time.ParseDuration(os.Getenv("DNSNOVA_LAB_SECONDS") + "s")
	pc.SetDeadline(time.Now().Add(secs))
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := r.Exchange(ctx, q)
			if err != nil {
				t.Logf("error: %v", err)
				return
			}
			pc.WriteTo(resp, addr)
		}()
	}
}
