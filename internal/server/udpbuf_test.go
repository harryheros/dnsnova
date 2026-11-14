package server

import (
	"net"
	"strings"
	"testing"
)

// TestGrantedBuffer: what granted reports is the buffer that was set, as
// usable bytes (Linux reports twice that).
func TestGrantedBuffer(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const want = 64 << 10 // below any system's cap
	if err := c.SetReadBuffer(want); err != nil {
		t.Fatal(err)
	}
	got, err := granted(c)
	if err != nil {
		t.Fatal(err)
	}
	if got < want*9/10 || got > want*11/10 {
		t.Fatalf("granted %d, want about %d", got, want)
	}
}

func TestShortBuffer(t *testing.T) {
	for _, tc := range []struct {
		got  int
		warn bool
	}{
		{udpBuffer, false},
		{udpBuffer * 95 / 100, false}, // rounding by the kernel
		{212992, true},                // the common default cap
		{1 << 20, true},
		{0, false}, // unknown: say nothing
	} {
		msg := shortBuffer(tc.got, udpBuffer)
		if (msg != "") != tc.warn {
			t.Errorf("got %d: %q", tc.got, msg)
		}
		if tc.warn && (!strings.Contains(msg, "net.core.rmem_max") || !strings.Contains(msg, "208 KB") && tc.got == 212992) {
			t.Errorf("got %d: message lacks the cause or the size: %q", tc.got, msg)
		}
	}
}
