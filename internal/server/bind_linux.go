package server

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// freeBind lets a DNS listener bind an address this machine does not have
// yet (IP_FREEBIND): at boot an address may come
// up after DNSNova starts (DHCP, or IPv6 still checking the address is
// unique), and one listen address missing would otherwise stop the server
// and every other address with it. Queries arrive once the address is up.
func freeBind(network, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		// errors ignored: without it the bind behaves as before
		_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
		if strings.HasSuffix(network, "6") {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
		}
	})
}
