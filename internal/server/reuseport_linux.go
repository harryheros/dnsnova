package server

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// reusePort lets several UDP sockets share one address, so the kernel
// spreads incoming queries across them, and across CPU cores (Linux 3.9+).
// Every socket on the address must set it, so a port already taken by
// another program still fails to bind.
func reusePort(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}

const canReusePort = true
