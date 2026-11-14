package server

import (
	"fmt"
	"net"
	"sync"
	"syscall"
)

// udpBuffer is the receive and send buffer asked for on DNS sockets: room
// for a burst of queries while the readers catch up.
const udpBuffer = 4 << 20

// The system caps socket buffers (on Linux, net.core.rmem_max), silently:
// a server with the common default of about 200 KB drops queries in bursts
// the buffer asked for would have absorbed. It is said once, at the first
// socket that is cut short.
var bufferWarned sync.Once

// granted returns the receive buffer c actually has. Linux reports twice
// the usable size (the rest is its bookkeeping), so that is halved.
func granted(c *net.UDPConn) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		n, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	if gerr != nil {
		return 0, gerr
	}
	return reportedToUsable(n), nil
}

// shortBuffer says what to do when a socket got less than it asked for, or
// "" when it got enough. got and want are in bytes.
func shortBuffer(got, want int) string {
	if got <= 0 || got >= want*9/10 {
		return ""
	}
	return fmt.Sprintf("UDP receive buffer is %d KB, not the %d KB asked for: the system caps it (net.core.rmem_max), "+
		"and bursts of queries can be dropped. Raise it: sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000 "+
		"(and in /etc/sysctl.d to keep it; install.sh does this)", got>>10, want>>10)
}
