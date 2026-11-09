//go:build !linux

package server

import "syscall"

func reusePort(_, _ string, _ syscall.RawConn) error { return nil }

// canReusePort is false off Linux: one socket per address.
const canReusePort = false
