//go:build !linux

package server

import "syscall"

func freeBind(_, _ string, _ syscall.RawConn) error { return nil }
