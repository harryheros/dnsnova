package server

import "github.com/harryheros/dnsnova/internal/guard"

// Test clients all connect from 127.0.0.1; the tests of private mode need
// it to be an outside client like any other.
func init() { guard.LoopbackPermitted = false }
