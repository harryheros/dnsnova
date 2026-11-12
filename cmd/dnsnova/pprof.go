//go:build pprof

package main

// Built with -tags pprof (for performance work only, never in releases):
// the Go profiler on 127.0.0.1:6060, or $DNSNOVA_PPROF. See
// docs/benchmark.md.

import (
	"net/http"
	_ "net/http/pprof"
	"os"
)

func init() {
	addr := os.Getenv("DNSNOVA_PPROF")
	if addr == "" {
		addr = "127.0.0.1:6060"
	}
	go http.ListenAndServe(addr, nil)
}
