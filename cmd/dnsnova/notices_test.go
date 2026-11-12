package main

import (
	"os"
	"strings"
	"testing"
)

// Every module the binary is built from is in THIRD_PARTY_NOTICES.md, at
// the version in go.mod: their licenses require the notices to go with it.
func TestThirdPartyNotices(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	notices, err := os.ReadFile("../../THIRD_PARTY_NOTICES.md")
	if err != nil {
		t.Fatal(err)
	}
	in := false
	for _, line := range strings.Split(string(mod), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "require ("):
			in = true
			continue
		case line == ")":
			in = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimPrefix(line, "require ")
		case !in:
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if !strings.Contains(string(notices), "## "+f[0]+" "+f[1]+"\n") {
			t.Errorf("%s %s is not in THIRD_PARTY_NOTICES.md (with its license text)", f[0], f[1])
		}
	}
}
