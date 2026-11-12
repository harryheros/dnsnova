package config

import (
	"strings"
	"testing"
)

// Lists typed into the settings (networks, local records): parsing never
// panics, and what parses is well formed.
func FuzzLists(f *testing.F) {
	f.Add("192.168.0.0/16\nfd00::/8\n10.0.0.1")
	f.Add("nas.home 192.168.1.5\nprinter.lan fd00::5")
	f.Fuzz(func(t *testing.T, s string) {
		list := strings.Split(s, "\n")
		if ps, err := ParsePrefixes(list); err == nil {
			for _, p := range ps {
				if !p.IsValid() || p != p.Masked() {
					t.Fatalf("prefix %v from %q", p, s)
				}
			}
		}
		if recs, err := ParseLocalRecords(list); err == nil {
			for _, r := range recs {
				if !r.Addr.IsValid() || r.Name == "" || strings.HasSuffix(r.Name, ".") || r.Name != strings.ToLower(r.Name) {
					t.Fatalf("record %+v from %q", r, s)
				}
			}
		}
	})
}
