package config

import (
	"strings"
	"testing"
)

// Lists typed into the settings (networks, local records, forwarded
// domains, client groups): parsing never
// panics, and what parses is well formed.
func FuzzLists(f *testing.F) {
	f.Add("192.168.0.0/16\nfd00::/8\n10.0.0.1")
	f.Add("nas.home 192.168.1.5\nprinter.lan fd00::5")
	f.Add("corp.example 10.0.0.53 tls://dc.corp.example#10.0.0.53\nlan 192.168.1.1")
	f.Add("finance 10.1.0.0/24 10.1.1.5 filter block=a.com,*.b.com allow=c.com\nlab ::1 nofilter")
	f.Fuzz(func(t *testing.T, s string) {
		list := strings.Split(s, "\n")
		if zs, err := ParseForwardZones(list); err == nil {
			for _, z := range zs {
				if z.Name == "" || strings.HasSuffix(z.Name, ".") || z.Name != strings.ToLower(z.Name) || len(z.Servers) == 0 {
					t.Fatalf("forward zone %+v from %q", z, s)
				}
			}
		}
		if gs, err := ParseGroups(list); err == nil {
			for _, g := range gs {
				if g.Name == "" || len(g.Networks) == 0 || (g.Filter != "" && g.Filter != "on" && g.Filter != "off") {
					t.Fatalf("group %+v from %q", g, s)
				}
				for _, p := range g.Networks {
					if !p.IsValid() || p != p.Masked() {
						t.Fatalf("group network %v from %q", p, s)
					}
				}
			}
		}
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
