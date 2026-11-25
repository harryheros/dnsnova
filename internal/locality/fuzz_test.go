package locality

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

// FuzzParseExits: whatever an exits line holds, parsing does not panic,
// and what it accepts is usable: every exit has a name, a source address
// of each family at most, and clients.
func FuzzParseExits(f *testing.F) {
	for _, s := range []string{"exit-a 10.66.1.2 XA XB", "b 10.66.2.2,fd66::2 XC,XD, 198.51.100.0/24", "o 10.66.3.2 10.20.0.7", "x 1.2.3.4", "", "a ::ffff:1.2.3.4 XA"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		exits, err := ParseExits(strings.Split(s, "\n"))
		if err != nil {
			return
		}
		for _, e := range exits {
			v4, v6 := 0, 0
			for _, a := range e.Local {
				if a.Is4() {
					v4++
				} else {
					v6++
				}
			}
			if e.Name == "" || v4 > 1 || v6 > 1 || len(e.Local) == 0 || len(e.Countries)+len(e.Networks) == 0 {
				t.Fatalf("accepted %+v", e)
			}
		}
		m := NewMapper(exits)
		m.View(netip.MustParseAddr("10.20.0.7"))
	})
}

// FuzzParseCountries: a registry file of any content parses without
// panicking, and lookups in what it built stay in bounds.
func FuzzParseCountries(f *testing.F) {
	f.Add([]byte(registryFile))
	f.Add([]byte("x|XA|ipv4|255.255.255.0|4294967295|1|allocated\nx|XA|ipv6|::|64|1|assigned\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseCountries(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, a := range []string{"0.0.0.0", "255.255.255.255", "203.0.113.1", "::", "2001:db8::1", "ffff::1"} {
			if cc := c.Lookup(netip.MustParseAddr(a)); cc != "" && len(cc) != 2 {
				t.Fatalf("%s: %q", a, cc)
			}
		}
	})
}
