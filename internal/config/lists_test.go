package config

import "testing"

func TestParseLocalRecordsNames(t *testing.T) {
	good := []string{
		"nas.home 192.168.1.5",
		"NAS.Home. 192.168.1.5",
		"nas 192.168.1.5",
		"a_b.home 192.168.1.5",
		"*.home 192.168.1.5",
		"printer.lan fd00::5",
	}
	for _, s := range good {
		if _, err := ParseLocalRecords([]string{s}); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{
		"0.. ::",
		"nas..home 192.168.1.5",
		".nas.home 192.168.1.5",
		"-nas.home 192.168.1.5",
		"nas-.home 192.168.1.5",
		"nas.-home 192.168.1.5",
		"*. 192.168.1.5",
		"a.*.home 192.168.1.5",
	}
	for _, s := range bad {
		if r, err := ParseLocalRecords([]string{s}); err == nil {
			t.Errorf("%q: accepted as %+v", s, r)
		}
	}
}
