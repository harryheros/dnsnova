package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseGroups(t *testing.T) {
	gs, err := ParseGroups([]string{
		"Finance 10.1.0.0/24 10.1.1.5 filter block=facebook.com,*.tiktok.com allow=ads.partner.example",
		"lab 10.9.0.0/16 2001:db8:9::/48 nofilter",
		"guests 192.168.50.7/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	f := gs[0]
	if f.Name != "finance" || f.Filter != "on" || len(f.Networks) != 2 || f.Networks[1] != netip.MustParsePrefix("10.1.1.5/32") ||
		strings.Join(f.Block, ",") != "facebook.com,tiktok.com" || strings.Join(f.Allow, ",") != "ads.partner.example" {
		t.Fatalf("finance: %+v", f)
	}
	if gs[1].Filter != "off" || len(gs[1].Networks) != 2 {
		t.Fatalf("lab: %+v", gs[1])
	}
	if gs[2].Filter != "" || gs[2].Networks[0] != netip.MustParsePrefix("192.168.50.0/24") {
		t.Fatalf("guests (masked network, filtering as the address decides): %+v", gs[2])
	}
	for _, c := range []struct {
		list []string
		want string
	}{
		{[]string{"finance"}, "write a name and its networks"},
		{[]string{"finance! 10.0.0.0/8"}, "a group name is"},
		{[]string{"a 10.0.0.0/8", "A 10.1.0.0/16"}, "listed twice"},
		{[]string{"a 10.0.0.0/8", "b 10.0.0.0/8"}, "already in group a"},
		{[]string{"a filter"}, "at least one network"},
		{[]string{"a 10.0.0.0/8 filter nofilter"}, "once"},
		{[]string{"a 10.0.0.0/8 block=not_a..domain"}, "is not a domain"},
		{[]string{"a 10.0.0.0/8 whitelist"}, "not a network, an address or an option"},
		{[]string{"a fe80::1%eth0"}, "not a network"},
	} {
		if _, err := ParseGroups(c.list); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v", c.list, err)
		}
	}
}
