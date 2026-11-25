package config

import (
	"errors"
	"strings"
	"testing"
)

func TestLocalitySettings(t *testing.T) {
	base := `[server]
mode = "public"

[recursion]
enabled = true

[doh]
listen = "127.0.0.1:8053"
`
	c, _, _, err := Load([]byte(base + `
[locality]
enabled = true
exits = ["exit-a 10.66.1.2 XA,XB", "office 10.66.3.2 10.20.0.0/16"]
exit_timeout = "1s"
fanout_qps = 50
relearn = "48h"
measure_path = "/exit-k3v9q2m8x7w4r1t6y5u0p2z8"
`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Locality.Enabled || len(c.LocalityExits()) != 2 || c.Locality.FanoutQPS != 50 {
		t.Fatalf("%+v", c.Locality)
	}
	d, _, _, err := Load([]byte(base))
	if err != nil || d.Locality.Enabled || d.Locality.ExitTimeout.String() != "800ms" || d.Locality.FanoutQPS != 200 || d.Locality.Relearn.Hours() != 168 {
		t.Fatalf("defaults %+v %v", d.Locality, err)
	}
	for name, tc := range map[string]struct{ src, want string }{
		"no recursion": {"[locality]\nenabled = true\nexits = [\"a 10.66.1.2 XA\"]\n", "needs recursion.enabled"},
		"with ecs":     {base + "[ecs]\naddress = \"203.0.113.0/24\"\n[locality]\nenabled = true\nexits = [\"a 10.66.1.2 XA\"]\n", "choose one"},
		"no exit":      {base + "[locality]\nenabled = true\n", "at least one exit"},
		"bad exit":     {base + "[locality]\nexits = [\"a 10.66.1.2\"]\n", "locality.exits"},
		"slow timeout": {base + "[locality]\nexit_timeout = \"30s\"\n", "locality.exit_timeout"},
		"short path":   {base + "[locality]\nmeasure_path = \"/x\"\n", "locality.measure_path"},
		"nested path":  {base + "[locality]\nmeasure_path = \"/exit/k3v9q2m8x7w4r1t6y5u0p2z8\"\n", "locality.measure_path"},
		"bad source":   {base + "[locality]\ncountry_sources = [\"ftp://x\"]\n", "locality.country_sources"},
		"fanout":       {base + "[locality]\nfanout_qps = 0\n", "locality.fanout_qps"},
		"relearn":      {base + "[locality]\nrelearn = \"10m\"\n", "locality.relearn"},
	} {
		_, _, _, err := Load([]byte(tc.src))
		var es Errors
		if !errors.As(err, &es) || !strings.Contains(es.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
