package config

import (
	"slices"
	"strings"
	"testing"
)

const primarySrc = `# the fleet's settings
[server]
mode = "public"
listen = ["192.0.2.1:53"]
data_dir = "/var/lib/dnsnova"

[upstream]
primary = ["https://1.1.1.1/dns-query"]

[cache]
size = 50000

[cluster]
role = "primary"
listen = "10.0.0.1:7001"

[anycast]
enabled = true
announce = ["birdc", "enable", "anycast"]
withdraw = ["birdc", "disable", "anycast"]
`

const followerSrc = `[server]
listen = ["192.0.2.9:53", "203.0.113.53:53"]

[cluster]
role = "follower"
name = "fra-1"
primary = "10.0.0.1:7001"
`

// A follower gets the primary's settings, its own on top, and never the
// primary's [cluster] or [anycast].
func TestMerge(t *testing.T) {
	merged, keys, err := Merge([]byte(primarySrc), []byte(followerSrc))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, _, err := Load(merged)
	if err != nil {
		t.Fatalf("merged configuration does not load: %v\n%s", err, merged)
	}
	if !slices.Equal(cfg.Server.Listen, []string{"192.0.2.9:53", "203.0.113.53:53"}) {
		t.Errorf("listen = %v: the follower's own setting must win", cfg.Server.Listen)
	}
	if cfg.Cache.Size != 50000 || len(cfg.Upstream.Primary) != 1 || cfg.Server.Mode != "public" {
		t.Errorf("shared settings lost: cache %d, upstreams %v, mode %q", cfg.Cache.Size, cfg.Upstream.Primary, cfg.Server.Mode)
	}
	if cfg.Cluster.Role != "follower" || cfg.Cluster.Name != "fra-1" || cfg.Cluster.Listen != "" {
		t.Errorf("cluster = %+v: the follower's own, not the primary's", cfg.Cluster)
	}
	if cfg.Anycast.Enabled || len(cfg.Anycast.Announce) != 0 {
		t.Errorf("the primary's anycast commands reached a follower: %+v", cfg.Anycast)
	}
	want := []string{"server.listen"}
	if !slices.Equal(keys, want) {
		t.Errorf("overrides %v, want %v", keys, want)
	}
	if strings.Contains(string(merged), "birdc") {
		t.Error("anycast commands in the merged file")
	}
	// comments and order of the shared file are kept
	if !strings.HasPrefix(string(merged), "# the fleet's settings") {
		t.Errorf("merged file does not start with the shared one:\n%s", merged)
	}
}

func TestIsFollower(t *testing.T) {
	for src, want := range map[string]bool{
		followerSrc:                     true,
		primarySrc:                      false,
		"[server]\nmode = \"public\"\n": false,
		"[cluster]\nrole = 1\n":         false,
	} {
		if got, err := IsFollower([]byte(src)); err != nil || got != want {
			t.Errorf("IsFollower(%q) = %v, %v", src[:20], got, err)
		}
	}
	if _, err := IsFollower([]byte("[[x")); err == nil {
		t.Error("broken TOML accepted")
	}
}

func TestValidateCluster(t *testing.T) {
	base := "[server]\nmode = \"public\"\nlisten = [\"127.0.0.1:53\"]\n[upstream]\nprimary = [\"1.1.1.1\"]\n"
	for extra, wantErr := range map[string]string{
		"[cluster]\nrole = \"primary\"\nlisten = \"10.0.0.1:7001\"\n":         "",
		"[cluster]\nrole = \"follower\"\nprimary = \"10.0.0.1:7001\"\n":       "",
		"[cluster]\nrole = \"primary\"\n":                                     "cluster.listen",
		"[cluster]\nrole = \"follower\"\n":                                    "cluster.primary",
		"[cluster]\nrole = \"follower\"\nprimary = \"10.0.0.1\"\n":            "cluster.primary",
		"[cluster]\nrole = \"leader\"\n":                                      "cluster.role",
		"[cluster]\ninterval = \"100ms\"\n":                                   "cluster.interval",
		"[anycast]\nenabled = true\n":                                         "anycast.announce",
		"[anycast]\nenabled = true\nannounce = [\"true\"]\n":                  "anycast.withdraw",
		"[anycast]\nenabled = true\nannounce = [\"a\"]\nwithdraw = [\"b\"]\n": "",
		"[anycast]\nfall = 0\n":                                               "anycast.fall",
	} {
		_, _, _, err := Load([]byte(base + extra))
		switch {
		case wantErr == "" && err != nil:
			t.Errorf("%q: %v", extra, err)
		case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
			t.Errorf("%q: error %v, want one about %s", extra, err, wantErr)
		}
	}
}

func TestNegativeTrustAnchors(t *testing.T) {
	base := "[server]\nmode = \"public\"\nlisten = [\"127.0.0.1:53\"]\n[upstream]\nprimary = [\"1.1.1.1\"]\n[recursion]\nenabled = true\nnegative_trust_anchors = "
	cfg, _, warns, err := Load([]byte(base + "[\"broken.example\", \"Other.Example.\"]\n"))
	if err != nil || len(cfg.Recursion.NegativeTrustAnchors) != 2 {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(warns, " "), "not validated") {
		t.Errorf("no warning about unvalidated domains: %v", warns)
	}
	for _, bad := range []string{`["com"]`, `["."]`, `["bad domain.example"]`, `[""]`} {
		if _, _, _, err := Load([]byte(base + bad + "\n")); err == nil || !strings.Contains(err.Error(), "negative_trust_anchors") {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
}

func TestValidateAlerts(t *testing.T) {
	base := "[server]\nmode = \"public\"\nlisten = [\"127.0.0.1:53\"]\n[upstream]\nprimary = [\"1.1.1.1\"]\n"
	cfg, _, _, err := Load([]byte(base))
	if err != nil || cfg.Alerts != DefaultAlerts || cfg.Alerts.Enabled {
		t.Fatalf("defaults: %+v %v", cfg.Alerts, err)
	}
	for extra, wantErr := range map[string]string{
		"[alerts]\nenabled = true\nservfail_ratio = 0.1\nlatency_p95 = \"1s\"\nrepeat = \"0s\"\n": "",
		"[alerts]\nservfail_ratio = 0\nlatency_p95 = \"0s\"\ncert_warn_days = 0\n":                "",
		"[alerts]\nrepeat = \"1m\"\n":                            "alerts.repeat",
		"[alerts]\nservfail_ratio = 5\n":                         "alerts.servfail_ratio",
		"[alerts]\nlatency_p95 = \"30s\"\n":                      "alerts.latency_p95",
		"[alerts]\nupstream_down_for = \"-1s\"\n":                "alerts.upstream_down_for",
		"[alerts]\ndnssec_failures = -1\n":                       "alerts.dnssec_failures",
		"[alerts]\ncert_warn_days = 3\ncert_critical_days = 7\n": "alerts.cert_critical_days",
		"[alerts]\nwebhook = \"https://example.com/hook\"\n":     "alerts.webhook",
	} {
		_, _, _, err := Load([]byte(base + extra))
		switch {
		case wantErr == "" && err != nil:
			t.Errorf("%q: %v", extra, err)
		case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
			t.Errorf("%q: error %v, want one about %s", extra, err, wantErr)
		}
	}
}

func TestValidateClientPath(t *testing.T) {
	base := "[server]\nmode = \"public\"\nlisten = [\"127.0.0.1:53\"]\n[doh]\nlisten = \"127.0.0.1:8053\"\n[recursion]\nenabled = true\n"
	for extra, wantErr := range map[string]string{
		"[ecs]\nclient_path = \"/ecs-k3v9q2m8x7w4r1t6y5u0p2z8\"\n": "",
		"[ecs]\nclient_path = \"/short\"\n":                        "ecs.client_path",
		"[ecs]\nclient_path = \"ecs-k3v9q2m8x7w4r1t6y5u0p2z8\"\n":  "ecs.client_path",
		"[ecs]\nclient_path = \"/ecs k3v9q2m8x7w4r1t6y5u0p2z8\"\n": "ecs.client_path",
	} {
		_, _, _, err := Load([]byte(base + extra))
		switch {
		case wantErr == "" && err != nil:
			t.Errorf("%q: %v", extra, err)
		case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
			t.Errorf("%q: error %v, want one about %s", extra, err, wantErr)
		}
	}
	// without recursion, or without DoH
	noRec := "[server]\nmode = \"public\"\nlisten = [\"127.0.0.1:53\"]\n[upstream]\nprimary = [\"1.1.1.1\"]\n[doh]\nlisten = \"127.0.0.1:8053\"\n[ecs]\nclient_path = \"/ecs-k3v9q2m8x7w4r1t6y5u0p2z8\"\n"
	if _, _, _, err := Load([]byte(noRec)); err == nil || !strings.Contains(err.Error(), "recursion") {
		t.Errorf("without recursion: %v", err)
	}
	noDoH := "[server]\nmode = \"public\"\nlisten = [\"127.0.0.1:53\"]\n[recursion]\nenabled = true\n[ecs]\nclient_path = \"/ecs-k3v9q2m8x7w4r1t6y5u0p2z8\"\n"
	if _, _, _, err := Load([]byte(noDoH)); err == nil || !strings.Contains(err.Error(), "DNS over HTTPS") {
		t.Errorf("without DoH: %v", err)
	}
}
