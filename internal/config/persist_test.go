package config

import (
	"strings"
	"testing"
)

// cache.persist: "auto" (the default) keeps the cache for a public server
// and not for a home or office one; "on"/"off" and true/false override.
func TestPersistCache(t *testing.T) {
	base := map[string]string{
		"public":  "[server]\nmode = \"public\"\nlisten = [\"127.0.0.1:53\"]\n[upstream]\nprimary = [\"1.1.1.1\"]\n",
		"private": "[server]\nmode = \"private\"\nlisten = [\"127.0.0.1:53\"]\n[access]\nallow = [\"192.168.0.0/16\"]\n[upstream]\nprimary = [\"1.1.1.1\"]\n",
	}
	for _, c := range []struct {
		mode, value string
		want        bool
	}{
		{"public", "", true}, {"private", "", false},
		{"public", `"auto"`, true}, {"private", `"auto"`, false},
		{"public", `"off"`, false}, {"private", `"on"`, true},
		{"public", "false", false}, {"private", "true", true},
	} {
		src := base[c.mode]
		if c.value != "" {
			src += "[cache]\npersist = " + c.value + "\n"
		}
		cfg, _, _, err := Load([]byte(src))
		if err != nil {
			t.Fatalf("%s %s: %v", c.mode, c.value, err)
		}
		if got := cfg.PersistCache(); got != c.want {
			t.Errorf("%s mode, persist = %s: %v, want %v", c.mode, c.value, got, c.want)
		}
	}
	for _, bad := range []string{`"yes"`, "1", `""`} {
		if _, _, _, err := Load([]byte(base["public"] + "[cache]\npersist = " + bad + "\n")); err == nil || !strings.Contains(err.Error(), "auto") {
			t.Errorf("persist = %s accepted (%v)", bad, err)
		}
	}
}
