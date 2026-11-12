package config

import (
	"slices"
	"testing"
)

// Any primary configuration and any follower file: merging never panics,
// never lets the primary's [cluster] or [anycast] through, and the
// follower's own settings win.
func FuzzMerge(f *testing.F) {
	f.Add([]byte(primarySrc), []byte(followerSrc))
	f.Add([]byte("[cluster]\nrole = \"primary\"\n"), []byte("[anycast]\nenabled = false\n"))
	f.Fuzz(func(t *testing.T, shared, local []byte) {
		merged, _, err := Merge(shared, local)
		if err != nil {
			return
		}
		md, err := Parse(merged)
		if err != nil {
			t.Fatalf("merged file does not parse: %v", err)
		}
		ld, _ := Parse(local)
		for _, e := range md.Entries {
			if slices.Contains(NodeLocalTables, e.Table) && ld.Lookup(e.Table, e.Key) == nil {
				t.Fatalf("%s.%s came from the primary", e.Table, e.Key)
			}
		}
		for _, e := range ld.Entries {
			got := md.Lookup(e.Table, e.Key)
			if got == nil || Format(got.Value) != Format(e.Value) {
				t.Fatalf("local %s.%s = %s lost", e.Table, e.Key, Format(e.Value))
			}
		}
	})
}
