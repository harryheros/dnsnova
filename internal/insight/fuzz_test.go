package insight

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// FuzzArchiveLine: any line of a query records file (they can be edited or
// damaged on disk) parses or is skipped, never a panic, and searching it
// works either way.
func FuzzArchiveLine(f *testing.F) {
	f.Add(strings.TrimSuffix(formatLine(Query{Time: time.Unix(1_800_000_000, 0), Client: "10.0.0.1", Proto: "udp", Name: "a.example", Type: "A", Rcode: "NOERROR", Source: "cache", MS: 1.5, Group: "lab"}), "\n"))
	f.Add("2026-11-14T10:00:00.000Z\tx\tudp\t\\009\tA\tNOERROR\tcache\tNaN\t1\t")
	f.Fuzz(func(t *testing.T, line string) {
		if strings.Contains(line, "\n") {
			return // the scanner hands over lines without their newline
		}
		if q, ok := parseLine(line); ok {
			ArchiveQuery{Name: "a", Client: "1", Group: "g", Result: "blocked"}.match(q)
			if strings.Count(formatLine(q), "\n") != 1 {
				t.Fatalf("a record from %q writes more than one line", line)
			}
		}
	})
}

// FuzzNODLoad: a damaged state file is refused or loaded, never a panic,
// and a refused one leaves the detector as it was.
func FuzzNODLoad(f *testing.F) {
	n := NewNOD(0)
	var good bytes.Buffer
	n.Save(&good)
	f.Add(good.Bytes()[:200])
	f.Add([]byte(nodMagic))
	f.Fuzz(func(t *testing.T, b []byte) {
		m := NewNOD(0)
		m.Observe("seen.example", "", "A", "")
		if err := m.Load(bytes.NewReader(b)); err != nil && m.Observe("seen.example", "", "A", "") {
			t.Fatal("a refused file changed the state")
		}
	})
}
