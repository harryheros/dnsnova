package admin

import "strings"

// diffLine is one line of a change preview: Op is " " (unchanged context),
// "-" (removed) or "+" (added). Old and New are 1-based line numbers in the
// old and new file (0 where the line does not exist on that side). Lines more
// than two away from a change are left out; a jump in the line numbers marks
// the gap.
type diffLine struct {
	Op   string `json:"op"`
	Old  int    `json:"old,omitempty"`
	New  int    `json:"new,omitempty"`
	Text string `json:"text"`
}

const diffContext = 2

func splitLines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lineDiff compares two files line by line (longest common subsequence).
func lineDiff(oldSrc, newSrc []byte) []diffLine {
	a, b := splitLines(oldSrc), splitLines(newSrc)
	// trim the common head and tail: edits usually touch a few lines
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]

	var ops []diffLine
	for i := 0; i < pre; i++ {
		ops = append(ops, diffLine{Op: " ", Old: i + 1, New: i + 1, Text: a[i]})
	}
	if len(ma)*len(mb) > 4_000_000 { // too large to align: replace the block
		for i, l := range ma {
			ops = append(ops, diffLine{Op: "-", Old: pre + i + 1, Text: l})
		}
		for j, l := range mb {
			ops = append(ops, diffLine{Op: "+", New: pre + j + 1, Text: l})
		}
	} else {
		// lcs[i][j] = length of the LCS of ma[i:] and mb[j:]
		lcs := make([][]int32, len(ma)+1)
		for i := range lcs {
			lcs[i] = make([]int32, len(mb)+1)
		}
		for i := len(ma) - 1; i >= 0; i-- {
			for j := len(mb) - 1; j >= 0; j-- {
				if ma[i] == mb[j] {
					lcs[i][j] = lcs[i+1][j+1] + 1
				} else {
					lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
				}
			}
		}
		i, j := 0, 0
		for i < len(ma) || j < len(mb) {
			switch {
			case i < len(ma) && j < len(mb) && ma[i] == mb[j]:
				ops = append(ops, diffLine{Op: " ", Old: pre + i + 1, New: pre + j + 1, Text: ma[i]})
				i++
				j++
			case i < len(ma) && (j == len(mb) || lcs[i+1][j] >= lcs[i][j+1]):
				ops = append(ops, diffLine{Op: "-", Old: pre + i + 1, Text: ma[i]}) // removals first
				i++
			default:
				ops = append(ops, diffLine{Op: "+", New: pre + j + 1, Text: mb[j]})
				j++
			}
		}
	}
	for k := 0; k < suf; k++ {
		ops = append(ops, diffLine{Op: " ", Old: len(a) - suf + k + 1, New: len(b) - suf + k + 1, Text: a[len(a)-suf+k]})
	}

	// keep changes and the context around them
	keep := make([]bool, len(ops))
	for k, op := range ops {
		if op.Op != " " {
			for d := -diffContext; d <= diffContext; d++ {
				if k+d >= 0 && k+d < len(ops) {
					keep[k+d] = true
				}
			}
		}
	}
	out := []diffLine{}
	for k, op := range ops {
		if keep[k] {
			out = append(out, op)
		}
	}
	return out
}
