// Package docs holds the documentation; this test keeps the README and the
// documents' links working and the README's header and footer in shape.
package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

const toolkitLine = "Part of the [Nova infrastructure toolkit](https://github.com/harryheros)."

var (
	linkRE    = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	imgRE     = regexp.MustCompile(`<img [^>]*src="([^"]+)"`)
	mdLinkRE  = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	schemeRE  = regexp.MustCompile(`^[a-z]+:`)
	headingRE = regexp.MustCompile(`^#{1,6} `)
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// slug is GitHub's anchor for a heading.
func slug(heading string) string {
	s := mdLinkRE.ReplaceAllString(heading, "$1")
	s = strings.ToLower(strings.NewReplacer("`", "", "*", "").Replace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// withoutCode drops fenced code blocks, whose text is not Markdown.
func withoutCode(text string) []string {
	var out []string
	inCode := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
			continue
		}
		if !inCode {
			out = append(out, line)
		}
	}
	return out
}

func anchors(text string) map[string]bool {
	out := map[string]bool{}
	for _, line := range withoutCode(text) {
		if headingRE.MatchString(line) {
			out[slug(strings.TrimSpace(strings.TrimLeft(line, "#")))] = true
		}
	}
	return out
}

func TestReadmeHeaderAndFooter(t *testing.T) {
	readme := readFile(t, "../README.md")
	if !strings.HasPrefix(readme, "<div align=\"center\">\n\n# DNSNova\n") {
		t.Error("README must open with the centered DNSNova header")
	}
	if !strings.Contains(readme, "img.shields.io/github/v/release/harryheros/dnsnova") ||
		strings.Contains(readme, "img.shields.io/badge/version-") {
		t.Error("the version badge must follow the latest release, not be written by hand")
	}
	if !strings.Contains(readme, "https://novaod.com/licensing") {
		t.Error("the License section must say where to ask for a commercial license")
	}
	lines := strings.Split(strings.TrimRight(readme, "\n"), "\n")
	if last := lines[len(lines)-1]; last != toolkitLine {
		t.Errorf("README must end with the toolkit line, ends with %q", last)
	}
}

func TestDocumentLinksResolve(t *testing.T) {
	docs, err := filepath.Glob("*.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range append([]string{"../README.md"}, docs...) {
		text := readFile(t, doc)
		body := strings.Join(withoutCode(text), "\n")
		var targets []string
		for _, m := range linkRE.FindAllStringSubmatch(body, -1) {
			targets = append(targets, m[1])
		}
		for _, m := range imgRE.FindAllStringSubmatch(body, -1) {
			targets = append(targets, m[1])
		}
		for _, target := range targets {
			if schemeRE.MatchString(target) {
				continue
			}
			file, frag, _ := strings.Cut(target, "#")
			dest := doc
			if file != "" {
				dest = filepath.Join(filepath.Dir(doc), file)
			}
			if _, err := os.Stat(dest); err != nil {
				t.Errorf("%s: link %s: %v", doc, target, err)
				continue
			}
			if frag != "" && strings.HasSuffix(dest, ".md") && !anchors(readFile(t, dest))[frag] {
				t.Errorf("%s: link %s: no heading with that anchor", doc, target)
			}
		}
	}
}
