package config

import (
	"errors"
	"strings"
	"testing"
)

const sample = `# dnsnova test file
[server]
mode = "public"   # keep this comment
listen = [
  "127.0.0.1:53", # first
  "[::1]:53",
]

[upstream]
primary = ['https://1.1.1.1/dns-query']
timeout = "3s"
parallel = 2
ratio = 1.5
enabled = true

[server.doh]
path = "/dns-query"
`

func TestParseValues(t *testing.T) {
	d, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if e := d.Lookup("server", "mode"); e == nil || e.Value.Str != "public" || e.Line != 3 {
		t.Fatalf("mode: %+v", e)
	}
	l := d.Lookup("server", "listen")
	if l == nil || len(l.Value.Arr) != 2 || l.Value.Arr[1].Str != "[::1]:53" || l.Line != 4 || l.EndLine != 7 {
		t.Fatalf("listen: %+v", l)
	}
	if e := d.Lookup("upstream", "primary"); e.Value.Arr[0].Str != "https://1.1.1.1/dns-query" {
		t.Fatal("literal string")
	}
	if e := d.Lookup("upstream", "parallel"); e.Value.Kind != Int || e.Value.Int != 2 {
		t.Fatal("int")
	}
	if e := d.Lookup("upstream", "ratio"); e.Value.Kind != Float || e.Value.Float != 1.5 {
		t.Fatal("float")
	}
	if e := d.Lookup("upstream", "enabled"); !e.Value.Bool {
		t.Fatal("bool")
	}
	if !d.HasTable("server.doh") {
		t.Fatal("dotted table")
	}
}

func TestParseErrorsCarryLines(t *testing.T) {
	cases := []struct {
		src  string
		line int
		want string
	}{
		{"[a]\nx = 1\nx = 2\n", 3, "already defined"},
		{"[a]\n[a]\n", 2, "defined twice"},
		{"[a]\nx = {y = 1}\n", 2, "inline tables"},
		{"[[a]]\n", 1, "arrays of tables"},
		{"[a]\nx = 5s\n", 2, "must be quoted"},
		{"[a]\nx = \"open\n", 2, "unterminated"},
		{"[a]\nx = [1, \"a\"]\n", 2, "mixes"},
		{"[a]\nx = 1979-05-27\n", 2, "dates"},
		{"[a]\nx = 1 y = 2\n", 2, "own line"},
		{"[a]\na.b = 1\n", 2, "dotted keys"},
		{"[a]\n\"k\" = 1\n", 2, "quoted keys"},
		{"[a]\nx = 012\n", 2, "leading zeros"},
		{"[a]\nx = \"\"\"long\"\"\"\n", 2, "multi-line"},
		{"[a]\nx = [\n1,\n2\n", 2, "unterminated array"},
		{"[a]\nb = 1\n[a.b]\n", 3, "conflicts"},
		{"[a]\nx = 0x10\n", 2, "decimal"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.src))
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Errorf("%q: want ParseError, got %v", c.src, err)
			continue
		}
		if pe.Line != c.line || !strings.Contains(pe.Msg, c.want) {
			t.Errorf("%q: got line %d %q, want line %d containing %q", c.src, pe.Line, pe.Msg, c.line, c.want)
		}
	}
}

func TestSetKeepsCommentsAndLayout(t *testing.T) {
	d, _ := Parse([]byte(sample))
	out, err := d.Set("server", "mode", Str("private"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(sample, `mode = "public"   # keep this comment`, `mode = "private"   # keep this comment`, 1)
	if string(out) != want {
		t.Fatalf("only the value should change:\n%s", out)
	}

	// replace a multi-line array: following lines stay untouched
	d, _ = Parse([]byte(sample))
	out, err = d.Set("server", "listen", StrList([]string{"10.0.0.1:53"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "listen = [\"10.0.0.1:53\"]\n\n[upstream]") {
		t.Fatalf("array replace:\n%s", out)
	}

	// add a key to an existing table: goes after its last setting
	d, _ = Parse([]byte(sample))
	out, err = d.Set("upstream", "fallback", StrList([]string{"tls://9.9.9.9"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "enabled = true\nfallback = [\"tls://9.9.9.9\"]\n\n[server.doh]") {
		t.Fatalf("insert:\n%s", out)
	}

	// add a key to a new table: appended at the end
	d, _ = Parse([]byte(sample))
	out, err = d.Set("cache", "size", IntV(5000))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(out), "path = \"/dns-query\"\n\n[cache]\nsize = 5000\n") {
		t.Fatalf("new table:\n%s", out)
	}

	// delete
	d, _ = Parse([]byte(sample))
	out, err = d.Delete("upstream", "ratio")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "ratio") || !strings.Contains(string(out), "parallel = 2\nenabled = true") {
		t.Fatalf("delete:\n%s", out)
	}
}

func TestFormatRoundTrip(t *testing.T) {
	vals := []Value{
		Str(`a "quoted" \ value` + "\t\n"), IntV(-42), FloatV(2), FloatV(0.25), BoolV(false),
		StrList([]string{"one", "two"}),
		StrList([]string{strings.Repeat("x", 40), strings.Repeat("y", 40)}), // multi-line form
	}
	for _, v := range vals {
		src := "[t]\nk = " + Format(v) + "\n"
		d, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if Format(d.Lookup("t", "k").Value) != Format(v) {
			t.Fatalf("round trip changed %s", src)
		}
	}
}

// FuzzParse: the parser must never panic, and any document it accepts must
// survive rewriting each of its values in place.
func FuzzParse(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte("[a]\nx = [1,2,3,]\ny = 'z'\n"))
	f.Add([]byte("x = \"\\u00e9\"\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		d, err := Parse(src)
		if err != nil {
			return
		}
		for _, e := range d.Entries {
			out, err := d.Set(e.Table, e.Key, e.Value)
			if err != nil {
				t.Fatalf("Set %s.%s: %v", e.Table, e.Key, err)
			}
			d2, err := Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			if Format(d2.Lookup(e.Table, e.Key).Value) != Format(e.Value) {
				t.Fatalf("value changed for %s.%s", e.Table, e.Key)
			}
		}
		Load(src)
	})
}
