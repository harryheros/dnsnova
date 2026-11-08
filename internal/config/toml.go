package config

// A strict TOML subset parser that remembers where every value sits in the
// source, so the admin API can change one setting by rewriting only the bytes
// of that value. Comments, blank lines and ordering are preserved.
//
// Supported: [table] and [dotted.table] headers, bare keys, basic "strings"
// and literal 'strings', integers, floats, booleans, and arrays of one of
// those types (possibly spanning lines, with comments and a trailing comma).
// Anything else (inline tables, arrays of tables, dates, quoted or dotted
// keys, multi-line strings) is rejected with the line it appears on.

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind is the type of a Value.
type Kind int

const (
	String Kind = iota + 1
	Int
	Float
	Bool
	Array
)

func (k Kind) String() string {
	switch k {
	case String:
		return "string"
	case Int:
		return "integer"
	case Float:
		return "float"
	case Bool:
		return "boolean"
	case Array:
		return "array"
	}
	return "unknown"
}

// Value is a parsed TOML value.
type Value struct {
	Kind  Kind
	Str   string
	Int   int64
	Float float64
	Bool  bool
	Arr   []Value
	Line  int
}

// Entry is one key = value pair and its position in the source.
type Entry struct {
	Table    string // "" for the root table
	Key      string
	Value    Value
	Line     int // line of the key
	EndLine  int // line where the value ends
	ValStart int // byte offsets of the value in the source
	ValEnd   int
	LineEnd  int // byte offset just after the newline ending EndLine (or len(src))
}

// Table is a [table] header and its position.
type Table struct {
	Name    string
	Line    int
	LineEnd int // byte offset just after the header line
	last    int // byte offset just after the last entry line of this table
}

// Document is a parsed file.
type Document struct {
	Src     []byte
	Entries []*Entry
	Tables  []*Table
	index   map[string]*Entry
	tables  map[string]*Table
}

// ParseError is a syntax error with its line.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

func entryKey(table, key string) string { return table + "\x00" + key }

// Lookup returns the entry for table.key, or nil.
func (d *Document) Lookup(table, key string) *Entry { return d.index[entryKey(table, key)] }

// HasTable reports whether a [table] header exists.
func (d *Document) HasTable(name string) bool { _, ok := d.tables[name]; return ok }

type parser struct {
	src  []byte
	pos  int
	line int
}

// Parse parses src. It never panics on malformed input.
func Parse(src []byte) (*Document, error) {
	if !utf8.Valid(src) {
		return nil, &ParseError{Line: 1, Msg: "file is not valid UTF-8"}
	}
	p := &parser{src: src, line: 1}
	d := &Document{Src: src, index: map[string]*Entry{}, tables: map[string]*Table{}}
	root := &Table{Name: "", Line: 0}
	d.tables[""] = root
	cur := root
	for {
		p.skipSpaceAndNewlines()
		if p.pos >= len(p.src) {
			break
		}
		c := p.src[p.pos]
		switch {
		case c == '[':
			t, err := p.tableHeader()
			if err != nil {
				return nil, err
			}
			if _, dup := d.tables[t.Name]; dup {
				return nil, &ParseError{Line: t.Line, Msg: fmt.Sprintf("table [%s] is defined twice", t.Name)}
			}
			if e := d.conflictingKey(t.Name); e != nil {
				return nil, &ParseError{Line: t.Line, Msg: fmt.Sprintf("table [%s] conflicts with key %q on line %d", t.Name, e.Key, e.Line)}
			}
			t.last = t.LineEnd
			d.tables[t.Name] = t
			d.Tables = append(d.Tables, t)
			cur = t
		case isBareKeyChar(c):
			e, err := p.keyValue(cur.Name)
			if err != nil {
				return nil, err
			}
			k := entryKey(e.Table, e.Key)
			if prev, dup := d.index[k]; dup {
				return nil, &ParseError{Line: e.Line, Msg: fmt.Sprintf("key %q is already defined on line %d", e.Key, prev.Line)}
			}
			sub := e.Key
			if e.Table != "" {
				sub = e.Table + "." + e.Key
			}
			if t, ok := d.tables[sub]; ok {
				return nil, &ParseError{Line: e.Line, Msg: fmt.Sprintf("key %q conflicts with table [%s] on line %d", e.Key, sub, t.Line)}
			}
			d.index[k] = e
			d.Entries = append(d.Entries, e)
			cur.last = e.LineEnd
		case c == '"' || c == '\'':
			return nil, p.errf("quoted keys are not supported; use a bare key")
		default:
			return nil, p.errf("unexpected character %q", c)
		}
	}
	return d, nil
}

// conflictingKey finds a key that a new table name would shadow, e.g. key
// "doh" in [server] versus table [server.doh].
func (d *Document) conflictingKey(table string) *Entry {
	i := strings.LastIndexByte(table, '.')
	parent, key := "", table
	if i >= 0 {
		parent, key = table[:i], table[i+1:]
	}
	return d.index[entryKey(parent, key)]
}

func (p *parser) errf(format string, a ...any) error {
	return &ParseError{Line: p.line, Msg: fmt.Sprintf(format, a...)}
}

func isBareKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// skipSpace skips spaces and tabs on the current line.
func (p *parser) skipSpace() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
}

// skipComment skips a comment up to (not including) the newline.
func (p *parser) skipComment() error {
	if p.pos < len(p.src) && p.src[p.pos] == '#' {
		for p.pos < len(p.src) && p.src[p.pos] != '\n' {
			c := p.src[p.pos]
			if c < 0x20 && c != '\t' && c != '\r' || c == 0x7f {
				return p.errf("control character in comment")
			}
			p.pos++
		}
	}
	return nil
}

// skipSpaceAndNewlines skips whitespace, comments and newlines.
func (p *parser) skipSpaceAndNewlines() {
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\r':
			p.pos++
		case '\n':
			p.pos++
			p.line++
		case '#':
			if p.skipComment() != nil {
				return // reported when the main loop hits the bad byte
			}
		default:
			return
		}
	}
}

// endOfLine expects only whitespace and an optional comment until the newline
// and returns the offset just after it.
func (p *parser) endOfLine() (int, error) {
	p.skipSpace()
	if err := p.skipComment(); err != nil {
		return 0, err
	}
	if p.pos < len(p.src) && p.src[p.pos] == '\r' {
		p.pos++
	}
	if p.pos >= len(p.src) {
		return p.pos, nil
	}
	if p.src[p.pos] != '\n' {
		return 0, p.errf("unexpected %q after value; put each setting on its own line", p.src[p.pos])
	}
	p.pos++
	p.line++
	return p.pos, nil
}

func (p *parser) bareKey() (string, error) {
	start := p.pos
	for p.pos < len(p.src) && isBareKeyChar(p.src[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", p.errf("expected a name")
	}
	return string(p.src[start:p.pos]), nil
}

func (p *parser) tableHeader() (*Table, error) {
	t := &Table{Line: p.line}
	p.pos++ // [
	if p.pos < len(p.src) && p.src[p.pos] == '[' {
		return nil, p.errf("arrays of tables ([[...]]) are not supported")
	}
	var parts []string
	for {
		p.skipSpace()
		k, err := p.bareKey()
		if err != nil {
			return nil, err
		}
		parts = append(parts, k)
		p.skipSpace()
		if p.pos >= len(p.src) {
			return nil, p.errf("unterminated table header")
		}
		if p.src[p.pos] == '.' {
			p.pos++
			continue
		}
		if p.src[p.pos] == ']' {
			p.pos++
			break
		}
		return nil, p.errf("unexpected %q in table header", p.src[p.pos])
	}
	t.Name = strings.Join(parts, ".")
	end, err := p.endOfLine()
	if err != nil {
		return nil, err
	}
	t.LineEnd = end
	return t, nil
}

func (p *parser) keyValue(table string) (*Entry, error) {
	e := &Entry{Table: table, Line: p.line}
	k, err := p.bareKey()
	if err != nil {
		return nil, err
	}
	e.Key = k
	p.skipSpace()
	if p.pos < len(p.src) && p.src[p.pos] == '.' {
		return nil, p.errf("dotted keys are not supported; use a [table] header")
	}
	if p.pos >= len(p.src) || p.src[p.pos] != '=' {
		return nil, p.errf("expected '=' after %q", k)
	}
	p.pos++
	p.skipSpace()
	e.ValStart = p.pos
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	e.Value = v
	e.ValEnd = p.pos
	e.EndLine = p.line
	if e.LineEnd, err = p.endOfLine(); err != nil {
		return nil, err
	}
	return e, nil
}

func (p *parser) value(depth int) (Value, error) {
	if p.pos >= len(p.src) || p.src[p.pos] == '\n' || p.src[p.pos] == '#' {
		return Value{}, p.errf("missing value")
	}
	line := p.line
	c := p.src[p.pos]
	switch {
	case c == '"':
		if strings.HasPrefix(string(p.src[p.pos:min(p.pos+3, len(p.src))]), `"""`) {
			return Value{}, p.errf("multi-line strings are not supported")
		}
		s, err := p.basicString()
		return Value{Kind: String, Str: s, Line: line}, err
	case c == '\'':
		if strings.HasPrefix(string(p.src[p.pos:min(p.pos+3, len(p.src))]), `'''`) {
			return Value{}, p.errf("multi-line strings are not supported")
		}
		s, err := p.literalString()
		return Value{Kind: String, Str: s, Line: line}, err
	case c == '[':
		if depth > 0 {
			return Value{}, p.errf("nested arrays are not supported")
		}
		return p.array()
	case c == '{':
		return Value{}, p.errf("inline tables are not supported; use a [table] header")
	case c == 't' || c == 'f':
		w := p.word()
		switch w {
		case "true":
			return Value{Kind: Bool, Bool: true, Line: line}, nil
		case "false":
			return Value{Kind: Bool, Bool: false, Line: line}, nil
		}
		return Value{}, p.errf("invalid value %q (strings must be quoted)", w)
	case c == '+' || c == '-' || c >= '0' && c <= '9':
		return p.number()
	default:
		w := p.word()
		if w == "" {
			w = string(c)
		}
		return Value{}, p.errf("invalid value %q (strings must be quoted)", w)
	}
}

// word reads a run of characters that could form a bare value.
func (p *parser) word() string {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',' || c == ']' || c == '#' {
			break
		}
		p.pos++
	}
	return string(p.src[start:p.pos])
}

func (p *parser) number() (Value, error) {
	line := p.line
	w := p.word()
	if strings.ContainsAny(w, ":T") || strings.Count(w, "-") > 1 && !strings.ContainsAny(w, "eE") {
		return Value{}, p.errf("dates and times are not supported; use a quoted string like \"5s\"")
	}
	if !validUnderscores(w) {
		return Value{}, p.errf("invalid number %q", w)
	}
	clean := strings.ReplaceAll(w, "_", "")
	digits := strings.TrimLeft(clean, "+-")
	if strings.HasPrefix(digits, "0x") || strings.HasPrefix(digits, "0o") || strings.HasPrefix(digits, "0b") {
		return Value{}, p.errf("only decimal numbers are supported, got %q", w)
	}
	if strings.ContainsAny(clean, ".eE") {
		if digits == "inf" || digits == "nan" {
			return Value{}, p.errf("invalid number %q", w)
		}
		f, err := strconv.ParseFloat(clean, 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || strings.HasPrefix(digits, ".") || strings.HasSuffix(digits, ".") {
			return Value{}, p.errf("invalid number %q", w)
		}
		return Value{Kind: Float, Float: f, Line: line}, nil
	}
	if len(digits) > 1 && digits[0] == '0' {
		return Value{}, p.errf("leading zeros are not allowed in %q", w)
	}
	n, err := strconv.ParseInt(clean, 10, 64)
	if err != nil {
		if strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return Value{}, p.errf("invalid value %q (strings must be quoted)", w)
		}
		return Value{}, p.errf("invalid integer %q", w)
	}
	return Value{Kind: Int, Int: n, Line: line}, nil
}

// validUnderscores checks that every underscore sits between two digits.
func validUnderscores(w string) bool {
	for i := 0; i < len(w); i++ {
		if w[i] == '_' {
			if i == 0 || i == len(w)-1 || !isDigit(w[i-1]) || !isDigit(w[i+1]) {
				return false
			}
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *parser) basicString() (string, error) {
	p.pos++ // opening quote
	var sb strings.Builder
	for {
		if p.pos >= len(p.src) || p.src[p.pos] == '\n' {
			return "", p.errf("unterminated string")
		}
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			if p.pos+1 >= len(p.src) {
				return "", p.errf("unterminated string")
			}
			e := p.src[p.pos+1]
			p.pos += 2
			switch e {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case 'b':
				sb.WriteByte('\b')
			case 't':
				sb.WriteByte('\t')
			case 'n':
				sb.WriteByte('\n')
			case 'f':
				sb.WriteByte('\f')
			case 'r':
				sb.WriteByte('\r')
			case 'u', 'U':
				n := 4
				if e == 'U' {
					n = 8
				}
				if p.pos+n > len(p.src) {
					return "", p.errf("invalid unicode escape")
				}
				r, err := strconv.ParseUint(string(p.src[p.pos:p.pos+n]), 16, 32)
				if err != nil || !utf8.ValidRune(rune(r)) {
					return "", p.errf("invalid unicode escape")
				}
				sb.WriteRune(rune(r))
				p.pos += n
			default:
				return "", p.errf("invalid escape \\%c", e)
			}
		case c < 0x20 && c != '\t' || c == 0x7f:
			return "", p.errf("control character in string")
		default:
			sb.WriteByte(c)
			p.pos++
		}
	}
}

func (p *parser) literalString() (string, error) {
	p.pos++
	start := p.pos
	for {
		if p.pos >= len(p.src) || p.src[p.pos] == '\n' {
			return "", p.errf("unterminated string")
		}
		c := p.src[p.pos]
		if c == '\'' {
			s := string(p.src[start:p.pos])
			p.pos++
			return s, nil
		}
		if c < 0x20 && c != '\t' || c == 0x7f {
			return "", p.errf("control character in string")
		}
		p.pos++
	}
}

func (p *parser) array() (Value, error) {
	v := Value{Kind: Array, Line: p.line}
	p.pos++ // [
	for {
		p.skipSpaceAndNewlines()
		if p.pos >= len(p.src) {
			return Value{}, &ParseError{Line: v.Line, Msg: "unterminated array"}
		}
		if p.src[p.pos] == ']' {
			p.pos++
			return v, nil
		}
		item, err := p.value(1)
		if err != nil {
			return Value{}, err
		}
		if len(v.Arr) > 0 && v.Arr[0].Kind != item.Kind {
			return Value{}, &ParseError{Line: item.Line, Msg: fmt.Sprintf("array mixes %s and %s", v.Arr[0].Kind, item.Kind)}
		}
		v.Arr = append(v.Arr, item)
		p.skipSpaceAndNewlines()
		if p.pos >= len(p.src) {
			return Value{}, &ParseError{Line: v.Line, Msg: "unterminated array"}
		}
		switch p.src[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return Value{}, p.errf("expected ',' or ']' in array")
		}
	}
}

// ---- formatting (used when writing values back) ----

// Format renders v as TOML.
func Format(v Value) string {
	switch v.Kind {
	case String:
		return quote(v.Str)
	case Int:
		return strconv.FormatInt(v.Int, 10)
	case Float:
		s := strconv.FormatFloat(v.Float, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	case Bool:
		return strconv.FormatBool(v.Bool)
	case Array:
		items := make([]string, len(v.Arr))
		total := 2
		for i, it := range v.Arr {
			items[i] = Format(it)
			total += len(items[i]) + 2
		}
		if total <= 72 {
			return "[" + strings.Join(items, ", ") + "]"
		}
		return "[\n  " + strings.Join(items, ",\n  ") + ",\n]"
	}
	return `""`
}

func quote(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\t':
			sb.WriteString(`\t`)
		case '\r':
			sb.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&sb, `\u%04X`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

// Str, IntV, FloatV, BoolV and StrList are helpers for building values.
func Str(s string) Value     { return Value{Kind: String, Str: s} }
func IntV(n int64) Value     { return Value{Kind: Int, Int: n} }
func FloatV(f float64) Value { return Value{Kind: Float, Float: f} }
func BoolV(b bool) Value     { return Value{Kind: Bool, Bool: b} }
func StrList(ss []string) Value {
	v := Value{Kind: Array, Arr: []Value{}}
	for _, s := range ss {
		v.Arr = append(v.Arr, Str(s))
	}
	return v
}
