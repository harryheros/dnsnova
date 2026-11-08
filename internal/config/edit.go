package config

import (
	"bytes"
	"fmt"
	"strings"
)

// Set returns a copy of the document source with table.key set to v. An
// existing value is replaced in place (its trailing comment and every other
// line stay as they are); a new key goes after the last setting of its table;
// a missing table is appended at the end of the file. The result is parsed
// again before it is returned, so a successful Set always yields valid TOML.
func (d *Document) Set(table, key string, v Value) ([]byte, error) {
	if !validName(key) {
		return nil, fmt.Errorf("invalid key %q", key)
	}
	for _, part := range strings.Split(table, ".") {
		if table != "" && !validName(part) {
			return nil, fmt.Errorf("invalid table %q", table)
		}
	}
	val := Format(v)
	var out []byte
	if e := d.Lookup(table, key); e != nil {
		out = splice(d.Src, e.ValStart, e.ValEnd, val)
	} else if t, ok := d.tables[table]; ok {
		at := t.last // after the table's last setting (or its header line)
		line := key + " = " + val + "\n"
		prefix := ""
		if at > 0 && d.Src[at-1] != '\n' {
			prefix = "\n"
		}
		out = splice(d.Src, at, at, prefix+line)
	} else {
		var b bytes.Buffer
		b.Write(d.Src)
		if len(d.Src) > 0 && d.Src[len(d.Src)-1] != '\n' {
			b.WriteByte('\n')
		}
		if len(d.Src) > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "[%s]\n%s = %s\n", table, key, val)
		out = b.Bytes()
	}
	if _, err := Parse(out); err != nil {
		return nil, fmt.Errorf("internal error: edit produced invalid TOML: %w", err)
	}
	return out, nil
}

// Delete returns a copy of the source without table.key. Removing a key that
// does not exist is not an error.
func (d *Document) Delete(table, key string) ([]byte, error) {
	e := d.Lookup(table, key)
	if e == nil {
		return append([]byte(nil), d.Src...), nil
	}
	start := bytes.LastIndexByte(d.Src[:e.ValStart], '\n') + 1
	out := splice(d.Src, start, e.LineEnd, "")
	if _, err := Parse(out); err != nil {
		return nil, fmt.Errorf("internal error: edit produced invalid TOML: %w", err)
	}
	return out, nil
}

func splice(src []byte, from, to int, s string) []byte {
	out := make([]byte, 0, len(src)-(to-from)+len(s))
	out = append(out, src[:from]...)
	out = append(out, s...)
	out = append(out, src[to:]...)
	return out
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isBareKeyChar(s[i]) {
			return false
		}
	}
	return true
}
