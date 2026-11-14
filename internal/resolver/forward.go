package resolver

import "strings"

// Forwards sends the names under some domains to servers of their own
// (local.forward): an office's Active Directory, a router that knows the
// names of the devices on its network. Those names are never sent to the
// upstreams or resolved from the root.
type Forwards struct {
	zones map[string]Exchanger // wire-format domain, lowercase
	// Spec identifies the configuration: when it changes, cached answers
	// for the old servers are dropped.
	Spec string
}

// NewForwards returns an empty set; spec identifies its configuration.
func NewForwards(spec string) *Forwards {
	return &Forwards{zones: map[string]Exchanger{}, Spec: spec}
}

// Add sends the names under domain (dotted, such as "corp.example") to x.
func (f *Forwards) Add(domain string, x Exchanger) {
	f.zones[toWire(strings.ToLower(strings.TrimSuffix(domain, ".")))] = x
}

// match returns where the names under the closest listed domain go, or nil.
// name is in wire format; case does not matter.
func (f *Forwards) match(name string) Exchanger {
	if f == nil || len(f.zones) == 0 {
		return nil
	}
	name = lowerWire(name)
	for i := 0; i < len(name) && name[i] != 0; i += 1 + int(name[i]) {
		if x, ok := f.zones[name[i:]]; ok {
			return x
		}
	}
	return nil
}

// lowerWire lowercases a wire-format name (length bytes are below 'A').
func lowerWire(name string) string {
	for i := 0; i < len(name); i++ {
		if c := name[i]; c >= 'A' && c <= 'Z' {
			b := []byte(name)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return name
}

func (f *Forwards) spec() string {
	if f == nil {
		return ""
	}
	return f.Spec
}
