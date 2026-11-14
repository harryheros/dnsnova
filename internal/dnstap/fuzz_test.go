package dnstap

import (
	"bytes"
	"testing"
)

// FuzzReadControl: whatever a collector answers in the handshake, reading
// it fails cleanly or gives a type and content type, never a panic.
func FuzzReadControl(f *testing.F) {
	var b bytes.Buffer
	writeControl(&b, ctrlAccept, ContentType)
	f.Add(b.Bytes())
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, in []byte) {
		readControl(bytes.NewReader(in))
	})
}
