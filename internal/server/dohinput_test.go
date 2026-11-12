package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The checks on a DoH POST happen before any lookup, so a bare Server will do.
func TestDoHPostInputChecks(t *testing.T) {
	s := &Server{}
	post := func(ct string, body []byte) int {
		r := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(body))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		w := httptest.NewRecorder()
		s.handleDoH(w, r)
		return w.Code
	}
	short := make([]byte, 5) // below the header length: 400 once the type is accepted
	for _, c := range []struct {
		ct   string
		body []byte
		want int
	}{
		{"application/dns-messageXYZ", short, http.StatusUnsupportedMediaType},
		{"application/dns-message-foo", short, http.StatusUnsupportedMediaType},
		{"text/plain", short, http.StatusUnsupportedMediaType},
		{"", short, http.StatusUnsupportedMediaType},
		{"application/dns-message", make([]byte, 65536), http.StatusRequestEntityTooLarge},
		{"application/dns-message", make([]byte, 1<<20), http.StatusRequestEntityTooLarge},
		{"application/dns-message", short, http.StatusBadRequest},
		{"Application/DNS-Message", short, http.StatusBadRequest},
		{"application/dns-message; charset=binary", short, http.StatusBadRequest},
	} {
		if got := post(c.ct, c.body); got != c.want {
			t.Errorf("Content-Type %q, %d bytes: got %d, want %d", c.ct, len(c.body), got, c.want)
		}
	}
}
