package tlsmgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A key dnsnova may not read (certbot's are root's only) says what to do.
func TestUnreadableKeyFileSaysWhy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	os.WriteFile(cert, []byte("x"), 0o644)
	os.WriteFile(key, []byte("x"), 0o000)
	m := NewManager(dir, nil)
	m.set.CertFile, m.set.KeyFile = cert, key
	err := m.loadFiles(true)
	if err == nil || !strings.Contains(err.Error(), "cannot read it") {
		t.Fatalf("got %v", err)
	}
}
