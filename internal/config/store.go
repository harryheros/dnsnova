package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HistoryLimit is how many previous versions of the file are kept.
const HistoryLimit = 10

// ErrConflict means the file changed on disk since the caller last read it.
var ErrConflict = errors.New("the configuration file was changed by someone else; reload it and try again")

// Store reads and writes the configuration file. Writes are atomic (temporary
// file + rename), keep the previous versions in a history directory and are
// refused when the file changed since the caller read it.
type Store struct {
	Path       string
	HistoryDir string

	mu      sync.Mutex
	hash    string
	modTime time.Time
	size    int64
}

// NewStore returns a store for path, keeping history in <dir>/history.
func NewStore(path string) *Store {
	return &Store{Path: path, HistoryDir: filepath.Join(filepath.Dir(path), "history")}
}

// Snapshot is one loaded version of the file.
type Snapshot struct {
	Config   *Config
	Doc      *Document
	Hash     string
	Warnings []string
}

// HashOf returns the identifier the store uses for file contents.
func HashOf(src []byte) string {
	sum := sha256.Sum256(src)
	return hex.EncodeToString(sum[:])
}

// Load reads, parses and validates the file.
func (s *Store) Load() (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (*Snapshot, error) {
	src, fi, err := readFile(s.Path)
	if err != nil {
		return nil, err
	}
	cfg, doc, warns, err := Load(src)
	if err != nil {
		return nil, err
	}
	s.hash, s.modTime, s.size = HashOf(src), fi.ModTime(), fi.Size()
	return &Snapshot{Config: cfg, Doc: doc, Hash: s.hash, Warnings: warns}, nil
}

// LoadRaw reads the file without validating it and remembers it as the
// version loaded (see Changed). A cluster follower's own file is only its
// overrides, not a whole configuration.
func (s *Store) LoadRaw() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	src, fi, err := readFile(s.Path)
	if err != nil {
		return nil, err
	}
	s.hash, s.modTime, s.size = HashOf(src), fi.ModTime(), fi.Size()
	return src, nil
}

// ErrFollower is returned for a change made on a cluster follower, whose
// settings come from the primary.
var ErrFollower = errors.New("this node follows a cluster primary: change the settings there (node-specific ones in this node's own file)")

func readFile(path string) ([]byte, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if fi.Size() > 1<<20 {
		return nil, nil, fmt.Errorf("%s is larger than 1 MiB", path)
	}
	src, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, nil, err
	}
	return src, fi, nil
}

// Changed reports whether the file on disk differs from the last version this
// store loaded or wrote. It checks size and time first and only hashes when
// they differ, so it is cheap to call every few seconds.
func (s *Store) Changed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	fi, err := os.Stat(s.Path)
	if err != nil {
		return false
	}
	if fi.Size() == s.size && fi.ModTime().Equal(s.modTime) {
		return false
	}
	src, _, err := readFile(s.Path)
	if err != nil {
		return false
	}
	return HashOf(src) != s.hash
}

// Write replaces the file with src after validating it. expectedHash must be
// the hash of the version the caller edited; if the file changed since then,
// ErrConflict is returned and nothing is written.
func (s *Store) Write(src []byte, expectedHash string) (*Snapshot, error) {
	cfg, doc, warns, err := Load(src)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, _, err := readFile(s.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && HashOf(cur) != expectedHash {
		return nil, ErrConflict
	}
	if err == nil {
		if err := s.saveHistory(cur); err != nil {
			return nil, fmt.Errorf("saving history: %w", err)
		}
	}
	if err := writeAtomic(s.Path, src); err != nil {
		return nil, err
	}
	fi, err := os.Stat(s.Path)
	if err != nil {
		return nil, err
	}
	s.hash, s.modTime, s.size = HashOf(src), fi.ModTime(), fi.Size()
	return &Snapshot{Config: cfg, Doc: doc, Hash: s.hash, Warnings: warns}, nil
}

// writeAtomic writes data to a temporary file in the same directory, syncs it
// and renames it over path, keeping the original file's permissions.
func writeAtomic(path string, data []byte) error {
	mode := os.FileMode(0o640)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// HistoryEntry is one saved previous version.
type HistoryEntry struct {
	Name  string
	Saved time.Time
}

func (s *Store) saveHistory(src []byte) error {
	if err := os.MkdirAll(s.HistoryDir, 0o750); err != nil {
		return err
	}
	base := strings.TrimSuffix(filepath.Base(s.Path), filepath.Ext(s.Path))
	// Names sort by time, to the millisecond. Two saves within the same
	// millisecond (quick edits, scripts, a restore) would get the same name
	// and the second would replace the first, so step forward to the next
	// free millisecond: every version is kept and the order stays right.
	t := time.Now().UTC().Truncate(time.Millisecond)
	var name string
	for {
		name = filepath.Join(s.HistoryDir, fmt.Sprintf("%s-%s.toml", base, t.Format("20060102-150405.000")))
		if _, err := os.Lstat(name); errors.Is(err, os.ErrNotExist) {
			break
		}
		t = t.Add(time.Millisecond)
	}
	if err := writeAtomic(name, src); err != nil {
		return err
	}
	list, err := s.historyLocked()
	if err != nil {
		return err
	}
	for i := HistoryLimit; i < len(list); i++ {
		os.Remove(filepath.Join(s.HistoryDir, list[i].Name))
	}
	return nil
}

// History lists saved versions, newest first.
func (s *Store) History() ([]HistoryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.historyLocked()
}

func (s *Store) historyLocked() ([]HistoryEntry, error) {
	ents, err := os.ReadDir(s.HistoryDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []HistoryEntry
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, HistoryEntry{Name: e.Name(), Saved: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Restore makes a saved version current. The version being replaced is
// itself kept in history, so a restore can be undone.
func (s *Store) Restore(name, expectedHash string) (*Snapshot, error) {
	if name != filepath.Base(name) || !strings.HasSuffix(name, ".toml") {
		return nil, errors.New("invalid history entry")
	}
	src, _, err := readFile(filepath.Join(s.HistoryDir, name))
	if err != nil {
		return nil, err
	}
	return s.Write(src, expectedHash)
}
