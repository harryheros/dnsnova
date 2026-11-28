package server

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
)

// cacheFile holds the answer cache across restarts (cache.persist), in
// data_dir.
const cacheFile = "cache.bin"

// cacheSaveEvery is how often the cache is saved while running, so a crash
// or power cut loses at most this much.
const cacheSaveEvery = 10 * time.Minute

var cacheSaveMu sync.Mutex // one save at a time

func cachePath(c *config.Config) string { return filepath.Join(c.Server.DataDir, cacheFile) }

// serversFile keeps what recursion learned about name servers (how fast
// each answers, and quirks) with the cache: addresses and timings only.
const serversFile = "servers.bin"

func serversPath(c *config.Config) string { return filepath.Join(c.Server.DataDir, serversFile) }

// loadServers teaches recursion what it knew about name servers before
// the restart, when the cache is kept. Like the cache, a damaged file is
// only logged.
func (s *Server) loadServers(c *config.Config) {
	if !c.PersistCache() || s.Rec == nil {
		return
	}
	f, err := os.Open(serversPath(c))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.Log.Warn("name server file not loaded", "err", err)
		return
	}
	defer f.Close()
	n, err := s.Rec.LoadServers(f)
	if err != nil {
		s.Log.Warn("could not load saved name server statistics; DNSNova will measure response times again", "file", serversPath(c), "err", err)
		return
	}
	if n > 0 {
		s.Log.Info("name servers remembered", "servers", n)
	}
}

// loadCache fills the answer cache from the file saved last time, when
// the cache is kept (Config.PersistCache). A damaged or unreadable file is only logged: the
// cache then starts empty, as without the setting.
func (s *Server) loadCache(c *config.Config) {
	if !c.PersistCache() {
		s.dropCacheFile(c)
		return
	}
	f, err := os.Open(cachePath(c))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		s.Log.Warn("cache file not loaded", "err", err)
		return
	}
	defer f.Close()
	start := time.Now()
	n, err := s.res.LoadCache(f)
	if err != nil {
		s.Log.Warn("cache file not loaded: the cache starts empty", "file", cachePath(c), "err", err)
		return
	}
	s.Log.Info("cache loaded", "entries", n, "took", time.Since(start).Round(time.Millisecond).String())
}

// saveCache writes the answer cache to data_dir when it is kept:
// to a temporary file (mode 0600) that then replaces the old one, so a
// crash while saving leaves the previous file.
func (s *Server) saveCache() error {
	st := s.state.Load()
	if st == nil || s.res == nil || !st.cfg.PersistCache() {
		return nil
	}
	cacheSaveMu.Lock()
	defer cacheSaveMu.Unlock()
	if err := writeFileAtomic(cachePath(st.cfg), func(w io.Writer) error { _, err := s.res.SaveCache(w); return err }); err != nil {
		return err
	}
	if s.Rec == nil {
		return nil
	}
	if localityOn(st.cfg) {
		if err := writeFileAtomic(zonesPath(st.cfg), func(w io.Writer) error { _, err := s.Rec.SaveZones(w); return err }); err != nil {
			return err
		}
	} else {
		os.Remove(zonesPath(st.cfg))
	}
	return writeFileAtomic(serversPath(st.cfg), func(w io.Writer) error { _, err := s.Rec.SaveServers(w); return err })
}

// writeFileAtomic writes path through a temporary file (mode 0600) that
// then replaces it, so a crash while writing leaves the previous file.
func writeFileAtomic(path string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := write(tmp); err != nil {
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
	return os.Rename(tmp.Name(), path)
}

// dropCacheFile removes a saved cache: when it is not kept, names that
// were looked up are not left on disk.
func (s *Server) dropCacheFile(c *config.Config) {
	cacheSaveMu.Lock()
	defer cacheSaveMu.Unlock()
	if err := os.Remove(cachePath(c)); err == nil {
		s.Log.Info("saved cache removed", "file", cachePath(c))
	}
	os.Remove(serversPath(c))
	os.Remove(zonesPath(c))
}

// cacheSaver saves the cache every cacheSaveEvery until the server stops
// (Shutdown saves it one last time).
func (s *Server) cacheSaver() {
	t := time.NewTicker(cacheSaveEvery)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			if err := s.saveCache(); err != nil {
				s.Log.Warn("cache not saved", "err", err)
			}
		}
	}
}
