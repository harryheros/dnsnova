package locality

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- the country table ----
//
// Clients are placed by the country their address is registered in, from
// the files the five regional Internet registries publish every day
// (delegated-extended). Registration is not always where an address is
// used, but it is right for most addresses, and it needs no outside
// service: the files are downloaded like block lists, and looking up a
// client sends nothing anywhere.

// DefaultCountrySources are the registries' daily files.
var DefaultCountrySources = []string{
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
	"https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

// Countries maps addresses to the country they are registered in. IPv6 is
// looked up by its first 64 bits: registries never assign smaller blocks.
type Countries struct {
	v4 []span
	v6 []span
	// Updated is when the newest file in it was downloaded.
	Updated time.Time
}

type span struct {
	start, end uint64
	cc         [2]byte
}

// Lookup returns the country a is registered in, or "".
func (c *Countries) Lookup(a netip.Addr) string {
	if c == nil || !a.IsValid() {
		return ""
	}
	a = a.Unmap()
	list, x := c.v6, uint64(0)
	if a.Is4() {
		b := a.As4()
		list, x = c.v4, uint64(binary.BigEndian.Uint32(b[:]))
	} else {
		b := a.As16()
		x = binary.BigEndian.Uint64(b[:8])
	}
	i, _ := slices.BinarySearchFunc(list, x, func(s span, x uint64) int {
		switch {
		case s.start > x:
			return 1
		case s.start < x:
			return -1
		}
		return 0
	})
	// i: the first span starting after x, or the one starting at x
	if i < len(list) && list[i].start == x {
		return string(list[i].cc[:])
	}
	if i > 0 && list[i-1].end >= x {
		return string(list[i-1].cc[:])
	}
	return ""
}

// Len returns how many address blocks the table holds.
func (c *Countries) Len() int {
	if c == nil {
		return 0
	}
	return len(c.v4) + len(c.v6)
}

// countryBuilder collects blocks from several files.
type countryBuilder struct{ v4, v6 []span }

// minBlocks: a registry file with fewer blocks than this is not a sound one
// (each lists tens of thousands).
const minBlocks = 1000

// parseDelegated reads one registry file (registry|cc|type|start|value|
// date|status...) into b, and returns how many blocks it held.
func (b *countryBuilder) parseDelegated(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		f := bytes.Split(line, []byte{'|'})
		if len(f) < 7 {
			continue // the version line, or a broken one
		}
		cc, typ, start, value, status := f[1], string(f[2]), string(f[3]), string(f[4]), string(f[6])
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' || string(cc) == "ZZ" {
			continue // summary lines (*), unassigned space
		}
		if status != "allocated" && status != "assigned" {
			continue
		}
		var s span
		copy(s.cc[:], cc)
		switch typ {
		case "ipv4":
			a, err := netip.ParseAddr(start)
			count, cerr := strconv.ParseUint(value, 10, 33)
			if err != nil || cerr != nil || !a.Is4() || count == 0 {
				continue
			}
			b4 := a.As4()
			s.start = uint64(binary.BigEndian.Uint32(b4[:]))
			s.end = s.start + count - 1
			if s.end > 0xffffffff {
				continue
			}
			b.v4 = append(b.v4, s)
		case "ipv6":
			a, err := netip.ParseAddr(start)
			plen, perr := strconv.Atoi(value)
			if err != nil || perr != nil || !a.Is6() || plen < 1 || plen > 64 {
				continue
			}
			b16 := a.As16()
			s.start = binary.BigEndian.Uint64(b16[:8])
			s.end = s.start | (^uint64(0) >> plen)
			b.v6 = append(b.v6, s)
		default:
			continue
		}
		n++
	}
	return n, sc.Err()
}

func (b *countryBuilder) build() *Countries {
	merge := func(list []span) []span {
		slices.SortFunc(list, func(a, b span) int {
			switch {
			case a.start < b.start:
				return -1
			case a.start > b.start:
				return 1
			}
			return 0
		})
		out := list[:0]
		for _, s := range list {
			if k := len(out); k > 0 {
				last := &out[k-1]
				if s.start <= last.end { // overlaps (should not happen): the first stays
					if s.end > last.end && s.cc == last.cc {
						last.end = s.end
					}
					continue
				}
				if s.cc == last.cc && last.end+1 == s.start {
					last.end = s.end
					continue
				}
			}
			out = append(out, s)
		}
		return slices.Clip(out)
	}
	return &Countries{v4: merge(b.v4), v6: merge(b.v6)}
}

// ParseCountries reads registry files into a table (for tests and tools).
func ParseCountries(files ...io.Reader) (*Countries, error) {
	var b countryBuilder
	for _, f := range files {
		if _, err := b.parseDelegated(f); err != nil {
			return nil, err
		}
	}
	return b.build(), nil
}

// ---- keeping the table current ----

// Updater downloads the registry files once a day, keeps a copy of each in
// Dir, and publishes a new table when one changed. A download that fails,
// or a file that does not look like a registry file, keeps the copy in use.
type Updater struct {
	Dir     string
	Sources []string // http(s) URLs or absolute file paths
	HTTP    *http.Client
	Log     *slog.Logger
	Every   time.Duration
	Publish func(*Countries)

	mu     sync.Mutex
	status CountryStatus
}

// CountryStatus is what the admin interface shows.
type CountryStatus struct {
	Blocks  int       `json:"blocks"`
	Updated time.Time `json:"updated"` // newest copy in use
	Checked time.Time `json:"checked"` // last download attempt
	Error   string    `json:"error,omitempty"`
}

// Status returns the table's state.
func (u *Updater) Status() CountryStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

// Run publishes the stored copies, then keeps them current until ctx is
// done.
func (u *Updater) Run(ctx context.Context) {
	every := u.Every
	if every <= 0 {
		every = 24 * time.Hour
	}
	if c, newest := u.load(); c != nil {
		u.publish(c, newest, "")
		if time.Since(newest) < every {
			select {
			case <-ctx.Done():
				return
			case <-time.After(every - time.Since(newest)):
			}
		}
	}
	for {
		u.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func (u *Updater) path(src string) string {
	sum := sha256.Sum256([]byte(src))
	return filepath.Join(u.Dir, "registry-"+hex.EncodeToString(sum[:8])+".txt")
}

// load builds a table from the stored copies, and returns the time of the
// newest.
func (u *Updater) load() (*Countries, time.Time) {
	var b countryBuilder
	var newest time.Time
	found := false
	for _, src := range u.Sources {
		f, err := os.Open(u.path(src))
		if err != nil {
			continue
		}
		if _, err := b.parseDelegated(f); err == nil {
			found = true
			if st, err := f.Stat(); err == nil && st.ModTime().After(newest) {
				newest = st.ModTime()
			}
		}
		f.Close()
	}
	if !found {
		return nil, time.Time{}
	}
	return b.build(), newest
}

func (u *Updater) publish(c *Countries, updated time.Time, errText string) {
	c.Updated = updated
	u.mu.Lock()
	u.status.Blocks, u.status.Updated = c.Len(), updated
	u.status.Checked, u.status.Error = time.Now(), errText
	u.mu.Unlock()
	if u.Publish != nil {
		u.Publish(c)
	}
}

// refresh downloads every source; when any copy changed, the table is
// rebuilt from all of them.
func (u *Updater) refresh(ctx context.Context) {
	changed := false
	var errs []string
	for _, src := range u.Sources {
		data, err := u.download(ctx, src)
		if err == nil {
			var b countryBuilder
			var n int
			if n, err = b.parseDelegated(bytes.NewReader(data)); err == nil && n < minBlocks {
				err = fmt.Errorf("%d address blocks, too few for a registry file", n)
			}
		}
		if err != nil {
			errs = append(errs, src+": "+err.Error())
			continue
		}
		if old, rerr := os.ReadFile(u.path(src)); rerr == nil && bytes.Equal(old, data) {
			now := time.Now()
			os.Chtimes(u.path(src), now, now)
			continue
		}
		if err := u.store(src, data); err != nil {
			errs = append(errs, src+": "+err.Error())
			continue
		}
		changed = true
	}
	errText := strings.Join(errs, "; ")
	if errText != "" && u.Log != nil {
		u.Log.Warn("locality: country data not updated; the copy in use is kept", "err", errText)
	}
	if changed {
		if c, newest := u.load(); c != nil {
			u.publish(c, newest, errText)
			return
		}
	}
	u.mu.Lock()
	u.status.Checked, u.status.Error = time.Now(), errText
	u.mu.Unlock()
}

// maxCountryFile bounds a download (the registry files are a few MB).
const maxCountryFile = 64 << 20

func (u *Updater) download(ctx context.Context, src string) ([]byte, error) {
	if strings.HasPrefix(src, "/") {
		f, err := os.Open(src)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return readAtMost(f)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dnsnova")
	hc := u.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	return readAtMost(resp.Body)
}

func readAtMost(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxCountryFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCountryFile {
		return nil, errors.New("too large for a registry file")
	}
	return data, nil
}

func (u *Updater) store(src string, data []byte) error {
	if err := os.MkdirAll(u.Dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(u.Dir, ".registry-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), u.path(src))
}
