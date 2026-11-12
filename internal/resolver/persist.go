package resolver

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"time"

	m "github.com/harryheros/dnsnova/internal/dnsmsg"
)

// The answer cache on disk (cache.persist): a header, one record per entry
// and a CRC-32 of everything before it. Each record keeps the upstream's
// response as it was cached (without its OPT record) and when it was
// stored; on load every response is checked again as when it first
// arrived, so a damaged or foreign file cannot put anything in the cache
// that an upstream could not have.
//
//	magic "DNCACHE1" | saved (unix ns, int64) | len(ECS) u16 | ECS
//	repeat: 1 | len(key) u16 | key | len(msg) u16 | msg | len(ede) u16 | ede | stored (unix ns)
//
// The cache lifetime is not saved: it is worked out again from the
// response with the limits in force (cache.min_ttl, max_ttl, ...).
//
//	0 | CRC-32 (IEEE) u32
const persistMagic = "DNCACHE1"

// ErrCacheFile is returned for a cache file that is damaged or not one.
var ErrCacheFile = errors.New("not a valid cache file")

// SaveCache writes the cache entries that can still be served (fresh, or
// within serve_stale) to w and returns how many. Failures are not kept.
func (r *Resolver) SaveCache(w io.Writer) (int, error) {
	s := r.set.Load()
	now := r.now()
	var list []struct {
		key string
		e   *entry
	}
	for i := range r.cache.shards {
		sh := &r.cache.shards[i]
		sh.mu.RLock()
		for k, e := range sh.m {
			if !e.failure && e.cacheable && now.Before(e.expire.Add(s.ServeStale)) {
				list = append(list, struct {
					key string
					e   *entry
				}{k, e})
			}
		}
		sh.mu.RUnlock()
	}
	crc := crc32.NewIEEE()
	bw := bufio.NewWriterSize(io.MultiWriter(w, crc), 1<<16)
	var b []byte
	b = append(b, persistMagic...)
	b = binary.BigEndian.AppendUint64(b, uint64(now.UnixNano()))
	b = appendField(b, s.ECS)
	bw.Write(b)
	for _, it := range list {
		b = append(b[:0], 1)
		b = appendField(b, []byte(it.key))
		b = appendField(b, it.e.msg)
		b = appendField(b, it.e.ede)
		b = binary.BigEndian.AppendUint64(b, uint64(it.e.stored.UnixNano()))
		if _, err := bw.Write(b); err != nil {
			return 0, err
		}
	}
	bw.WriteByte(0)
	if err := bw.Flush(); err != nil {
		return 0, err
	}
	if _, err := w.Write(binary.BigEndian.AppendUint32(nil, crc.Sum32())); err != nil {
		return 0, err
	}
	return len(list), nil
}

func appendField(b, f []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(f)))
	return append(b, f...)
}

// LoadCache reads a file written by SaveCache into the cache and returns
// how many entries it added. Entries past expiry plus serve_stale are left
// out, and so is everything when the file was saved for another client
// subnet (ecs.address): those answers were for another network. Nothing is
// added unless the whole file is intact.
func (r *Resolver) LoadCache(rd io.Reader) (int, error) {
	data, err := io.ReadAll(io.LimitReader(rd, 1<<31))
	if err != nil {
		return 0, err
	}
	if len(data) < len(persistMagic)+8+2+1+4 || string(data[:len(persistMagic)]) != persistMagic {
		return 0, ErrCacheFile
	}
	body, sum := data[:len(data)-4], binary.BigEndian.Uint32(data[len(data)-4:])
	if crc32.ChecksumIEEE(body) != sum {
		return 0, fmt.Errorf("%w: checksum mismatch", ErrCacheFile)
	}
	p := &reader{b: body[len(persistMagic)+8:]}
	ecs := p.field()
	s := r.set.Load()
	if p.err != nil {
		return 0, ErrCacheFile
	}
	if !bytes.Equal(ecs, s.ECS) {
		return 0, nil // answers for another network
	}
	now := r.now()
	type item struct {
		key string
		e   *entry
	}
	var items []item
	for {
		tag := p.byte()
		if p.err != nil {
			return 0, ErrCacheFile
		}
		if tag == 0 {
			break
		}
		key, msg, ede := string(p.field()), bytes.Clone(p.field()), bytes.Clone(p.field())
		stored := time.Unix(0, int64(p.u64()))
		if p.err != nil || tag != 1 {
			return 0, ErrCacheFile
		}
		e, ok := restore(key, msg, ede, stored, s)
		if !ok || stored.After(now.Add(time.Minute)) || !now.Before(e.expire.Add(s.ServeStale)) {
			continue
		}
		items = append(items, item{key, e})
	}
	if len(p.b) != 0 {
		return 0, ErrCacheFile
	}
	n := 0
	for _, it := range items {
		if r.cache.get(it.key) == nil {
			r.cache.set(it.key, it.e)
			n++
		}
	}
	return n, nil
}

// restore rebuilds an entry from its saved response, checking it as a new
// upstream response for the question its key names.
func restore(key string, msg, ede []byte, stored time.Time, s *Settings) (*entry, bool) {
	if len(msg) < m.HeaderLen || m.U16(msg, 4) != 1 {
		return nil, false
	}
	name, off, err := m.ReadQName(msg, m.HeaderLen)
	if err != nil || off+4 > len(msg) {
		return nil, false
	}
	q := &m.Query{Name: name, Type: m.U16(msg, off), Class: m.U16(msg, off+2)}
	if len(key) == 0 {
		return nil, false
	}
	bits := key[len(key)-1]
	q.DO = bits&1 != 0
	if bits&2 != 0 {
		q.Flags |= m.FlagCD
	}
	if q.CacheKey() != key {
		return nil, false
	}
	e, err := analyze(msg, q)
	if err != nil || !e.cacheable || e.failure {
		return nil, false
	}
	if e.signed && !e.negative { // as fetch does
		e.ttl = clampSigned(e.ttl, s)
	} else {
		e.ttl = clampTTL(e.ttl, e.negative, false, s)
	}
	e.ede, e.stored = ede, stored
	e.expire = stored.Add(time.Duration(e.ttl) * time.Second)
	return e, e.ttl > 0
}

// reader reads the fields of a cache file; the first error sticks.
type reader struct {
	b   []byte
	err error
}

func (p *reader) take(n int) []byte {
	if p.err != nil || n > len(p.b) {
		p.err = ErrCacheFile
		return nil
	}
	out := p.b[:n]
	p.b = p.b[n:]
	return out
}

func (p *reader) byte() byte {
	if b := p.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (p *reader) u64() uint64 {
	if b := p.take(8); b != nil {
		return binary.BigEndian.Uint64(b)
	}
	return 0
}

func (p *reader) field() []byte {
	if b := p.take(2); b != nil {
		return p.take(int(binary.BigEndian.Uint16(b)))
	}
	return nil
}
