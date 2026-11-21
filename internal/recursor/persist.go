package recursor

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net/netip"
	"time"
)

// What is learnt about name servers (how fast each answers, and the ways
// some answer that must be allowed for) can be kept across a restart, so
// that the first lookups after one go to the fast servers at once rather
// than learning them again, one slow or failed try at a time.
//
// The file holds name server addresses and timings only: no names, no
// zones, no clients, no cookies. Each record:
//
//	address      16 bytes (IPv4 as IPv4-mapped IPv6)
//	srtt         4 bytes, microseconds
//	last used    8 bytes, Unix milliseconds
//	no EDNS, answers plain, no TCP: until when, 8 bytes each, Unix seconds (0: no)
//
// after a header (magic, record count) and before a CRC-32 of everything
// before it. Failures and back-offs are not kept: a restart is often what
// follows a network problem, and every server deserves a fresh try.

var serversMagic = [8]byte{'D', 'N', 'S', 'N', 'I', 'N', 'F', 1}

const serverRecord = 16 + 4 + 8 + 3*8

// ErrServersFile is returned for a file that is damaged or not one.
var ErrServersFile = errors.New("not a name server file, or damaged")

// SaveServers writes what is worth keeping about name servers to w and
// returns how many were written: the ones used recently enough that their
// round trip still counts (infraForget), and the ones with a quirk still
// in force.
func (r *Recursor) SaveServers(w io.Writer) (int, error) {
	now := r.now()
	type saved struct {
		a     netip.Addr
		srtt  time.Duration
		last  time.Time
		until [3]time.Time
	}
	// copied under the lock, which lookups need, and encoded after it
	in := r.infra
	in.mu.Lock()
	list := make([]saved, 0, len(in.m))
	for a, s := range in.m {
		fresh := s.srtt > 0 && s.fails == 0 && !s.decayed && now.Sub(s.lastUsed) < infraForget // measured, not estimated
		quirk := now.Before(s.noEDNS) || now.Before(s.plainUntil) || now.Before(s.noTCPUntil)
		if !fresh && !quirk {
			continue
		}
		v := saved{a: a, last: s.lastUsed, until: [3]time.Time{s.noEDNS, s.plainUntil, s.noTCPUntil}}
		if fresh {
			v.srtt = s.srtt
		}
		list = append(list, v)
	}
	in.mu.Unlock()
	out := make([]byte, 0, 16+len(list)*serverRecord+4)
	out = append(out, serversMagic[:]...)
	out = binary.BigEndian.AppendUint64(out, uint64(len(list)))
	for _, v := range list {
		b := v.a.As16()
		out = append(out, b[:]...)
		out = binary.BigEndian.AppendUint32(out, uint32(min(v.srtt, maxSavedRTT)/time.Microsecond))
		out = binary.BigEndian.AppendUint64(out, uint64(v.last.UnixMilli()))
		for _, t := range v.until {
			u := int64(0)
			if now.Before(t) {
				u = t.Unix()
			}
			out = binary.BigEndian.AppendUint64(out, uint64(u))
		}
	}
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	if _, err := w.Write(out); err != nil {
		return 0, err
	}
	return len(list), nil
}

// maxSavedRTT: no round trip above this is kept or believed (a failure
// raises the estimate to 5 s at most, and those are not kept).
const maxSavedRTT = 5 * time.Second

// maxServersFile bounds the file read: as many records as are remembered.
const maxServersFile = 16 + maxServers*serverRecord + 4

// LoadServers reads a file written by SaveServers and returns how many
// servers it taught. Nothing is taken unless the whole file is intact,
// and each value is checked: a round trip that is no longer current, a
// time in the future (the clock went back) or a quirk that would last
// longer than it can when learnt is left out.
func (r *Recursor) LoadServers(rd io.Reader) (int, error) {
	data, err := io.ReadAll(io.LimitReader(rd, maxServersFile+1))
	if err != nil {
		return 0, err
	}
	if len(data) < 16+4 || len(data) > maxServersFile || [8]byte(data[:8]) != serversMagic {
		return 0, ErrServersFile
	}
	body, sum := data[:len(data)-4], binary.BigEndian.Uint32(data[len(data)-4:])
	if crc32.ChecksumIEEE(body) != sum {
		return 0, ErrServersFile
	}
	count := binary.BigEndian.Uint64(body[8:16])
	recs := body[16:]
	if count > maxServers || uint64(len(recs)) != count*serverRecord {
		return 0, ErrServersFile
	}
	now := r.now()
	// a quirk is learnt for an hour (setPlain, setNoTCP, the EDNS fallback)
	latest := now.Add(time.Hour)
	in := r.infra
	in.mu.Lock()
	defer in.mu.Unlock()
	n := 0
	for len(recs) > 0 {
		rec := recs[:serverRecord]
		recs = recs[serverRecord:]
		a := netip.AddrFrom16([16]byte(rec[:16])).Unmap()
		if a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		srtt := time.Duration(binary.BigEndian.Uint32(rec[16:20])) * time.Microsecond
		last := time.UnixMilli(int64(binary.BigEndian.Uint64(rec[20:28])))
		var until [3]time.Time
		for i := range until {
			u := int64(binary.BigEndian.Uint64(rec[28+8*i:]))
			if u <= 0 {
				continue
			}
			if t := time.Unix(u, 0); t.After(now) && !t.After(latest) {
				until[i] = t
			}
		}
		fresh := srtt > 0 && srtt <= maxSavedRTT && !last.After(now) && now.Sub(last) < infraForget
		if !fresh && until == [3]time.Time{} {
			continue
		}
		if _, known := in.m[a]; known {
			continue // learnt since the start: newer
		}
		if len(in.m) >= maxServers {
			break
		}
		s := &server{noEDNS: until[0], plainUntil: until[1], noTCPUntil: until[2]}
		if fresh {
			s.srtt, s.lastUsed = srtt, last
		} else {
			s.lastUsed = now
		}
		in.m[a] = s
		n++
	}
	return n, nil
}
