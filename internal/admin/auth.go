package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// ---- account and setup code, stored under <data_dir>/secrets ----

// account is the administrator. The file holds no plain-text secret except
// the TOTP seed, which by its nature must be readable by the server.
type account struct {
	Username string    `json:"username"`
	Password string    `json:"password"` // PHC string: $argon2id$v=19$m=..,t=..,p=..$salt$hash
	TOTP     string    `json:"totp,omitempty"`
	Updated  time.Time `json:"updated"`
}

type secrets struct {
	dir string
	mu  sync.Mutex
	acc *account
}

func openSecrets(dataDir string) (*secrets, error) {
	s := &secrets{dir: filepath.Join(dataDir, "secrets")}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "admin.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var a account
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(s.dir, "admin.json"), err)
		}
		s.acc = &a
	}
	return s, nil
}

// ResetAccount removes the administrator account of the server whose data
// directory is dataDir, for a forgotten password. Settings are untouched;
// once DNSNova restarts, the web interface offers to create the account
// again, as after installing.
func ResetAccount(dataDir string) error {
	dir := filepath.Join(dataDir, "secrets")
	for _, f := range []string{"admin.json", "setup-code", "setup-trust"} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *secrets) account() *account {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acc == nil {
		return nil
	}
	a := *s.acc
	return &a
}

func (s *secrets) save(a *account) error {
	a.Updated = time.Now().UTC()
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(s.dir, "admin.json"), b); err != nil {
		return err
	}
	s.mu.Lock()
	c := *a
	s.acc = &c
	s.mu.Unlock()
	return nil
}

// setupCode returns the one-time setup code, creating it when no account
// exists. It is empty once an account exists.
//
// The code is short enough to read out and type (8 characters, about 40
// bits, shown as XXXX-XXXX); guessing is limited by the per-address lockout
// and by setupFailLimit, after which a new code replaces it.
func (s *secrets) setupCode() (string, error) {
	if s.account() != nil {
		return "", nil
	}
	path := filepath.Join(s.dir, "setup-code")
	if b, err := os.ReadFile(path); err == nil {
		if c := strings.TrimSpace(string(b)); len(normalizeCode(c)) >= 8 {
			return c, nil
		}
	}
	return s.newSetupCode()
}

// codeAlphabet leaves out characters that are easy to confuse (0 O 1 I L).
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

func (s *secrets) newSetupCode() (string, error) {
	b := randomBytes(8)
	out := make([]byte, 0, 9)
	for i, x := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(x)%len(codeAlphabet)])
	}
	code := string(out)
	if err := writeSecret(filepath.Join(s.dir, "setup-code"), []byte(code+"\n")); err != nil {
		return "", err
	}
	return code, nil
}

// normalizeCode makes typing forgiving: case, spaces and dashes don't
// matter. (The code itself has no 0, O, 1, I or L to confuse.)
func normalizeCode(c string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(c) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *secrets) clearSetupCode() {
	os.Remove(filepath.Join(s.dir, "setup-code"))
	os.Remove(filepath.Join(s.dir, "setup-trust"))
}

// trustLocalSetup is off in tests that check the setup code itself.
var trustLocalSetup = true

// setupTrusted reports whether ip may create the administrator without the
// setup code: the server itself, a private network (the usual home or
// office install), or an address the installer was run from over SSH
// (listed in setup-trust). Anyone else on the internet needs the code, so a
// scanner that finds a fresh install first cannot take it over.
func (s *secrets) setupTrusted(ip netip.Addr) bool {
	ip = ip.Unmap()
	if trustLocalSetup && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return true
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "setup-trust"))
	if err != nil {
		return false
	}
	for _, line := range strings.Fields(string(b)) {
		if a, err := netip.ParseAddr(line); err == nil && a.Unmap() == ip {
			return true
		}
	}
	return false
}

// writeSecret writes a 0600 file atomically.
func writeSecret(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported systems
	}
	return b
}

// ---- passwords: Argon2id ----

// hashParams are the Argon2id costs for new hashes (RFC 9106, second
// recommended option). Stored hashes carry their own parameters.
var hashParams = struct {
	time, memory uint32
	threads      uint8
}{3, 64 * 1024, 2}

// hashSlots bounds how many hashes run at once: each takes 64 MiB.
var hashSlots = make(chan struct{}, 2)

// loginQueue counts logins being checked or waiting for a slot.
var loginQueue atomic.Int32

const maxLoginQueue = 8

func hashPassword(pw string) string {
	salt := randomBytes(16)
	p := hashParams
	hashSlots <- struct{}{}
	key := argon2.IDKey([]byte(pw), salt, p.time, p.memory, p.threads, 32)
	<-hashSlots
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.time, p.threads, enc.EncodeToString(salt), enc.EncodeToString(key))
}

func checkPassword(phc, pw string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || m > 1<<20 || t == 0 || t > 16 || p == 0 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	hashSlots <- struct{}{}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	<-hashSlots
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is checked when the user name is wrong, so a wrong name takes as
// long as a wrong password.
var dummyHash = sync.OnceValue(func() string { return hashPassword("not a password") })

func validPassword(pw string) error {
	switch {
	case len(pw) < 10:
		return errors.New("the password must have at least 10 characters")
	case len(pw) > 256:
		return errors.New("the password is too long")
	}
	return nil
}

func validUsername(u string) error {
	if u == "" || len(u) > 64 {
		return errors.New("the user name must have 1 to 64 characters")
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '@') {
			return errors.New("the user name may use letters, digits and . _ - @")
		}
	}
	return nil
}

// ---- two-step verification: TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string { return b32.EncodeToString(randomBytes(20)) }

func totpURI(secret, user, issuer string) string {
	label := url.PathEscape(issuer + ":" + user)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func totpAt(secret string, counter uint64) (string, bool) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return "", false
	}
	mac := hmac.New(sha1.New, key)
	binary.Write(mac, binary.BigEndian, counter)
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), true
}

// totpCheck verifies code at now with one step of clock skew either way and
// returns the counter it matched, so a code is never accepted twice.
func totpCheck(secret, code string, now time.Time, lastUsed uint64) (uint64, bool) {
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != 6 {
		return 0, false
	}
	c := uint64(now.Unix() / 30)
	for _, ctr := range []uint64{c - 1, c, c + 1} {
		if ctr <= lastUsed {
			continue
		}
		if want, ok := totpAt(secret, ctr); ok && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return ctr, true
		}
	}
	return 0, false
}

// ---- sessions ----

const (
	cookieName  = "dnsnova_session"
	idleTimeout = 12 * time.Hour
	maxLifetime = 7 * 24 * time.Hour
	maxSessions = 64
)

type session struct {
	user        string
	csrf        string
	created     time.Time
	seen        time.Time
	pendingTOTP string // a secret being set up, not yet confirmed
}

// sessions are kept in memory only: a restart logs everyone out. The map is
// keyed by the SHA-256 of the cookie value.
type sessions struct {
	mu sync.Mutex
	m  map[string]*session
}

func tokenKey(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return string(sum[:])
}

func (s *sessions) create(user string, now time.Time) (token string, sess *session) {
	token = base64.RawURLEncoding.EncodeToString(randomBytes(32))
	sess = &session{user: user, csrf: base64.RawURLEncoding.EncodeToString(randomBytes(24)), created: now, seen: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]*session{}
	}
	if len(s.m) >= maxSessions { // drop the least recently used
		var oldK string
		var old *session
		for k, v := range s.m {
			if old == nil || v.seen.Before(old.seen) {
				oldK, old = k, v
			}
		}
		delete(s.m, oldK)
	}
	s.m[tokenKey(token)] = sess
	return token, sess
}

func (s *sessions) get(token string, now time.Time) *session {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tokenKey(token)
	sess := s.m[k]
	if sess == nil {
		return nil
	}
	if now.Sub(sess.seen) > idleTimeout || now.Sub(sess.created) > maxLifetime {
		delete(s.m, k)
		return nil
	}
	sess.seen = now
	return sess
}

func (s *sessions) drop(token string) {
	s.mu.Lock()
	delete(s.m, tokenKey(token))
	s.mu.Unlock()
}

// dropAll logs every session out, e.g. after a password change; keep is the
// token of the session that made the change, or "".
func (s *sessions) dropAll(keep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tokenKey(keep)
	for key := range s.m {
		if keep == "" || key != k {
			delete(s.m, key)
		}
	}
}

// ---- login lockout ----

const (
	maxFailures  = 5
	failureSpan  = 15 * time.Minute
	lockDuration = 15 * time.Minute
	// maxLockEntries bounds the table of addresses with failed attempts.
	maxLockEntries = 10000
)

type lockout struct {
	mu sync.Mutex
	m  map[netip.Prefix]*failures
}

type failures struct {
	n     int
	first time.Time
	until time.Time
}

// lockKey groups IPv6 clients by /64, which one host usually owns.
func lockKey(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p
	}
	return netip.PrefixFrom(ip, 32)
}

// locked returns how long ip must still wait, or 0.
func (l *lockout) locked(ip netip.Addr, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.m[lockKey(ip)]; f != nil && now.Before(f.until) {
		return f.until.Sub(now)
	}
	return 0
}

func (l *lockout) fail(ip netip.Addr, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[netip.Prefix]*failures{}
	}
	if len(l.m) > maxLockEntries { // forget stale entries
		for k, f := range l.m {
			if now.Sub(f.first) > failureSpan && now.After(f.until) {
				delete(l.m, k)
			}
		}
		// still full: a flood from many addresses. Forget counts in
		// progress (never a lock in force) so the table stays bounded.
		for k, f := range l.m {
			if len(l.m) <= maxLockEntries {
				break
			}
			if now.After(f.until) {
				delete(l.m, k)
			}
		}
	}
	k := lockKey(ip)
	f := l.m[k]
	if f == nil || now.Sub(f.first) > failureSpan {
		f = &failures{first: now}
		l.m[k] = f
	}
	f.n++
	if f.n >= maxFailures {
		f.until = now.Add(lockDuration)
		f.n, f.first = 0, now
	}
}

func (l *lockout) succeed(ip netip.Addr) {
	l.mu.Lock()
	delete(l.m, lockKey(ip))
	l.mu.Unlock()
}
