package admin

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harryheros/dnsnova/internal/config"
	"github.com/harryheros/dnsnova/internal/insight"
	"github.com/harryheros/dnsnova/internal/stats"
)

func subtleEq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// ---- setup, login, session ----

func (a *Admin) getSetup(w http.ResponseWriter, r *http.Request, c *call) {
	needed := a.sec.account() == nil
	writeJSON(w, http.StatusOK, map[string]any{"needed": needed, "code_required": needed && !a.sec.setupTrusted(c.ip), "secure": r.TLS != nil})
}

func (a *Admin) postSetup(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct{ Code, Username, Password string }
	if !decode(w, r, 4<<10, &req) {
		return
	}
	if a.sec.account() != nil {
		writeError(w, http.StatusConflict, "setup is already done; log in instead")
		return
	}
	if !a.notLocked(w, c) {
		return
	}
	code := a.SetupCode()
	if a.sec.setupTrusted(c.ip) {
		// no code needed from here
	} else if code == "" || !constEq(normalizeCode(req.Code), normalizeCode(code)) {
		a.lock.fail(c.ip, a.Now())
		if a.setupFails.Add(1) >= setupFailLimit {
			// Too many wrong codes from anywhere: replace the code, so
			// guessing from many addresses gets nowhere.
			a.setupFails.Store(0)
			if _, err := a.sec.newSetupCode(); err == nil {
				a.log.Warn("admin: too many wrong setup codes; a new code was written to " + a.sec.dir + "/setup-code")
			}
		}
		writeError(w, http.StatusForbidden, "wrong setup code; the installer printed it, and it is in <data_dir>/secrets/setup-code")
		return
	}
	if err := validUsername(req.Username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validPassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.sec.save(&account{Username: req.Username, Password: hashPassword(req.Password)}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save the account: "+err.Error())
		return
	}
	a.sec.clearSetupCode()
	a.lock.succeed(c.ip)
	a.log.Info("admin: administrator created", "user", req.Username, "from", c.ip.String())
	a.startSession(w, r, c, req.Username, http.StatusCreated)
}

func (a *Admin) notLocked(w http.ResponseWriter, c *call) bool {
	if d := a.lock.locked(c.ip, a.Now()); d > 0 {
		secs := int(math.Ceil(d.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed attempts; try again in %d minutes", (secs+59)/60))
		return false
	}
	return true
}

func (a *Admin) startSession(w http.ResponseWriter, r *http.Request, c *call, user string, status int) {
	token, s := a.sess.create(user, a.Now())
	a.setCookie(w, r, token, int(maxLifetime.Seconds()))
	acc := a.sec.account()
	writeJSON(w, status, map[string]any{"username": user, "csrf": s.csrf, "totp": acc != nil && acc.TOTP != "", "secure": r.TLS != nil, "client_ip": c.ip.String()})
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct{ Username, Password, TOTP string }
	if !decode(w, r, 4<<10, &req) {
		return
	}
	acc := a.sec.account()
	if acc == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "no administrator yet; finish setup first", "setup": true})
		return
	}
	if !a.notLocked(w, c) {
		return
	}
	hash := acc.Password
	userOK := constEq(req.Username, acc.Username)
	if !userOK {
		hash = dummyHash()
	}
	if !checkPassword(hash, req.Password) || !userOK {
		a.lock.fail(c.ip, a.Now())
		a.log.Warn("admin: failed login", "from", c.ip.String())
		writeError(w, http.StatusUnauthorized, "wrong user name or password")
		return
	}
	if acc.TOTP != "" {
		if req.TOTP == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "enter the code from your authenticator app", "totp_required": true})
			return
		}
		if !a.useTOTP(acc.TOTP, req.TOTP) {
			a.lock.fail(c.ip, a.Now())
			a.log.Warn("admin: failed login (two-step code)", "from", c.ip.String())
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "wrong or already used code", "totp_required": true})
			return
		}
	}
	a.lock.succeed(c.ip)
	a.log.Info("admin: login", "user", acc.Username, "from", c.ip.String())
	a.startSession(w, r, c, acc.Username, http.StatusOK)
}

func (a *Admin) useTOTP(secret, code string) bool {
	a.totpMu.Lock()
	defer a.totpMu.Unlock()
	ctr, ok := totpCheck(secret, code, a.Now(), a.totpLast)
	if ok {
		a.totpLast = ctr
	}
	return ok
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request, c *call) {
	a.sess.drop(c.token)
	a.setCookie(w, r, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) getSession(w http.ResponseWriter, r *http.Request, c *call) {
	acc := a.sec.account()
	writeJSON(w, http.StatusOK, map[string]any{"username": c.sess.user, "csrf": c.sess.csrf, "totp": acc.TOTP != "", "secure": r.TLS != nil, "client_ip": c.ip.String()})
}

// ---- account ----

func (a *Admin) changePassword(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct{ Current, New string }
	if !decode(w, r, 4<<10, &req) || !a.notLocked(w, c) {
		return
	}
	acc := a.sec.account()
	if !checkPassword(acc.Password, req.Current) {
		a.lock.fail(c.ip, a.Now())
		writeError(w, http.StatusForbidden, "the current password is wrong")
		return
	}
	if err := validPassword(req.New); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	acc.Password = hashPassword(req.New)
	if err := a.sec.save(acc); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.sess.dropAll(c.token) // every other session is logged out
	a.log.Info("admin: password changed", "user", acc.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) beginTOTP(w http.ResponseWriter, r *http.Request, c *call) {
	acc := a.sec.account()
	if acc.TOTP != "" {
		writeError(w, http.StatusConflict, "two-step verification is already on; turn it off first")
		return
	}
	secret := newTOTPSecret()
	a.sess.mu.Lock()
	c.sess.pendingTOTP = secret
	a.sess.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "uri": totpURI(secret, acc.Username, "DNSNova")})
}

func (a *Admin) confirmTOTP(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct{ Code string }
	if !decode(w, r, 1<<10, &req) {
		return
	}
	a.sess.mu.Lock()
	secret := c.sess.pendingTOTP
	a.sess.mu.Unlock()
	if secret == "" {
		writeError(w, http.StatusConflict, "start with POST /api/v1/account/totp")
		return
	}
	if !a.useTOTP(secret, req.Code) {
		writeError(w, http.StatusBadRequest, "wrong code; check the time on your phone and try the next code")
		return
	}
	acc := a.sec.account()
	acc.TOTP = secret
	if err := a.sec.save(acc); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.sess.mu.Lock()
	c.sess.pendingTOTP = ""
	a.sess.mu.Unlock()
	a.log.Info("admin: two-step verification turned on", "user", acc.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) disableTOTP(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct{ Password string }
	if !decode(w, r, 4<<10, &req) || !a.notLocked(w, c) {
		return
	}
	acc := a.sec.account()
	if !checkPassword(acc.Password, req.Password) {
		a.lock.fail(c.ip, a.Now())
		writeError(w, http.StatusForbidden, "wrong password")
		return
	}
	acc.TOTP = ""
	if err := a.sec.save(acc); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.log.Info("admin: two-step verification turned off", "user", acc.Username)
	w.WriteHeader(http.StatusNoContent)
}

// ---- status ----

func (a *Admin) status(w http.ResponseWriter, r *http.Request, c *call) {
	snap := a.b.Snapshot()
	cfg := snap.Config
	pos, neg := a.b.Cache()
	started := a.b.Started()
	ql := a.b.QueryLog().State(a.Now())
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        a.b.Version(),
		"started":        started.UTC(),
		"uptime_seconds": int64(a.Now().Sub(started).Seconds()),
		"mode":           cfg.Server.Mode,
		"domains":        nonNil(cfg.TLS.Domains),
		"listeners":      a.b.Listeners(),
		"certificate":    a.b.Certificate(),
		"cache":          map[string]int{"positive": pos, "negative": neg, "capacity": cfg.Cache.Size},
		"retention":      cfg.Stats.Retention,
		"serves_dns":     cfg.ServesDNS(),
		"privacy": map[string]any{
			"query_log":            ql.On,
			"query_log_full_ip":    ql.On && ql.FullIP,
			"client_ip_upstream":   false, // DNSNova never forwards client addresses (no ECS)
			"telemetry":            false,
			"zero_rtt":             false,
			"private_ptr_answered": true,
		},
		"warnings": nonNil(snap.Warnings),
	})
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func (a *Admin) stats(w http.ResponseWriter, r *http.Request, c *call) {
	spans := map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}
	name := r.URL.Query().Get("range")
	if name == "" {
		name = "24h"
	}
	span, ok := spans[name]
	if !ok {
		writeError(w, http.StatusBadRequest, "range must be 1h, 24h or 7d")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		stats.Report
		Tops
	}{a.b.Report(span), a.b.Tops(span)})
}

func (a *Admin) clearStats(w http.ResponseWriter, r *http.Request, c *call) {
	a.b.ClearStats()
	a.log.Info("admin: statistics cleared", "user", c.sess.user)
	w.WriteHeader(http.StatusNoContent)
}

// ---- query log ----

func (a *Admin) getQueryLog(w http.ResponseWriter, r *http.Request, c *call) {
	limit := 500
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > insight.QueryLogSize {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit must be 1 to %d", insight.QueryLogSize))
			return
		}
		limit = n
	}
	l, now := a.b.QueryLog(), a.Now()
	writeJSON(w, http.StatusOK, map[string]any{
		"state":   l.State(now),
		"entries": l.Recent(limit, r.URL.Query().Get("q"), now),
	})
}

// queryLogMinutes are the lengths an administrator can choose.
var queryLogMinutes = map[int]bool{15: true, 60: true, 360: true, 1440: true}

func (a *Admin) startQueryLog(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct {
		Minutes int  `json:"minutes"`
		FullIP  bool `json:"full_ip"`
	}
	if !decode(w, r, 1<<10, &req) {
		return
	}
	if !queryLogMinutes[req.Minutes] {
		writeError(w, http.StatusBadRequest, "minutes must be 15, 60, 360 or 1440")
		return
	}
	l, now := a.b.QueryLog(), a.Now()
	l.Start(time.Duration(req.Minutes)*time.Minute, req.FullIP, now)
	// The service log keeps a record of who turned it on and how.
	a.log.Info("admin: query log started", "user", c.sess.user, "minutes", req.Minutes, "full_ip", req.FullIP)
	writeJSON(w, http.StatusOK, map[string]any{"state": l.State(now)})
}

func (a *Admin) stopQueryLog(w http.ResponseWriter, r *http.Request, c *call) {
	a.b.QueryLog().Stop(a.Now())
	a.log.Info("admin: query log stopped and cleared", "user", c.sess.user)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) upstreams(w http.ResponseWriter, r *http.Request, c *call) {
	writeJSON(w, http.StatusOK, map[string]any{"upstreams": nonNil(a.b.Upstreams())})
}

func (a *Admin) events(w http.ResponseWriter, r *http.Request, c *call) {
	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 200 {
			writeError(w, http.StatusBadRequest, "limit must be 1 to 200")
			return
		}
		limit = n
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": nonNil(a.b.Events(limit))})
}

func (a *Admin) clearCache(w http.ResponseWriter, r *http.Request, c *call) {
	a.b.ClearCache()
	a.log.Info("admin: cache cleared", "user", c.sess.user)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) addresses(w http.ResponseWriter, r *http.Request, c *call) {
	writeJSON(w, http.StatusOK, map[string]any{"addresses": nonNil(a.b.Addresses())})
}

var qtypes = map[string]uint16{"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
	"AAAA": 28, "SRV": 33, "DS": 43, "DNSKEY": 48, "SVCB": 64, "HTTPS": 65, "CAA": 257}

func (a *Admin) lookup(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct {
		Name      string   `json:"name"`
		Type      string   `json:"type"`
		Upstreams []string `json:"upstreams"`
	}
	if !decode(w, r, 8<<10, &req) {
		return
	}
	wire, err := wireName(req.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Type == "" {
		req.Type = "A"
	}
	qt, ok := qtypes[strings.ToUpper(req.Type)]
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported record type "+req.Type)
		return
	}
	if len(req.Upstreams) > 10 {
		writeError(w, http.StatusBadRequest, "at most 10 upstreams at a time")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": strings.TrimSuffix(strings.ToLower(req.Name), ".") + ".", "type": strings.ToUpper(req.Type),
		"results": a.b.Lookup(r.Context(), wire, qt, req.Upstreams)})
}

// wireName converts a dotted name to wire format (without the final zero).
func wireName(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || len(name) > 253 {
		return "", errors.New("enter a domain name such as example.com")
	}
	var b []byte
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return "", fmt.Errorf("%q is not a valid domain name", name)
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
				return "", fmt.Errorf("%q is not a valid domain name", name)
			}
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return string(b), nil
}

// ---- configuration ----

type setting struct {
	Key     string `json:"key"`
	Value   any    `json:"value"`
	Default any    `json:"default"`
	InFile  bool   `json:"in_file"`
	Line    int    `json:"line,omitempty"`
}

func (a *Admin) getConfig(w http.ResponseWriter, r *http.Request, c *call) {
	snap := a.b.Snapshot()
	defaults := config.Defaults()
	var out []setting
	for _, k := range config.Keys() {
		v, _ := snap.Config.Get(k)
		d, _ := defaults.Get(k)
		s := setting{Key: k, Value: toJSON(v), Default: toJSON(d)}
		if e := snap.Doc.Lookup(config.SplitKey(k)); e != nil {
			s.InFile, s.Line = true, e.Line
		}
		out = append(out, s)
	}
	writeJSON(w, http.StatusOK, map[string]any{"hash": snap.Hash, "settings": out, "warnings": nonNil(snap.Warnings)})
}

// editRequest changes settings by name. Values use JSON types: strings,
// numbers, booleans and arrays of strings; durations are strings such as
// "3s" or numbers of seconds.
type editRequest struct {
	Hash  string                     `json:"hash"`
	Set   map[string]json.RawMessage `json:"set"`
	Unset []string                   `json:"unset"`
}

type change struct {
	Key  string `json:"key"`
	From any    `json:"from"`
	To   any    `json:"to"`
}

// editResult is what a preview or a change returns.
type editResult struct {
	Hash            string     `json:"hash"`
	Changes         []change   `json:"changes"`
	Diff            []diffLine `json:"diff"`
	Warnings        []string   `json:"warnings"`
	RestartRequired []string   `json:"restart_required"`
}

type problem struct {
	Line    int    `json:"line,omitempty"`
	Key     string `json:"key,omitempty"`
	Message string `json:"message"`
}

// applyEdits returns the new file contents, or writes the error response.
func (a *Admin) applyEdits(w http.ResponseWriter, snap *config.Snapshot, req *editRequest) ([]byte, bool) {
	if req.Hash != snap.Hash {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the configuration changed since you loaded it; reload and try again", "hash": snap.Hash})
		return nil, false
	}
	if len(req.Set) == 0 && len(req.Unset) == 0 {
		writeError(w, http.StatusBadRequest, "nothing to change: give set and/or unset")
		return nil, false
	}
	known := map[string]bool{}
	for _, k := range config.Keys() {
		known[k] = true
	}
	doc := snap.Doc
	keys := make([]string, 0, len(req.Set))
	for k := range req.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic output
	for _, k := range keys {
		if !known[k] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown setting " + k, "problems": []problem{{Key: k, Message: "unknown setting"}}})
			return nil, false
		}
		v, err := fromJSON(req.Set[k])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": k + ": " + err.Error(), "problems": []problem{{Key: k, Message: err.Error()}}})
			return nil, false
		}
		table, key := config.SplitKey(k)
		src, err := doc.Set(table, key, v)
		if err == nil {
			doc, err = config.Parse(src)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return nil, false
		}
	}
	for _, k := range req.Unset {
		if !known[k] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown setting " + k})
			return nil, false
		}
		table, key := config.SplitKey(k)
		src, err := doc.Delete(table, key)
		if err == nil {
			doc, err = config.Parse(src)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return nil, false
		}
	}
	return doc.Src, true
}

// check validates src and describes how it differs from the running file.
func (a *Admin) check(w http.ResponseWriter, snap *config.Snapshot, src []byte) (*editResult, bool) {
	cfg, _, warns, err := config.Load(src)
	if err != nil {
		writeInvalid(w, err)
		return nil, false
	}
	res := &editResult{Hash: config.HashOf(src), Diff: lineDiff(snap.Doc.Src, src), Warnings: nonNil(warns), Changes: []change{}, RestartRequired: []string{}}
	for _, k := range config.Keys() {
		before, _ := snap.Config.Get(k)
		after, _ := cfg.Get(k)
		if config.Format(before) != config.Format(after) {
			res.Changes = append(res.Changes, change{Key: k, From: toJSON(before), To: toJSON(after)})
			if k == "server.data_dir" {
				res.RestartRequired = append(res.RestartRequired, k)
			}
		}
	}
	return res, true
}

func writeInvalid(w http.ResponseWriter, err error) {
	var probs []problem
	var es config.Errors
	var pe *config.ParseError
	switch {
	case errors.As(err, &es):
		for _, e := range es {
			probs = append(probs, problem{Line: e.Line, Key: e.Key, Message: e.Msg})
		}
	case errors.As(err, &pe):
		probs = append(probs, problem{Line: pe.Line, Message: pe.Msg})
	default:
		probs = append(probs, problem{Message: err.Error()})
	}
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "the configuration is not valid", "problems": probs})
}

func (a *Admin) previewConfig(w http.ResponseWriter, r *http.Request, c *call) {
	var req editRequest
	if !decode(w, r, 256<<10, &req) {
		return
	}
	snap := a.b.Snapshot()
	src, ok := a.applyEdits(w, snap, &req)
	if !ok {
		return
	}
	if res, ok := a.check(w, snap, src); ok {
		writeJSON(w, http.StatusOK, res)
	}
}

func (a *Admin) patchConfig(w http.ResponseWriter, r *http.Request, c *call) {
	var req editRequest
	if !decode(w, r, 256<<10, &req) {
		return
	}
	snap := a.b.Snapshot()
	src, ok := a.applyEdits(w, snap, &req)
	if ok {
		a.write(w, c, snap, src, "settings changed")
	}
}

// write validates, saves and applies src.
func (a *Admin) write(w http.ResponseWriter, c *call, snap *config.Snapshot, src []byte, what string) {
	res, ok := a.check(w, snap, src)
	if !ok {
		return
	}
	if len(res.Changes) == 0 && string(src) == string(snap.Doc.Src) {
		writeJSON(w, http.StatusOK, res)
		return
	}
	nsnap, err := a.b.ApplyConfig(src, snap.Hash)
	switch {
	case errors.Is(err, config.ErrConflict):
		cur := a.b.Snapshot()
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "hash": cur.Hash})
		return
	case err != nil:
		var es config.Errors
		var pe *config.ParseError
		if errors.As(err, &es) || errors.As(err, &pe) {
			writeInvalid(w, err)
			return
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "could not apply the change, so the previous configuration was kept: " + err.Error(), "reverted": true})
		return
	}
	res.Hash = nsnap.Hash
	keys := make([]string, len(res.Changes))
	for i, ch := range res.Changes {
		keys[i] = ch.Key
	}
	a.log.Info("admin: "+what, "user", c.sess.user, "keys", strings.Join(keys, ", "))
	writeJSON(w, http.StatusOK, res)
}

func (a *Admin) getConfigFile(w http.ResponseWriter, r *http.Request, c *call) {
	snap := a.b.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"hash": snap.Hash, "content": string(snap.Doc.Src)})
}

func (a *Admin) putConfigFile(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct {
		Hash    string `json:"hash"`
		Content string `json:"content"`
		Preview bool   `json:"preview"`
	}
	if !decode(w, r, 1<<20+4<<10, &req) {
		return
	}
	snap := a.b.Snapshot()
	if req.Hash != snap.Hash {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the configuration changed since you loaded it; reload and try again", "hash": snap.Hash})
		return
	}
	if req.Preview {
		if res, ok := a.check(w, snap, []byte(req.Content)); ok {
			writeJSON(w, http.StatusOK, res)
		}
		return
	}
	a.write(w, c, snap, []byte(req.Content), "configuration file edited")
}

func (a *Admin) listHistory(w http.ResponseWriter, r *http.Request, c *call) {
	list, err := a.b.ConfigHistory()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type item struct {
		Name  string    `json:"name"`
		Saved time.Time `json:"saved"`
	}
	out := []item{}
	for _, h := range list {
		out = append(out, item{h.Name, h.Saved.UTC()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

func (a *Admin) historyFile(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	src, err := a.b.ConfigHistoryFile(r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such saved version")
		return nil, false
	}
	return src, true
}

func (a *Admin) getHistory(w http.ResponseWriter, r *http.Request, c *call) {
	src, ok := a.historyFile(w, r)
	if !ok {
		return
	}
	snap := a.b.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"name": r.PathValue("name"), "content": string(src), "diff": lineDiff(snap.Doc.Src, src)})
}

func (a *Admin) restoreHistory(w http.ResponseWriter, r *http.Request, c *call) {
	var req struct{ Hash string }
	if !decode(w, r, 1<<10, &req) {
		return
	}
	src, ok := a.historyFile(w, r)
	if !ok {
		return
	}
	snap := a.b.Snapshot()
	if req.Hash != snap.Hash {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the configuration changed since you loaded it; reload and try again", "hash": snap.Hash})
		return
	}
	a.write(w, c, snap, src, "previous configuration restored ("+r.PathValue("name")+")")
}

// ---- JSON <-> TOML values ----

func toJSON(v config.Value) any {
	switch v.Kind {
	case config.String:
		return v.Str
	case config.Int:
		return v.Int
	case config.Float:
		return v.Float
	case config.Bool:
		return v.Bool
	case config.Array:
		out := make([]any, len(v.Arr))
		for i, it := range v.Arr {
			out[i] = toJSON(it)
		}
		return out
	}
	return nil
}

func fromJSON(raw json.RawMessage) (config.Value, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return config.Value{}, err
	}
	return valueOf(x, 0)
}

func valueOf(x any, depth int) (config.Value, error) {
	switch t := x.(type) {
	case string:
		return config.Str(t), nil
	case bool:
		return config.BoolV(t), nil
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return config.IntV(n), nil
		}
		f, err := t.Float64()
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return config.Value{}, fmt.Errorf("invalid number %s", t)
		}
		return config.FloatV(f), nil
	case []any:
		if depth > 0 {
			return config.Value{}, errors.New("nested arrays are not supported")
		}
		out := config.Value{Kind: config.Array}
		for _, it := range t {
			v, err := valueOf(it, depth+1)
			if err != nil {
				return config.Value{}, err
			}
			if len(out.Arr) > 0 && out.Arr[0].Kind != v.Kind {
				return config.Value{}, errors.New("array items must all have the same type")
			}
			out.Arr = append(out.Arr, v)
		}
		return out, nil
	case nil:
		return config.Value{}, errors.New("null is not a value; use unset to remove a setting")
	}
	return config.Value{}, errors.New("objects are not supported")
}
