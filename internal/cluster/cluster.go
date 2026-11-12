// Package cluster lets several DNSNova nodes share one configuration.
//
// One node is the primary: it keeps the configuration that the
// administrator edits. Followers ask it every few seconds whether that
// configuration changed, and tell it how they are doing in the same
// request. The primary needs no list of followers; a new node only needs
// the primary's address and the cluster key.
//
// Every request and answer is sealed with AES-256-GCM under keys derived
// from the cluster key (a file under data_dir/secrets, never part of the
// configuration): nobody without the key can read the configuration, send
// a node a configuration, or pose as a node. A request carries the time
// and a random challenge; the answer must carry the same challenge, so an
// old answer cannot be played back to a follower. Plain HTTP is therefore
// enough on the cluster port, without certificates.
package cluster

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/harryheros/dnsnova/internal/alert"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Path is the HTTP path of the sync exchange.
const Path = "/cluster/v1/sync"

// MaxSkew is how far apart the clocks of two nodes may be.
const MaxSkew = 5 * time.Minute

const maxBody = 2 << 20 // a configuration is at most 1 MiB

// Key is the cluster's shared secret.
type Key [32]byte

// LoadKey reads the key from path. With create, a missing file is made
// with a new random key (mode 0600) and created is true.
func LoadKey(path string, create bool) (k Key, created bool, err error) {
	b, err := os.ReadFile(path)
	if err == nil {
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != len(k) {
			return k, false, fmt.Errorf("%s: want %d bytes in hex (as written by dnsnova)", path, len(k))
		}
		copy(k[:], raw)
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return k, false, err
	}
	if _, err := rand.Read(k[:]); err != nil {
		return k, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return k, false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(k[:])+"\n"), 0o600); err != nil {
		return k, false, err
	}
	return k, true, os.Rename(tmp, path)
}

// box seals requests and answers with separate keys, so an answer can
// never pass for a request or the other way round.
type box struct{ req, resp cipher.AEAD }

func newBox(k Key) box {
	derive := func(label string) cipher.AEAD {
		m := hmac.New(sha256.New, k[:])
		m.Write([]byte("dnsnova cluster v1 " + label))
		block, _ := aes.NewCipher(m.Sum(nil))
		aead, _ := cipher.NewGCM(block)
		return aead
	}
	return box{req: derive("request"), resp: derive("response")}
}

func seal(a cipher.AEAD, v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize(), a.NonceSize()+len(plain)+a.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plain, nil), nil
}

// ErrAuth means a message was not sealed with this cluster's key.
var ErrAuth = errors.New("cluster: not sealed with this cluster's key")

func open(a cipher.AEAD, b []byte, v any) error {
	if len(b) < a.NonceSize()+a.Overhead() {
		return ErrAuth
	}
	plain, err := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], nil)
	if err != nil {
		return ErrAuth
	}
	return json.Unmarshal(plain, v)
}

// Report is what a follower tells the primary with each sync.
type Report struct {
	Node      string `json:"node"`
	Region    string `json:"region,omitempty"`
	Version   string `json:"version"`
	Time      int64  `json:"time"` // unix seconds, when sent
	Challenge []byte `json:"challenge"`
	// Have is the hash of the shared configuration the node runs.
	Have string `json:"have,omitempty"`
	// ConfigError: the last shared configuration could not be applied here.
	ConfigError string `json:"config_error,omitempty"`
	// Overrides are the settings the node's own file sets.
	Overrides []string `json:"overrides,omitempty"`
	Status    string   `json:"status"`            // ok, unhealthy or setup, as /healthz
	Anycast   string   `json:"anycast,omitempty"` // announced or withdrawn, when anycast is on
	CertUntil int64    `json:"cert_until,omitempty"`
	Uptime    int64    `json:"uptime"`   // seconds
	Interval  int64    `json:"interval"` // seconds between syncs
	// Alerts are the node's alerts that have fired: the primary sends
	// the notifications for the whole cluster.
	Alerts []alert.Condition `json:"alerts,omitempty"`
}

// Reply is the primary's answer.
type Reply struct {
	Challenge []byte `json:"challenge"`
	Time      int64  `json:"time"`
	Primary   string `json:"primary"` // the primary's node name
	Hash      string `json:"hash"`    // of the shared configuration
	// Config is the shared configuration, left out when the follower
	// already has it.
	Config string `json:"config,omitempty"`
}

// Primary answers followers.
type Primary struct {
	Name string
	// Shared returns the configuration to hand out (already without the
	// node-local tables) and its hash.
	Shared func() (src []byte, hash string)
	// OnReport receives every authenticated report and the address it
	// came from.
	OnReport func(r Report, from netip.Addr)
	// OnReject is told about requests that failed authentication.
	OnReject func(from netip.Addr, err error)
	Now      func() time.Time
	box      box
}

// NewPrimary returns a primary using key.
func NewPrimary(key Key, name string) *Primary {
	return &Primary{Name: name, box: newBox(key), Now: time.Now}
}

func (p *Primary) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	from := netip.Addr{}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		from = ap.Addr().Unmap()
	}
	if r.URL.Path != Path || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var rep Report
	if err := open(p.box.req, body, &rep); err != nil {
		p.reject(from, err)
		http.Error(w, "forbidden", http.StatusForbidden) // nothing more for a stranger
		return
	}
	now := p.Now()
	if d := now.Sub(time.Unix(rep.Time, 0)); d > MaxSkew || d < -MaxSkew || len(rep.Challenge) < 16 || rep.Node == "" {
		p.reject(from, fmt.Errorf("node %q: clock %s apart, or an incomplete request", rep.Node, d.Round(time.Second)))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if p.OnReport != nil {
		p.OnReport(rep, from)
	}
	src, hash := p.Shared()
	reply := Reply{Challenge: rep.Challenge, Time: now.Unix(), Primary: p.Name, Hash: hash}
	if rep.Have != hash {
		reply.Config = string(src)
	}
	out, err := seal(p.box.resp, reply)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(out)
}

func (p *Primary) reject(from netip.Addr, err error) {
	if p.OnReject != nil {
		p.OnReject(from, err)
	}
}

// Follower syncs with a primary.
type Follower struct {
	Addr   string // the primary's host:port
	Client *http.Client
	Now    func() time.Time
	box    box
}

// NewFollower returns a follower of the primary at addr.
func NewFollower(key Key, addr string) *Follower {
	return &Follower{Addr: addr, Client: &http.Client{Timeout: 10 * time.Second}, Now: time.Now, box: newBox(key)}
}

// Sync sends rep (its time and challenge are filled in) and returns the
// primary's answer, after checking that it answers this very request.
func (f *Follower) Sync(ctx context.Context, rep Report) (*Reply, error) {
	rep.Time = f.Now().Unix()
	rep.Challenge = make([]byte, 16)
	if _, err := rand.Read(rep.Challenge); err != nil {
		return nil, err
	}
	body, err := seal(f.box.req, rep)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+f.Addr+Path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("the primary refused this node: is the cluster key the same on both, and are their clocks right?")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("primary answered %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	var reply Reply
	if err := open(f.box.resp, b, &reply); err != nil {
		return nil, err
	}
	if !bytes.Equal(reply.Challenge, rep.Challenge) {
		return nil, errors.New("cluster: the answer is not for this request")
	}
	if d := f.Now().Sub(time.Unix(reply.Time, 0)); d > MaxSkew || d < -MaxSkew {
		return nil, fmt.Errorf("cluster: the primary's clock is %s apart", d.Round(time.Second))
	}
	return &reply, nil
}
