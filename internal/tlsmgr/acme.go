package tlsmgr

// A small ACME (RFC 8555) client written against the standard library: ES256
// account keys, orders for DNS names and IP addresses (RFC 8738), the http-01
// and tls-alpn-01 (RFC 8737) challenges, and certificate profiles (needed for
// Let's Encrypt's short-lived IP address certificates).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Let's Encrypt directories.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

var b64 = base64.RawURLEncoding

type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	Meta       struct {
		TermsOfService string            `json:"termsOfService"`
		Profiles       map[string]string `json:"profiles"`
	} `json:"meta"`
}

// Identifier is a name to certify: type "dns" or "ip".
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type problem struct {
	Type        string    `json:"type"`
	Detail      string    `json:"detail"`
	Subproblems []problem `json:"subproblems"`
}

func (p *problem) Error() string {
	msg := strings.TrimPrefix(p.Type, "urn:ietf:params:acme:error:") + ": " + p.Detail
	for _, s := range p.Subproblems {
		msg += "; " + s.Detail
	}
	return msg
}

type order struct {
	Status         string       `json:"status"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
	Error          *problem     `json:"error"`
}

type authorization struct {
	Status     string      `json:"status"`
	Identifier Identifier  `json:"identifier"`
	Challenges []challenge `json:"challenges"`
}

type challenge struct {
	Type   string   `json:"type"`
	URL    string   `json:"url"`
	Token  string   `json:"token"`
	Status string   `json:"status"`
	Error  *problem `json:"error"`
}

// Solver makes a challenge answerable and removes it afterwards.
type Solver interface {
	Present(chType string, id Identifier, token, keyAuth string) error
	CleanUp(chType string, id Identifier, token string)
}

// Client talks to one ACME server with one account key.
type Client struct {
	Directory string
	Key       *ecdsa.PrivateKey
	HTTP      *http.Client
	KID       string // account URL, filled in by Register

	dir    *directory
	mu     sync.Mutex
	nonces []string
	poll   time.Duration // poll interval (tests shorten it)
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) discover(ctx context.Context) error {
	if c.dir != nil {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.Directory, nil)
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("acme directory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acme directory: http %d", resp.StatusCode)
	}
	var d directory
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return fmt.Errorf("acme directory: %w", err)
	}
	if d.NewNonce == "" || d.NewAccount == "" || d.NewOrder == "" {
		return errors.New("acme directory is incomplete")
	}
	c.dir = &d
	return nil
}

// SupportsProfile reports whether the server advertises a profile.
func (c *Client) SupportsProfile(ctx context.Context, name string) (bool, error) {
	if err := c.discover(ctx); err != nil {
		return false, err
	}
	_, ok := c.dir.Meta.Profiles[name]
	return ok, nil
}

func (c *Client) nonce(ctx context.Context) (string, error) {
	c.mu.Lock()
	if n := len(c.nonces); n > 0 {
		v := c.nonces[n-1]
		c.nonces = c.nonces[:n-1]
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, c.dir.NewNonce, nil)
	resp, err := c.client().Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if v := resp.Header.Get("Replay-Nonce"); v != "" {
		return v, nil
	}
	return "", errors.New("acme: no nonce")
}

func (c *Client) saveNonce(h http.Header) {
	if v := h.Get("Replay-Nonce"); v != "" {
		c.mu.Lock()
		if len(c.nonces) < 8 {
			c.nonces = append(c.nonces, v)
		}
		c.mu.Unlock()
	}
}

// JWK returns the public account key as a JSON Web Key, members in the
// lexicographic order required for the thumbprint (RFC 7638).
func JWK(k *ecdsa.PublicKey) string {
	x, y := k.X.FillBytes(make([]byte, 32)), k.Y.FillBytes(make([]byte, 32))
	return fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, b64.EncodeToString(x), b64.EncodeToString(y))
}

// Thumbprint is the RFC 7638 thumbprint used in key authorizations.
func Thumbprint(k *ecdsa.PublicKey) string {
	sum := sha256.Sum256([]byte(JWK(k)))
	return b64.EncodeToString(sum[:])
}

// sign builds a flattened JWS. payload nil means POST-as-GET.
func (c *Client) sign(url, nonce string, payload any) ([]byte, error) {
	var prot string
	if c.KID == "" {
		prot = fmt.Sprintf(`{"alg":"ES256","jwk":%s,"nonce":%q,"url":%q}`, JWK(&c.Key.PublicKey), nonce, url)
	} else {
		prot = fmt.Sprintf(`{"alg":"ES256","kid":%q,"nonce":%q,"url":%q}`, c.KID, nonce, url)
	}
	p64 := ""
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		p64 = b64.EncodeToString(raw)
	}
	input := b64.EncodeToString([]byte(prot)) + "." + p64
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, c.Key, sum[:])
	if err != nil {
		return nil, err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return json.Marshal(map[string]string{
		"protected": b64.EncodeToString([]byte(prot)),
		"payload":   p64,
		"signature": b64.EncodeToString(sig),
	})
}

// post sends a signed request and decodes a JSON answer into out (if not
// nil). A badNonce error is retried once, as RFC 8555 recommends.
func (c *Client) post(ctx context.Context, url string, payload, out any) (http.Header, []byte, error) {
	for attempt := 0; ; attempt++ {
		n, err := c.nonce(ctx)
		if err != nil {
			return nil, nil, err
		}
		body, err := c.sign(url, n, payload)
		if err != nil {
			return nil, nil, err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("User-Agent", "dnsnova")
		resp, err := c.client().Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		c.saveNonce(resp.Header)
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode >= 400 {
			p := &problem{}
			if json.Unmarshal(data, p) != nil || p.Type == "" {
				return nil, nil, fmt.Errorf("acme: http %d", resp.StatusCode)
			}
			if strings.HasSuffix(p.Type, ":badNonce") && attempt == 0 {
				continue
			}
			return nil, nil, p
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				return nil, nil, fmt.Errorf("acme: %w", err)
			}
		}
		return resp.Header, data, nil
	}
}

// Register creates the account, or finds the existing one for this key.
func (c *Client) Register(ctx context.Context, email string) error {
	if err := c.discover(ctx); err != nil {
		return err
	}
	if c.KID != "" {
		return nil
	}
	req := map[string]any{"termsOfServiceAgreed": true}
	if email != "" {
		req["contact"] = []string{"mailto:" + email}
	}
	h, _, err := c.post(ctx, c.dir.NewAccount, req, nil)
	if err != nil {
		return fmt.Errorf("acme account: %w", err)
	}
	if c.KID = h.Get("Location"); c.KID == "" {
		return errors.New("acme account: no account URL")
	}
	return nil
}

// Obtain orders a certificate for ids and answers each challenge with solver,
// preferring the challenge types in prefer, in order. It returns the PEM
// chain and its private key.
func (c *Client) Obtain(ctx context.Context, ids []Identifier, profile string, prefer []string, solver Solver) ([]byte, *ecdsa.PrivateKey, error) {
	if err := c.discover(ctx); err != nil {
		return nil, nil, err
	}
	req := map[string]any{"identifiers": ids}
	if profile != "" {
		req["profile"] = profile
	}
	var o order
	h, _, err := c.post(ctx, c.dir.NewOrder, req, &o)
	if err != nil {
		return nil, nil, fmt.Errorf("acme order: %w", err)
	}
	orderURL := h.Get("Location")

	for _, az := range o.Authorizations {
		if err := c.authorize(ctx, az, prefer, solver); err != nil {
			return nil, nil, err
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := makeCSR(key, ids)
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := c.post(ctx, o.Finalize, map[string]string{"csr": b64.EncodeToString(csr)}, &o); err != nil {
		return nil, nil, fmt.Errorf("acme finalize: %w", err)
	}
	for o.Status != "valid" {
		if o.Status == "invalid" {
			if o.Error != nil {
				return nil, nil, fmt.Errorf("acme order failed: %w", o.Error)
			}
			return nil, nil, errors.New("acme order failed")
		}
		if err := c.wait(ctx, nil); err != nil {
			return nil, nil, err
		}
		if _, _, err := c.post(ctx, orderURL, nil, &o); err != nil {
			return nil, nil, fmt.Errorf("acme order: %w", err)
		}
	}
	_, pem, err := c.post(ctx, o.Certificate, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("acme certificate: %w", err)
	}
	return pem, key, nil
}

func (c *Client) authorize(ctx context.Context, url string, prefer []string, solver Solver) error {
	var az authorization
	if _, _, err := c.post(ctx, url, nil, &az); err != nil {
		return fmt.Errorf("acme authorization: %w", err)
	}
	if az.Status == "valid" {
		return nil
	}
	var ch *challenge
	for _, want := range prefer {
		for i := range az.Challenges {
			if az.Challenges[i].Type == want {
				ch = &az.Challenges[i]
				break
			}
		}
		if ch != nil {
			break
		}
	}
	if ch == nil {
		return fmt.Errorf("acme: %s offers none of the challenges %v", az.Identifier.Value, prefer)
	}
	keyAuth := ch.Token + "." + Thumbprint(&c.Key.PublicKey)
	if err := solver.Present(ch.Type, az.Identifier, ch.Token, keyAuth); err != nil {
		return err
	}
	defer solver.CleanUp(ch.Type, az.Identifier, ch.Token)
	if _, _, err := c.post(ctx, ch.URL, struct{}{}, nil); err != nil {
		return fmt.Errorf("acme challenge: %w", err)
	}
	for {
		if err := c.wait(ctx, nil); err != nil {
			return err
		}
		if _, _, err := c.post(ctx, url, nil, &az); err != nil {
			return fmt.Errorf("acme authorization: %w", err)
		}
		switch az.Status {
		case "valid":
			return nil
		case "invalid", "deactivated", "expired", "revoked":
			for _, c := range az.Challenges {
				if c.Error != nil {
					return fmt.Errorf("acme: validation of %s failed: %w", az.Identifier.Value, c.Error)
				}
			}
			return fmt.Errorf("acme: validation of %s failed", az.Identifier.Value)
		}
	}
}

func (c *Client) wait(ctx context.Context, h http.Header) error {
	d := c.poll
	if d == 0 {
		d = 2 * time.Second
	}
	if h != nil {
		if s, err := strconv.Atoi(h.Get("Retry-After")); err == nil && s > 0 && s < 60 {
			d = time.Duration(s) * time.Second
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func makeCSR(key *ecdsa.PrivateKey, ids []Identifier) ([]byte, error) {
	tmpl := &x509.CertificateRequest{}
	for _, id := range ids {
		switch id.Type {
		case "dns":
			tmpl.DNSNames = append(tmpl.DNSNames, id.Value)
		case "ip":
			a, err := netip.ParseAddr(id.Value)
			if err != nil {
				return nil, err
			}
			tmpl.IPAddresses = append(tmpl.IPAddresses, a.AsSlice())
		}
	}
	if len(tmpl.DNSNames) > 0 {
		tmpl.Subject = pkix.Name{CommonName: tmpl.DNSNames[0]}
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

// ---- tls-alpn-01 ----

var oidACMEIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 1, 31}

// ALPNChallengeCert builds the self-signed certificate that answers a
// tls-alpn-01 challenge for id.
func ALPNChallengeCert(id Identifier, keyAuth string) (*tlsCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(keyAuth))
	ext, err := asn1OctetString(sum[:])
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "dnsnova acme challenge"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidACMEIdentifier, Critical: true, Value: ext}},
	}
	if id.Type == "ip" {
		a, err := netip.ParseAddr(id.Value)
		if err != nil {
			return nil, err
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, a.AsSlice())
	} else {
		tmpl.DNSNames = []string{id.Value}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tlsCert{der: der, key: key}, nil
}

type tlsCert struct {
	der []byte
	key crypto.Signer
}

// ChallengeServerName is the TLS server name a CA sends when validating id
// with tls-alpn-01: the name itself, or for an IP address its reverse
// mapping name (RFC 8738 section 6).
func ChallengeServerName(id Identifier) string {
	if id.Type != "ip" {
		return strings.ToLower(id.Value)
	}
	a, err := netip.ParseAddr(id.Value)
	if err != nil {
		return ""
	}
	return ReverseName(a)
}

// ReverseName returns the in-addr.arpa or ip6.arpa name of a, without the
// trailing dot.
func ReverseName(a netip.Addr) string {
	a = a.Unmap()
	b := a.AsSlice()
	var parts []string
	if a.Is4() {
		for i := 3; i >= 0; i-- {
			parts = append(parts, strconv.Itoa(int(b[i])))
		}
		return strings.Join(parts, ".") + ".in-addr.arpa"
	}
	const hex = "0123456789abcdef"
	for i := 15; i >= 0; i-- {
		parts = append(parts, string(hex[b[i]&0xF]), string(hex[b[i]>>4]))
	}
	return strings.Join(parts, ".") + ".ip6.arpa"
}

// asn1OctetString encodes b as a DER OCTET STRING.
func asn1OctetString(b []byte) ([]byte, error) {
	if len(b) > 127 {
		return nil, errors.New("too long")
	}
	return append([]byte{0x04, byte(len(b))}, b...), nil
}
