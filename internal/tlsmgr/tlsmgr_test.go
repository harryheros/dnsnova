package tlsmgr

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- a fake ACME CA that really validates challenges ----

type fakeCA struct {
	t        *testing.T
	srv      *httptest.Server
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	lifetime time.Duration
	profiles map[string]string
	target   string // host:port the CA connects to for validation

	mu       sync.Mutex
	nonces   map[string]bool
	accounts map[string]*ecdsa.PublicKey
	orders   map[string]*fOrder
	authzs   map[string]*fAuthz
	chals    map[string]*fChal
	issued   int
	n        int
}

type fOrder struct {
	id      string
	ids     []Identifier
	authz   []string
	status  string
	certPEM []byte
	account string
}

type fAuthz struct {
	id     Identifier
	status string
	chals  []string
}

type fChal struct {
	typ, token, status, authz, account string
}

func newFakeCA(t *testing.T) *fakeCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake ACME CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	ca := &fakeCA{t: t, key: key, cert: cert, lifetime: 160 * time.Hour,
		profiles: map[string]string{"classic": "", "shortlived": ""},
		nonces:   map[string]bool{}, accounts: map[string]*ecdsa.PublicKey{},
		orders: map[string]*fOrder{}, authzs: map[string]*fAuthz{}, chals: map[string]*fChal{}}
	ca.srv = httptest.NewServer(http.HandlerFunc(ca.handle))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) url(p string) string { return ca.srv.URL + p }

func (ca *fakeCA) nextID() string { ca.n++; return fmt.Sprint(ca.n) }

func (ca *fakeCA) nonce(w http.ResponseWriter) {
	n := fmt.Sprintf("nonce-%d-%d", time.Now().UnixNano(), ca.n)
	ca.n++
	ca.nonces[n] = true
	w.Header().Set("Replay-Nonce", n)
}

func (ca *fakeCA) fail(w http.ResponseWriter, code int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail})
}

func (ca *fakeCA) handle(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	switch {
	case r.URL.Path == "/dir":
		json.NewEncoder(w).Encode(map[string]any{
			"newNonce": ca.url("/nonce"), "newAccount": ca.url("/acct"), "newOrder": ca.url("/order"),
			"meta": map[string]any{"profiles": ca.profiles},
		})
		return
	case r.URL.Path == "/nonce":
		ca.nonce(w)
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/jose+json" {
		ca.fail(w, 405, "malformed", "POST with application/jose+json required")
		return
	}
	payload, kid, jwkKey, ok := ca.verify(w, r)
	ca.nonce(w)
	if !ok {
		return
	}
	path := r.URL.Path
	switch {
	case path == "/acct":
		if jwkKey == nil {
			ca.fail(w, 400, "malformed", "newAccount needs jwk")
			return
		}
		var req struct {
			Agreed bool `json:"termsOfServiceAgreed"`
		}
		json.Unmarshal(payload, &req)
		if !req.Agreed {
			ca.fail(w, 400, "malformed", "terms not agreed")
			return
		}
		for id, k := range ca.accounts {
			if k.Equal(jwkKey) {
				w.Header().Set("Location", id)
				w.WriteHeader(200)
				return
			}
		}
		id := ca.url("/acct/" + ca.nextID())
		ca.accounts[id] = jwkKey
		w.Header().Set("Location", id)
		w.WriteHeader(201)
		w.Write([]byte(`{"status":"valid"}`))
	case path == "/order":
		var req struct {
			Identifiers []Identifier `json:"identifiers"`
			Profile     string       `json:"profile"`
		}
		json.Unmarshal(payload, &req)
		if _, ok := ca.profiles[req.Profile]; req.Profile != "" && !ok {
			ca.fail(w, 400, "invalidProfile", "unknown profile")
			return
		}
		for _, id := range req.Identifiers {
			if id.Type == "ip" && req.Profile != "shortlived" {
				ca.fail(w, 400, "rejectedIdentifier", "IP addresses need the shortlived profile")
				return
			}
		}
		o := &fOrder{id: ca.nextID(), ids: req.Identifiers, status: "pending", account: kid}
		for _, id := range req.Identifiers {
			az := ca.nextID()
			a := &fAuthz{id: id, status: "pending"}
			for _, typ := range []string{HTTP01, TLSALPN01} {
				cid := ca.nextID()
				ca.chals[cid] = &fChal{typ: typ, token: "tok" + cid + strings.Repeat("x", 20), status: "pending", authz: az, account: kid}
				a.chals = append(a.chals, cid)
			}
			ca.authzs[az] = a
			o.authz = append(o.authz, az)
		}
		ca.orders[o.id] = o
		w.Header().Set("Location", ca.url("/order/"+o.id))
		w.WriteHeader(201)
		ca.writeOrder(w, o)
	case strings.HasPrefix(path, "/order/"):
		ca.writeOrder(w, ca.orders[strings.TrimPrefix(path, "/order/")])
	case strings.HasPrefix(path, "/authz/"):
		ca.writeAuthz(w, strings.TrimPrefix(path, "/authz/"))
	case strings.HasPrefix(path, "/chal/"):
		cid := strings.TrimPrefix(path, "/chal/")
		ch := ca.chals[cid]
		a := ca.authzs[ch.authz]
		keyAuth := ch.token + "." + Thumbprint(ca.accounts[ch.account])
		ca.mu.Unlock()
		err := ca.validate(ch.typ, a.id, ch.token, keyAuth)
		ca.mu.Lock()
		if err != nil {
			ch.status, a.status = "invalid", "invalid"
			ca.t.Logf("fake CA: validation failed: %v", err)
		} else {
			ch.status, a.status = "valid", "valid"
		}
		json.NewEncoder(w).Encode(map[string]string{"type": ch.typ, "status": "processing", "url": ca.url("/chal/" + cid)})
	case strings.HasPrefix(path, "/finalize/"):
		o := ca.orders[strings.TrimPrefix(path, "/finalize/")]
		for _, az := range o.authz {
			if ca.authzs[az].status != "valid" {
				ca.fail(w, 403, "orderNotReady", "authorizations pending")
				return
			}
		}
		var req struct {
			CSR string `json:"csr"`
		}
		json.Unmarshal(payload, &req)
		der, _ := b64.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || csr.CheckSignature() != nil {
			ca.fail(w, 400, "badCSR", "bad csr")
			return
		}
		if len(csr.DNSNames)+len(csr.IPAddresses) != len(o.ids) {
			ca.fail(w, 400, "badCSR", "names do not match the order")
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(100 + ca.issued)), Subject: csr.Subject,
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(ca.lifetime),
			DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leaf, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
		o.certPEM = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
		o.status = "valid"
		ca.issued++
		ca.writeOrder(w, o)
	case strings.HasPrefix(path, "/cert/"):
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(ca.orders[strings.TrimPrefix(path, "/cert/")].certPEM)
	default:
		ca.fail(w, 404, "malformed", "not found")
	}
}

func (ca *fakeCA) writeOrder(w http.ResponseWriter, o *fOrder) {
	st := o.status
	if st == "pending" {
		ready := true
		for _, az := range o.authz {
			if ca.authzs[az].status != "valid" {
				ready = false
			}
		}
		if ready {
			st = "ready"
		}
	}
	m := map[string]any{"status": st, "identifiers": o.ids, "finalize": ca.url("/finalize/" + o.id)}
	var azs []string
	for _, a := range o.authz {
		azs = append(azs, ca.url("/authz/"+a))
	}
	m["authorizations"] = azs
	if o.status == "valid" {
		m["certificate"] = ca.url("/cert/" + o.id)
	}
	json.NewEncoder(w).Encode(m)
}

func (ca *fakeCA) writeAuthz(w http.ResponseWriter, id string) {
	a := ca.authzs[id]
	var chs []map[string]string
	for _, cid := range a.chals {
		c := ca.chals[cid]
		chs = append(chs, map[string]string{"type": c.typ, "url": ca.url("/chal/" + cid), "token": c.token, "status": c.status})
	}
	json.NewEncoder(w).Encode(map[string]any{"status": a.status, "identifier": a.id, "challenges": chs})
}

// verify checks the JWS: signature, nonce, url and account.
func (ca *fakeCA) verify(w http.ResponseWriter, r *http.Request) (payload []byte, kid string, jwk *ecdsa.PublicKey, ok bool) {
	var jws struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		ca.fail(w, 400, "malformed", "bad jws")
		return
	}
	rawProt, _ := b64.DecodeString(jws.Protected)
	var prot struct {
		Alg, Nonce, URL, KID string
		JWK                  *struct{ Crv, Kty, X, Y string }
	}
	json.Unmarshal(rawProt, &prot)
	if !ca.nonces[prot.Nonce] {
		ca.fail(w, 400, "badNonce", "unknown nonce")
		return
	}
	delete(ca.nonces, prot.Nonce)
	if prot.URL != ca.url(r.URL.Path) || prot.Alg != "ES256" {
		ca.fail(w, 400, "malformed", "url or alg mismatch")
		return
	}
	var key *ecdsa.PublicKey
	if prot.JWK != nil {
		x, _ := b64.DecodeString(prot.JWK.X)
		y, _ := b64.DecodeString(prot.JWK.Y)
		key = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		jwk = key
	} else if key = ca.accounts[prot.KID]; key == nil {
		ca.fail(w, 400, "accountDoesNotExist", "unknown kid")
		return
	}
	sig, _ := b64.DecodeString(jws.Signature)
	sum := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	if len(sig) != 64 || !ecdsa.Verify(key, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		ca.fail(w, 400, "malformed", "bad signature")
		return
	}
	payload, _ = b64.DecodeString(jws.Payload)
	return payload, prot.KID, jwk, true
}

func (ca *fakeCA) validate(typ string, id Identifier, token, keyAuth string) error {
	switch typ {
	case HTTP01:
		resp, err := http.Get("http://" + ca.target + "/.well-known/acme-challenge/" + token)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != keyAuth {
			return fmt.Errorf("http-01: got %q", body)
		}
		return nil
	case TLSALPN01:
		conn, err := tls.Dial("tcp", ca.target, &tls.Config{
			ServerName: ChallengeServerName(id), NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true,
		})
		if err != nil {
			return err
		}
		defer conn.Close()
		cs := conn.ConnectionState()
		if cs.NegotiatedProtocol != "acme-tls/1" {
			return fmt.Errorf("tls-alpn-01: negotiated %q", cs.NegotiatedProtocol)
		}
		leaf := cs.PeerCertificates[0]
		sum := sha256.Sum256([]byte(keyAuth))
		want, _ := asn1OctetString(sum[:])
		for _, e := range leaf.Extensions {
			if e.Id.Equal(oidACMEIdentifier) && e.Critical && bytes.Equal(e.Value, want) {
				return nil
			}
		}
		return fmt.Errorf("tls-alpn-01: acmeIdentifier extension missing or wrong")
	}
	return fmt.Errorf("unknown challenge %s", typ)
}

// ---- tests ----

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func newManager(t *testing.T, dir string) *Manager {
	m := NewManager(dir, quietLog())
	m.pollTime = 10 * time.Millisecond
	return m
}

func TestIssueWithHTTP01IncludingIPAddresses(t *testing.T) {
	ca := newFakeCA(t)
	ca.target = freePort(t)
	dir := t.TempDir()
	m := newManager(t, dir)
	s := Settings{Mode: ModeACME, Domains: []string{"DNS.Example.test"}, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		Directory: ca.url("/dir"), Challenge: HTTP01, HTTPListen: ca.target, Email: "ops@example.test"}
	if err := m.Configure(s); err != nil {
		t.Fatal(err)
	}
	if m.Ready() {
		t.Fatal("ready before issuance")
	}
	m.tick(context.Background())
	st := m.Status()
	if !st.Ready || st.LastError != "" || strings.Join(st.Names, ",") != "dns.example.test,192.0.2.53" {
		t.Fatalf("status after issuance: %+v", st)
	}
	if fi, err := os.Stat(filepath.Join(dir, "certs", "key.pem")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "acme", "account.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("account key: %v %v", fi, err)
	}
	// the challenge listener is closed again
	if c, err := net.DialTimeout("tcp", ca.target, 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("http-01 listener left open")
	}
	// a restart reuses the stored certificate and account
	m2 := newManager(t, dir)
	m2.Configure(s)
	if !m2.Ready() || m2.dueForRenewal(time.Now(), s) {
		t.Fatal("stored certificate not reused")
	}
	if len(ca.accounts) != 1 {
		t.Fatalf("%d accounts registered, want 1", len(ca.accounts))
	}
	// asking for another name makes the stored certificate unsuitable
	s2 := s
	s2.Domains = []string{"other.example.test"}
	m2.Configure(s2)
	if m2.Ready() {
		t.Fatal("certificate for the wrong names served")
	}
}

func TestIssueWithTLSALPN01(t *testing.T) {
	ca := newFakeCA(t)
	m := newManager(t, t.TempDir())
	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig("dot"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	ca.target = ln.Addr().String()
	s := Settings{Mode: ModeACME, Domains: []string{"dns.example.test"}, IPs: []netip.Addr{netip.MustParseAddr("2001:db8::53")},
		Directory: ca.url("/dir"), Challenge: TLSALPN01}
	m.Configure(s)
	m.tick(context.Background())
	if st := m.Status(); !st.Ready {
		t.Fatalf("tls-alpn-01 issuance failed: %+v", st)
	}
	// normal clients get the issued certificate, not a challenge certificate
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	c, err := tls.Dial("tcp", ca.target, &tls.Config{ServerName: "dns.example.test", RootCAs: pool, NextProtos: []string{"dot"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.ConnectionState().NegotiatedProtocol != "dot" {
		t.Fatal("ALPN dot not negotiated")
	}
	c.Close()
	// verified DDR: the same certificate is valid for the IP address
	c, err = tls.Dial("tcp", ca.target, &tls.Config{ServerName: "2001:db8::53", RootCAs: pool})
	if err != nil {
		t.Fatalf("certificate not valid for the IP address: %v", err)
	}
	c.Close()
}

func TestRenewalAndBackoff(t *testing.T) {
	ca := newFakeCA(t)
	ca.target = freePort(t)
	ca.lifetime = 3 * time.Hour
	m := newManager(t, t.TempDir())
	now := time.Now()
	m.now = func() time.Time { return now }
	s := Settings{Mode: ModeACME, Domains: []string{"dns.example.test"}, Directory: ca.url("/dir"), Challenge: HTTP01, HTTPListen: ca.target}
	m.Configure(s)
	m.tick(context.Background())
	if ca.issued != 1 {
		t.Fatal("not issued")
	}
	now = now.Add(time.Hour) // a third of the lifetime used: keep
	m.tick(context.Background())
	if ca.issued != 1 {
		t.Fatal("renewed too early")
	}
	now = now.Add(time.Hour + 5*time.Minute) // past two thirds: renew
	m.tick(context.Background())
	if ca.issued != 2 {
		t.Fatalf("not renewed (issued %d)", ca.issued)
	}

	// validation failure: error recorded, next attempt backed off
	ca.target = freePort(t)    // the CA now validates against a closed port
	s.HTTPListen = freePort(t) // while dnsnova listens elsewhere
	s.Domains = []string{"x.example.test"}
	m.Configure(s)
	m.tick(context.Background())
	st := m.Status()
	if st.LastError == "" || !st.NextAttempt.After(now) {
		t.Fatalf("failure not recorded: %+v", st)
	}
	before := ca.issued
	m.tick(context.Background())
	if ca.issued != before || len(ca.orders) != 3 {
		t.Fatalf("retried before the backoff expired (orders %d)", len(ca.orders))
	}
}

func TestProfileRequiredForIPs(t *testing.T) {
	ca := newFakeCA(t)
	ca.profiles = map[string]string{"classic": ""}
	ca.target = freePort(t)
	m := newManager(t, t.TempDir())
	m.Configure(Settings{Mode: ModeACME, IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Directory: ca.url("/dir"), Challenge: HTTP01, HTTPListen: ca.target})
	m.tick(context.Background())
	if st := m.Status(); st.Ready || !strings.Contains(st.LastError, "shortlived") {
		t.Fatalf("want a shortlived profile error: %+v", st)
	}
}

func selfSigned(t *testing.T, dir, name string, notAfter time.Time) (certFile, keyFile string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, DNSNames: []string{name},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	return
}

func TestFilesModeReloads(t *testing.T) {
	dir := t.TempDir()
	cf, kf := selfSigned(t, dir, "one.test", time.Now().Add(48*time.Hour))
	m := newManager(t, t.TempDir())
	if err := m.Configure(Settings{Mode: ModeFiles, CertFile: cf, KeyFile: kf}); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); !st.Ready || st.Names[0] != "one.test" {
		t.Fatalf("%+v", st)
	}
	time.Sleep(20 * time.Millisecond)
	selfSigned(t, dir, "two.test", time.Now().Add(48*time.Hour))
	future := time.Now().Add(time.Second)
	os.Chtimes(cf, future, future)
	m.tick(context.Background())
	if st := m.Status(); st.Names[0] != "two.test" {
		t.Fatalf("files not reloaded: %+v", st)
	}
	// an expired or mismatched file is refused and the current one kept
	selfSigned(t, dir, "old.test", time.Now().Add(-time.Minute))
	if err := m.Configure(Settings{Mode: ModeFiles, CertFile: cf, KeyFile: kf}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired certificate accepted: %v", err)
	}
	if err := m.Configure(Settings{Mode: ModeFiles, CertFile: cf, KeyFile: filepath.Join(dir, "missing.pem")}); err == nil {
		t.Fatal("missing key accepted")
	}
}

func TestReverseNames(t *testing.T) {
	if got := ReverseName(netip.MustParseAddr("192.0.2.53")); got != "53.2.0.192.in-addr.arpa" {
		t.Fatal(got)
	}
	got := ReverseName(netip.MustParseAddr("2001:db8::1"))
	if !strings.HasPrefix(got, "1.0.0.0.0.0.0.0") || !strings.HasSuffix(got, "8.b.d.0.1.0.0.2.ip6.arpa") || strings.Count(got, ".") != 33 {
		t.Fatal(got)
	}
	ips := PublicIPs([]netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::1"), netip.MustParseAddr("8.8.8.8")})
	if len(ips) != 1 || ips[0].String() != "8.8.8.8" {
		t.Fatal(ips)
	}
}
