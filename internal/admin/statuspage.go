package admin

import (
	"crypto/sha256"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"strings"
)

// PublicInfo is what the public status page shows. It holds nothing about
// any client.
type PublicInfo struct {
	Domain         string   `json:"domain"`
	Mode           string   `json:"mode"`
	Healthy        bool     `json:"healthy"`   // at least one primary upstream answers
	Encrypted      bool     `json:"encrypted"` // the certificate is ready
	DoH            string   `json:"doh,omitempty"`
	HTTP3          bool     `json:"http3"`
	DoT            string   `json:"dot,omitempty"`
	DoQ            string   `json:"doq,omitempty"`
	Plain          []string `json:"plain,omitempty"` // public mode only
	Check          bool     `json:"check"`
	QueryLog       bool     `json:"query_log"`
	QueryLogFullIP bool     `json:"query_log_full_ip"`
	// Filtered lists the addresses of the filtered service, when it is on.
	Filtered *Filtered `json:"filtered,omitempty"`
}

// Filtered describes the filtered service for clients.
type Filtered struct {
	DoH   string   `json:"doh,omitempty"`
	DoT   string   `json:"dot,omitempty"`
	DoQ   string   `json:"doq,omitempty"`
	Plain []string `json:"plain,omitempty"`
	Rules int      `json:"rules"`
}

// GuideInfo feeds the admin interface's setup guide: the public addresses
// plus every address DNS listens on (a home server's are private), and
// where the Apple profile can be downloaded (null: nowhere, the status
// page is off).
type GuideInfo struct {
	PublicInfo
	Profile *string `json:"profile"`
	Port    int     `json:"port"` // of plain DNS; devices mostly expect 53
}

// PublicBackend feeds the status page.
type PublicBackend interface {
	PublicStatus() PublicInfo
	// ProbeSeen reports whether the check name with this token was asked
	// for, and over which protocol (udp, tcp, dot, doh, doh3, doq).
	ProbeSeen(token string) (string, bool)
}

// StatusPage is the public page served on the DNS-over-HTTPS addresses:
// how to use the server, what it keeps, and a check that the visitor's
// device is using it. It needs no sign-in and shows no statistics.
type StatusPage struct {
	b   PublicBackend
	mux *http.ServeMux
}

// statusAssets are the files the status page may load.
var statusAssets = map[string]bool{"app.css": true, "theme.js": true, "logo.svg": true, "status.js": true, "guides.js": true}

// NewStatusPage returns the page's handler.
func NewStatusPage(b PublicBackend) *StatusPage {
	p := &StatusPage{b: b, mux: http.NewServeMux()}
	ui, _ := fs.Sub(uiFiles, "ui")
	p.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data, _ := fs.ReadFile(ui, "status.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(data)
	})
	files := http.FileServerFS(ui)
	p.mux.HandleFunc("GET /assets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !statusAssets[r.PathValue("name")] {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + r.PathValue("name")
		files.ServeHTTP(w, r2)
	})
	p.mux.HandleFunc("GET /status.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, b.PublicStatus())
	})
	p.mux.HandleFunc("GET /check/{token}", func(w http.ResponseWriter, r *http.Request) {
		proto, seen := b.ProbeSeen(r.PathValue("token"))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"seen": seen, "proto": proto})
	})
	p.mux.HandleFunc("GET /dnsnova.mobileconfig", p.profile)
	return p
}

// ServeHTTP serves the page with headers that keep it self-contained.
func (p *StatusPage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	img := "'self' data:"
	if info := p.b.PublicStatus(); info.Check {
		img += " https://*.check." + info.Domain // the check loads one image from a random name there
	}
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src "+img+
		"; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	p.mux.ServeHTTP(w, r)
}

// profile is an Apple configuration profile that sets encrypted DNS on
// iPhone, iPad and Mac (iOS 14 and macOS 11 or later).
func (p *StatusPage) profile(w http.ResponseWriter, r *http.Request) {
	info := p.b.PublicStatus()
	var proto, key, value, label string
	kind, filtered := strings.CutSuffix(r.URL.Query().Get("p"), "-filtered")
	doh, dot := info.DoH, info.DoT
	if filtered { // the filtered service's addresses
		doh, dot = "", ""
		if info.Filtered != nil {
			doh, dot = info.Filtered.DoH, info.Filtered.DoT
		}
	}
	switch kind {
	case "dot":
		proto, key, value, label = "TLS", "ServerName", strings.SplitN(dot, ":", 2)[0], "DNS over TLS"
		if dot == "" || strings.Contains(dot, ":") { // Apple only supports port 853
			http.NotFound(w, r)
			return
		}
	default:
		proto, key, value, label = "HTTPS", "ServerURL", doh, "DNS over HTTPS"
		if doh == "" {
			http.NotFound(w, r)
			return
		}
	}
	id := "dnsnova." + reverse(info.Domain) + "." + strings.ToLower(proto)
	if filtered {
		label += ", filtered"
		id += ".filtered" // its own profile, next to the unfiltered one
	}
	esc := html.EscapeString
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>%s</string>
				<key>%s</key>
				<string>%s</string>
			</dict>
			<key>PayloadDisplayName</key>
			<string>%s (%s)</string>
			<key>PayloadIdentifier</key>
			<string>%s.dns</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Sends this device's DNS queries to %s over %s.</string>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>%s</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, proto, key, esc(value), esc(info.Domain), label, esc(id), uuid(id+".dns"),
		esc(info.Domain), label, esc(info.Domain), esc(id), uuid(id))
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	suffix := strings.ToLower(proto)
	if filtered {
		suffix += "-filtered"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+info.Domain+`-`+suffix+`.mobileconfig"`)
	w.Write([]byte(body))
}

// uuid derives a stable UUID from s, so downloading the profile again
// replaces the installed one instead of adding a second.
func uuid(s string) string {
	b := sha256.Sum256([]byte(s))
	b[6] = b[6]&0x0f | 0x50 // version 5 style
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}

func reverse(domain string) string {
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}
