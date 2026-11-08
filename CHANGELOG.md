# Changelog

All notable changes are listed here. Versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked
**Security**.

## Unreleased

First development release of the 1.0 core.

- DNS over UDP and TCP; DNS over TLS; DNS over QUIC (RFC 9250, UDP 853);
  DNS over HTTPS over HTTP/1.1, HTTP/2 and HTTP/3 (same port, TCP and UDP),
  built in or behind a reverse proxy. HTTP/1.1 and HTTP/2 responses advertise
  HTTP/3 with Alt-Svc; `doh.http3 = false` turns it off.
- 0-RTT is never accepted on TLS or QUIC.
- QUIC connections are capped (`limits.quic_connections`); when busy, new
  clients must prove their address with a QUIC Retry. Clients outside the
  access list (private mode) are refused before the handshake.
- Automatic certificates from Let's Encrypt through a built-in ACME client
  (tls-alpn-01, http-01, short-lived IP address certificates), or certificate
  files reloaded when they change.
- DDR (RFC 9462): SVCB answers for `_dns.resolver.arpa` advertising the DoT,
  DoH (`alpn=h2,h3` when HTTP/3 is on) and DoQ endpoints.
- Upstreams over UDP, TCP, DNS over TLS, DNS over HTTPS and DNS over QUIC
  (`quic://`, one reused connection, no 0-RTT), with parallel
  primaries, fallback upstreams, bootstrap resolution and pinned addresses.
- Cache with serve-stale, prefetch, coalescing and negative caching.
- Public and private service modes; limits per client, per network and
  global; response rate limiting; upstream concurrency caps in total and per
  domain.
- Local answers for private reverse zones and localhost.
- TOML configuration with line-numbered errors, automatic reload, atomic
  writes and version history.
- Prometheus metrics (queries by protocol, including `doq` and `doh3`) and a
  health endpoint.
- Admin API (`[admin] listen`, documented in docs/api.md): one-time setup
  code, Argon2id passwords, sessions in HttpOnly SameSite=Strict cookies,
  CSRF tokens, Host header checks against DNS rebinding, login lockout,
  optional TOTP two-step verification; status, statistics history (1 hour,
  24 hours, 7 days), upstream health, recent events, cache clearing; reading
  and editing the configuration by key or as a whole file with preview,
  line diff, conflict detection, automatic revert when a change cannot be
  applied, and restore from history. HTTPS on the same port once a
  certificate exists.
- Web interface on the admin port, built into the binary (plain HTML, CSS
  and JavaScript, no external requests, strict Content Security Policy):
  setup wizard, overview with response times, protocols, upstreams, events,
  certificate and privacy; upstream health; settings pages that show every
  change before it is applied; password, two-step verification,
  configuration history and the raw file; Compare upstreams, which asks
  every upstream the same question and shows each answer and its time. Light and dark appearance, or follow the system.
- Admin API: `GET /system/addresses`, `POST /tools/lookup`, and `client_ip`
  in session responses.
- Interface polish: navigation and event icons (line icons in the style of
  Lucide, ISC), a clearer summary with three key figures, a response-time
  chart with an area, a pointer readout and an empty state, upstream states
  Healthy, Slow, Failing and Standby with success rates, repeated events
  folded into one, and a blue-grey dark appearance. The design rules are in
  docs/design.md.
- Privacy: queries and client addresses are never written to disk.
  `[log] queries` no longer logs anything (it is accepted with a warning).
  Instead, the admin interface has a query log held in memory: it runs for
  15 minutes to 24 hours and stops by itself, shortens client addresses
  unless asked not to, keeps at most 10,000 queries and deletes them an hour
  after it stops. Starting it is recorded in the service log and shown in
  the status.
- Overview lists the most queried domains and domains that do not exist
  (by registrable domain, only once 5 networks asked within an hour, using
  an hourly-keyed sketch instead of addresses), and the networks that hit
  the rate limits most. All in memory.
- golang.org/x/net is now a direct dependency (public suffix list).
- Durations of a second or more read back as `1.5s` rather than `1500ms`.
- The installer asks whether the admin interface is local (SSH tunnel) or
  public (`--admin local|public|off`, `--admin-port`) and prints a setup
  link with the one-time code. Existing installations are not changed: add `[admin]` to enable it.
- First third-party dependency: quic-go v0.65.0 (MIT, with its golang.org/x
  dependencies), for DoQ and HTTP/3.
- golang.org/x/crypto is now a direct dependency (Argon2id).
- Requires Go 1.27 to build (`go 1.27` in go.mod); release binaries are
  built with the latest Go 1.27 patch release.
- One-line installer with optional encrypted DNS setup, checksum verification, upgrade with automatic
  rollback, and uninstall; release builds for linux/amd64 and linux/arm64.
