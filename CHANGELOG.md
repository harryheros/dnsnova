# Changelog

All notable changes are listed here. Versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked
**Security**.

## Unreleased

First development release of the 1.0 core.

- DNS over UDP and TCP; DNS over TLS; DNS over HTTPS (HTTP/1.1 and HTTP/2),
  built in or behind a reverse proxy.
- Automatic certificates from Let's Encrypt through a built-in ACME client
  (tls-alpn-01, http-01, short-lived IP address certificates), or certificate
  files reloaded when they change.
- DDR (RFC 9462): SVCB answers for `_dns.resolver.arpa` advertising the DoT
  and DoH endpoints.
- Upstreams over UDP, TCP, DNS over TLS and DNS over HTTPS, with parallel
  primaries, fallback upstreams, bootstrap resolution and pinned addresses.
- Cache with serve-stale, prefetch, coalescing and negative caching.
- Public and private service modes; limits per client, per network and
  global; response rate limiting; upstream concurrency caps in total and per
  domain.
- Local answers for private reverse zones and localhost.
- TOML configuration with line-numbered errors, automatic reload, atomic
  writes and version history.
- Prometheus metrics and a health endpoint.
- One-line installer with optional encrypted DNS setup, checksum verification, upgrade with automatic
  rollback, and uninstall; release builds for linux/amd64 and linux/arm64.
