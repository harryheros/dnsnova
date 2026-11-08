# Changelog

All notable changes are listed here. Versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked
**Security**.

## Unreleased

First development release of the 1.0 core.

- DNS over UDP and TCP; DNS over HTTPS behind a reverse proxy.
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
