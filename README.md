# DNSNova

> A secure, lightweight forwarding DNS server for public and private resolvers.

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](./LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-orange.svg)](./CHANGELOG.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-lightgrey.svg)](#)
[![CI](https://github.com/harryheros/dnsnova/actions/workflows/ci.yml/badge.svg)](https://github.com/harryheros/dnsnova/actions/workflows/ci.yml)

DNSNova forwards queries to upstream resolvers you choose — Cloudflare, Google, Quad9 or your own — and answers from a cache. It is built for operators with one or a few servers who want a resolver that is safe to expose to the internet without becoming a DDoS amplifier.

It belongs to the same family as dnsdist, CoreDNS, Blocky and AdGuard Home: not an authoritative server like BIND or Knot, and not a recursive resolver like Unbound.

> [!NOTE]
> **Pre-release of 1.0.** The core server is complete; a web interface and setup wizard are planned for a later release.

---

## Quick start

On a Linux server with systemd (amd64 or arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sudo bash
```

The installer downloads the latest release, verifies its SHA-256 checksum, asks a few questions (addresses, public or private, upstreams, and a domain for encrypted DNS), checks the configuration and ports, and starts DNSNova as a sandboxed systemd service. With a domain, a Let's Encrypt certificate is obtained and renewed automatically.

- **Upgrade**: run the same command again. The configuration is kept; if the new version fails its health check, the previous one is restored.
- **Uninstall**: `--uninstall` (keeps the configuration) or `--uninstall --purge` (removes everything).

Unattended install:

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sudo bash -s -- \
  --yes --mode public --listen 203.0.113.10:53 \
  --upstream https://1.1.1.1/dns-query --fallback https://dns.google/dns-query#8.8.8.8 \
  --domain dns.example.com --email ops@example.com
```

`install.sh --help` lists all options.

---

## Features

| | |
|---|---|
| **Protocols** | UDP and TCP (with pipelining), DNS over TLS, DNS over QUIC (RFC 9250), DNS over HTTPS over HTTP/1.1, HTTP/2 and HTTP/3 — all built in. DoH can also run behind nginx. |
| **Certificates** | Automatic from Let's Encrypt (built-in ACME, tls-alpn-01 or http-01), or loaded from files and reloaded on change. One certificate serves DoT, DoQ and DoH. 0-RTT is never accepted. |
| **Encrypted upgrade** | DDR (RFC 9462): clients that ask `_dns.resolver.arpa` learn the DoT, DoH and DoQ endpoints. With `tls.ip_addresses = true`, Windows 11, iOS and macOS switch to encrypted DNS by themselves. |
| **Upstreams** | UDP, TCP, DoT, DoH and DoQ. Fastest primaries are queried in parallel; fallbacks only when primaries fail. Host names resolved through fixed bootstrap servers or pinned addresses. |
| **Cache** | Serve-stale (RFC 8767), prefetch, coalescing of identical queries, negative caching (RFC 2308). |
| **Two modes** | `public`: anyone may query, protected by per-client, per-network and global limits, response rate limiting, upstream concurrency caps, refusal of ANY and zone transfers, and connection caps. `private`: only listed networks; everyone else is dropped silently. |
| **Local answers** | Reverse lookups of private, loopback and link-local addresses (RFC 6303) and `localhost.` never leave the server. |
| **DNSSEC** | Signatures passed through to clients that ask; validation is left to the upstream resolver. |
| **Configuration** | One TOML file with line-numbered errors, applied without restart on save or `SIGHUP`; cache and statistics are kept. |
| **Operations** | Prometheus metrics, a `/healthz` endpoint, and an [admin API](./docs/api.md) for status, statistics, upstream health, recent events and editing the configuration with preview, conflict detection and history. |
| **Privacy** | No telemetry; queries are not logged unless you turn it on — see [PRIVACY.md](./PRIVACY.md). |
| **Dependencies** | Go standard library plus [quic-go](https://github.com/quic-go/quic-go) (MIT). The ACME client and TOML parser are built in. |

---

## Configuration

Start from [`dnsnova.example.toml`](./dnsnova.example.toml); every setting is explained there. The minimum:

```toml
[server]
mode = "public"
listen = ["203.0.113.10:53"]

[upstream]
primary = ["https://1.1.1.1/dns-query"]
```

- On hosts with several IP addresses, list each address instead of `:53`, so UDP replies leave from the address the query was sent to.
- Changes apply within a few seconds. An invalid file is reported with its line number and the running configuration stays in place. Previous versions are kept in `/etc/dnsnova/history/`.
- Only one program can use port 53 on an address; stop any other DNS server there first. systemd-resolved listens on 127.0.0.53 only and does not conflict.

### Encrypted DNS

```toml
[dot]
listen = ["203.0.113.10:853"]         # TCP 853

[doq]
listen = ["203.0.113.10:853"]         # UDP 853

[doh]
https_listen = ["203.0.113.10:443"]   # TCP 443, and UDP 443 for HTTP/3

[tls]
certificate = "acme"
domains = ["dns.example.com"]
ip_addresses = true
```

The domain must point to the server, and port 443 (or 80) must be reachable while the certificate is issued. Open TCP 853, UDP 853, and TCP + UDP 443 in your firewall. Set `[doh] http3 = false` to serve only HTTP/1.1 and HTTP/2.

| Protocol | Client address |
|---|---|
| DNS over TLS | `dns.example.com` (port 853) |
| DNS over QUIC | `quic://dns.example.com` |
| DNS over HTTPS | `https://dns.example.com/dns-query` |

If the log warns about the UDP receive buffer, raise the limits once:

```sh
echo 'net.core.rmem_max=7500000
net.core.wmem_max=7500000' | sudo tee /etc/sysctl.d/90-dnsnova-quic.conf
sudo sysctl --system
```

**Behind nginx**: set `[doh] listen = "127.0.0.1:8053"` and proxy to it — see [`deploy/nginx-doh.conf`](./deploy/nginx-doh.conf). nginx must send `X-Real-IP` so limits and access lists apply to the real client.

### Web interface

The installer asks whether the admin interface (port 7000) should be
reachable only from the server itself, through an SSH tunnel, or from
anywhere with a password; `--admin local|public|off` answers without asking.
It then prints a one-time setup link. The wizard creates the administrator
and walks through who may use the server, its addresses, upstreams and
encrypted DNS.

Afterwards the interface shows response times, traffic by protocol,
upstream health, the most queried domains, recent events and the
certificate, and every setting can be
changed there: each change is listed before it is applied, keeps the file's
comments, refuses to overwrite someone else's edit, is put back if it cannot
be applied, and can be undone from the history. Two-step verification is
optional. Light and dark appearance, or follow the system.

Queries and client addresses are never written to disk. For
troubleshooting, a query log can be started from the interface: it is kept
in memory, shortens client addresses, and stops by itself (see
[PRIVACY.md](./PRIVACY.md)).

The interface is built into the binary and makes no requests to other sites.
Everything it does goes through the [admin API](./docs/api.md), which scripts
can use too. Its design rules are in [docs/design.md](./docs/design.md).

### Status page

With `[status] enabled = true` (or the switch in Settings › Encrypted DNS),
`https://your-domain/` shows a public page: the server's addresses, setup
steps for Android, iPhone and Mac (with a profile to download), Windows,
browsers and routers, what the server keeps, and whether the query log is
on. A check on the page tells visitors whether their device is actually
using this server, and over which protocol: the page looks up a one-time
name under `check.your-domain`, and DNSNova notes only that name and the
protocol, for five minutes. No statistics are shown.

### Metrics and health

With `[metrics] listen = "127.0.0.1:9153"`:

- `GET /metrics` — Prometheus metrics: queries by protocol, answers by source, response codes, rejections, latency, cache size, open connections, and per-upstream health.
- `GET /healthz` — `200` when at least one upstream is healthy, `503` otherwise. Contains no addresses, so it is safe to expose to an external monitor.

---

## Manual installation

Requirements: Linux with systemd, amd64 or arm64; Go 1.27 or later to build.

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dnsnova ./cmd/dnsnova

sudo install -m 755 dnsnova /usr/local/bin/dnsnova
sudo useradd --system --no-create-home --shell /usr/sbin/nologin dnsnova
sudo install -d -o dnsnova -g dnsnova -m 750 /etc/dnsnova /var/lib/dnsnova
sudo install -o dnsnova -g dnsnova -m 640 dnsnova.example.toml /etc/dnsnova/dnsnova.toml

sudoedit /etc/dnsnova/dnsnova.toml   # set mode, listen and upstream
dnsnova -t -c /etc/dnsnova/dnsnova.toml

sudo install -m 644 deploy/dnsnova.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now dnsnova
```

Tests: `go vet ./...` and `go test -race ./...`. Release history: [CHANGELOG.md](./CHANGELOG.md).

---

## License

[GNU Affero General Public License v3.0](./LICENSE). If you modify DNSNova and offer it to others as a network service, you must make your modified source available to them.

Contributions require agreeing to a contributor license agreement, which will be published before external contributions are accepted.

**Security**: report vulnerabilities privately — see [SECURITY.md](./SECURITY.md).

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
