# DNSNova

> A secure DNS server, from one box at home to a public resolver on several continents.

[![Version](https://img.shields.io/badge/version-v1.4.0-blue)](https://github.com/harryheros/dnsnova/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-lightgrey.svg)](#)
[![CI](https://github.com/harryheros/dnsnova/actions/workflows/ci.yml/badge.svg)](https://github.com/harryheros/dnsnova/actions/workflows/ci.yml)
[![Fuzz](https://github.com/harryheros/dnsnova/actions/workflows/fuzz.yml/badge.svg)](https://github.com/harryheros/dnsnova/actions/workflows/fuzz.yml)

DNSNova resolves names itself, from the root servers with DNSSEC, or forwards them to upstreams you choose. It answers over plain DNS, DNS over TLS, DNS over QUIC and DNS over HTTPS. One program, no dependencies, managed from the browser, no query logs.

**At home or in an office**: a private resolver with optional ad and tracker blocking, set up in minutes. **On the internet**: a public resolver built to be exposed, with rate limits, DNS Cookies, a security self-check, multi-node clusters behind anycast, and alerts.

![The DNSNova web interface](./docs/images/overview.webp)

## New in 1.4

Recursion without upstreams, on networks that tamper with DNS ([details](./docs/restricted-networks.md)):

- **Censors on the path** (such as the Great Firewall): their forged answers are dropped and the genuine answer, which they cannot stop, is used. Before, such names failed DNSSEC validation or got the forged address.
- **Networks that take over port 53**: detected and reported, never cached. With your own DNSNova elsewhere as an encrypted upstream, queries go there at once.
- **DNS over HTTP/3 upstreams**: `h3://1.1.1.1/dns-query`.

Upgrading from 1.2 or earlier: see the [changelog](./CHANGELOG.md) first.

## Install

On Linux with systemd (amd64 or arm64), as root:

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sh
```

Without root it uses sudo (or run `su -` first where there is none). The installer prints where to open the setup wizard:

- **Home or office**: add `--lan` (`| sh -s -- --lan`). DNS answers your private networks only, and the wizard opens directly from them at `http://<server>:7000`.
- **Internet**: until it has a certificate, the web interface opens only on the server itself. Reach it with `ssh -L 7000:127.0.0.1:7000 root@<server>`, then `http://127.0.0.1:7000`.

The wizard sets the administrator, who the server is for, recursion or upstreams, a domain for encrypted DNS and filtering, then shows what to set on your router or devices. Every choice is also a command-line option: `install.sh --help`.

- **Upgrade**: run the install command again. The configuration is kept; if the new version fails to start, the previous one is restored.
- **Uninstall**: add `-u` (`| sh -s -- -u`). The configuration stays in `/etc/dnsnova` unless you add `--purge`.
- **Lost password**: run `dnsnova -reset-admin` on the server, then create the administrator again in the web interface. Settings are kept.

## What it does

### Answering

- **Plain and encrypted DNS**: UDP and TCP on port 53, DNS over TLS, DNS over QUIC and DNS over HTTPS (HTTP/2 and HTTP/3), with an automatic Let's Encrypt certificate.
- **Recursion or forwarding**: resolve from the root servers with DNSSEC validation and minimal names, so no third party sees the queries; or forward to upstreams such as Cloudflare or Quad9 over DoH (HTTP/2 or HTTP/3), DoT or DoQ. With both, upstreams are used only when a domain's own servers cannot be reached.
- **Opt-in filtering**: the usual addresses answer everything; a second address, name or DoH path blocks ads, trackers, malware and CNAME-cloaked trackers. The default list is [ShieldNova](https://github.com/harryheros/shieldnova) (free to use in DNSNova, commercially too); AdGuard-style, hosts and domain lists also work. A broken list update never replaces a working list, *Check a domain* shows which list blocks a name, and one click allows it again.
- **Local names** such as `nas.home`, blocked clients, and EDNS Client Subnet for a network you choose (never your clients' addresses).

### On the internet

- **Public or private**: open to everyone within rate limits, or only to the networks you list; behind load balancers, PROXY protocol v1 and v2 from the ones you list.
- **Hard to poison**: random ports and IDs, answers checked against the server and question asked, and DNS Cookies. Forged answers, including those from censors on the path, are dropped and the genuine one is used; an attack in progress moves the question to TCP. A network that answers port 53 itself is detected, never cached ([details](./docs/restricted-networks.md)).
- **Hard to abuse**: per-client and per-network limits, response rate limiting against reflection, and DNS Cookies that exempt real clients.
- **Secure by default**: the web interface stays on the server itself until it has HTTPS; two-step verification; a self-check at startup and after every change reports weaknesses.

### Many servers

- **One configuration for a fleet**: a primary sends its settings to followers over an encrypted, authenticated channel; a node that cannot apply them keeps the last working ones and reports why. A Nodes page shows the fleet ([docs/cluster.md](./docs/cluster.md)).
- **Anycast with health checks**: the route is announced while the node can answer and withdrawn when it cannot, and first at shutdown, while traffic drains.

### Running it

- **Web interface**: queries per second, response times, cache hit rate and traffic history, query flow by protocol, upstream health, top domains, and every setting, previewed before it is applied and kept in a history.
- **Alerts and monitoring**: Telegram, Discord, Slack or webhook notifications, a heartbeat for outside monitors, Prometheus metrics and a health check ([docs/alerts.md](./docs/alerts.md)).
- **Diagnostics**: trace any lookup from the root, server by server; a DNSSEC page of failing domains, each exemptible (RFC 7646); an in-memory query log that stops by itself.
- **Fast**: on one CPU core, about 200,000 answers per second from the cache, 94,000 over DNS over TLS, and 23,000 for new names forwarded to an upstream; a 225,000-rule blocklist costs about 14% ([method](./docs/benchmark.md)).
- **Quick to recover**: the cache survives restarts (by default on public servers), and recent failures are remembered so a broken domain cannot flood upstreams.
- **Private**: queries and client addresses are never written to disk; no telemetry ([PRIVACY.md](./PRIVACY.md)).
- **Status page** (optional): addresses, setup steps per device, and a check that shows visitors whether they use the server.

## Encrypted DNS

Give the setup wizard (or Settings › Encrypted DNS) a domain that points to the server, and DNSNova obtains and renews a Let's Encrypt certificate. Open TCP 853, UDP 853 and TCP + UDP 443 (Let's Encrypt validates on 443, or on 80 if nothing listens on 443). Devices then use:

| Protocol | Address |
|---|---|
| DNS over TLS | `dns.example.com` |
| DNS over QUIC | `quic://dns.example.com` |
| DNS over HTTPS | `https://dns.example.com/dns-query` |
| DNS over HTTPS, with filtering on | `https://dns.example.com/filtered` |

For encrypted DNS only, choose *Only this server* in the wizard: plain DNS then answers on 127.0.0.1 alone.

## Documentation

- [`dnsnova.example.toml`](./dnsnova.example.toml): every setting, explained. The live file is `/etc/dnsnova/dnsnova.toml`; changes apply on save.
- [docs/cluster.md](./docs/cluster.md): several servers sharing one configuration, and anycast.
- [docs/alerts.md](./docs/alerts.md): notifications, what is checked, the webhook format.
- [docs/restricted-networks.md](./docs/restricted-networks.md): resolving where DNS is censored or intercepted.
- [docs/api.md](./docs/api.md): the admin API used by the web interface, for scripts.
- [docs/benchmark.md](./docs/benchmark.md): performance, and how to measure it yourself.
- [tools/resolver-check.sh](./tools/resolver-check.sh): compares a running server with a reference resolver (popular domains, DNSSEC, minimal names, TCP, response times): `bash resolver-check.sh <server-ip>`.
- [CHANGELOG.md](./CHANGELOG.md), [PRIVACY.md](./PRIVACY.md), [SECURITY.md](./SECURITY.md) (report vulnerabilities privately).

Build from source (Go 1.27 or later): `CGO_ENABLED=0 go build -o dnsnova ./cmd/dnsnova`. Tests: `go test -race ./...`; every parser is also fuzzed weekly.

## License

[GNU Affero General Public License v3.0](./LICENSE): free for any use, including commercial. If you modify DNSNova and offer it as a network service, you must make your modified source available to its users. For other terms, see the commercial license in [COMMERCIAL.md](./COMMERCIAL.md). Contributions are welcome under the [contributor license agreement](./CONTRIBUTING.md). Third-party components: [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).

Part of the [Nova projects](https://github.com/harryheros).
