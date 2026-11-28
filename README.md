# DNSNova

> A secure DNS resolver for home networks, offices, and multi-region public DNS services.

[![Version](https://img.shields.io/badge/version-v2.0.0-blue.svg)](https://github.com/harryheros/dnsnova/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](#license)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64%20%7C%20arm-lightgrey.svg)](#install)
[![CI](https://github.com/harryheros/dnsnova/actions/workflows/ci.yml/badge.svg)](https://github.com/harryheros/dnsnova/actions/workflows/ci.yml)
[![Fuzz](https://github.com/harryheros/dnsnova/actions/workflows/fuzz.yml/badge.svg)](https://github.com/harryheros/dnsnova/actions/workflows/fuzz.yml)

[Install](#install) · [What it does](#what-it-does) · [Encrypted DNS](#encrypted-dns) · [Documentation](#documentation) · [Changelog](./CHANGELOG.md) · [License](#license)

DNSNova resolves DNS queries directly from the root and authoritative name servers with DNSSEC validation, or forwards them to upstream resolvers you configure. It serves unencrypted DNS, DNS over TLS (DoT), DNS over QUIC (DoQ), and DNS over HTTPS (DoH), and is managed from your browser. It is a single static binary with no runtime dependencies, and query logging is off by default.

**At home or in an office**: a private resolver with optional ad and tracker blocking, set up in minutes. **On the internet**: designed for public deployment, with rate limiting, DNS Cookies, a security self-check, alerts, and multi-node deployments with anycast. **Beyond what resolvers usually do**: private locality gives distant clients CDN answers for their own location without sending anything about them, and every capability is visible and configurable in one interface.

![The DNSNova web interface](./docs/images/overview.webp)

## Install

On Linux with systemd (amd64, arm64, or 32-bit ARM such as Raspberry Pi OS 32-bit), as root:

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sh
```

If you run the installer without root privileges, it uses sudo when available. If sudo is unavailable, switch to the root account and rerun the installer. The installer prints where to open the setup wizard:

- **Home or office**: add `--lan` (`| sh -s -- --lan`). DNS answers your private networks only, and the wizard opens directly from them at `http://<server>:7000`.
- **Internet**: until it has a certificate, the web interface opens only on the server itself. Reach it with `ssh -L 7000:127.0.0.1:7000 root@<server>`, then `http://127.0.0.1:7000`.

The setup wizard creates an administrator account and guides you through access, resolution, encrypted DNS, and filtering, then verifies what is running and displays the settings for your router or devices. Setup resumes where it was left after a reload or a new sign-in. Every choice is also a command-line option: `install.sh --help`.

- **Firewall**: open what you use: port 53 over UDP and TCP; 853 (TCP and UDP) and 443 (TCP and UDP) for encrypted DNS. With ufw or firewalld on, the installer prints the commands.
- **Containers**: in LXC or OpenVZ containers that cannot sandbox services, the installer runs DNSNova without the sandbox (a drop-in in `/etc/systemd/system/dnsnova.service.d`). Without systemd (Docker, Alpine), run the binary from the release yourself: `dnsnova -c /etc/dnsnova/dnsnova.toml`.
- **Upgrade**: run the install command again. The configuration is kept; if the new version fails to start, the previous one is restored. From 1.2 or earlier, read the [changelog](./CHANGELOG.md) first.
- **Verify a release** (optional): the installer checks each download against the release's SHA256SUMS. Each file is also signed with its build provenance: `gh attestation verify dnsnova-linux-amd64.tar.gz -R harryheros/dnsnova` shows it was built by this repository's release workflow from the tagged commit.
- **Uninstall**: add `-u` (`| sh -s -- -u`). The configuration stays in `/etc/dnsnova`; uninstalling with `--purge` deletes the configuration and stored data.
- **Forgot your password?** Run `dnsnova -reset-admin` on the server (under systemd it restarts DNSNova; otherwise restart it yourself), then open the admin interface to create a new administrator account. Configuration settings are preserved.

## What it does

### Resolution

- **Unencrypted and encrypted DNS**: UDP and TCP on port 53, DoT, DoQ, and DoH (HTTP/2 and HTTP/3), with automatic Let's Encrypt certificates.
- **Recursive resolution or forwarding**: resolve queries directly by contacting root and authoritative name servers, with DNSSEC validation and QNAME minimization; or forward them to upstream resolvers over DoH (HTTP/2 or HTTP/3), DoT, or DoQ. If fallback is enabled, DNSNova may forward a query to an upstream resolver when authoritative servers are unreachable; with fallback off or no upstream resolver configured, no third-party resolver receives any query.
- **Opt-in filtering**: the standard endpoints answer everything; a separate address, host name, or DoH path blocks ads, trackers, malware, and CNAME-cloaked trackers. The default list is [ShieldNova](https://github.com/harryheros/shieldnova) (free to use with DNSNova, commercially too); adblock-style, hosts, RPZ, and domain lists also work. A failed list update never replaces a working list; *Test a filtering rule* shows which list blocks a name, and one click adds it to the allowlist.
- **Client groups**: clients grouped by network, each group with its own filtering policy and its own blocked or allowed domains (the finance office filtered, the lab never, social networks blocked for guests).
- **Local records** such as `nas.home`; **forward zones**, such as an office's Active Directory or a router's device names, resolved only there; denied clients; and EDNS Client Subnet for a network you choose (never your clients' addresses).
- **Private locality** (optional): distant clients get the CDN answers authoritative name servers give for their own location, so content is served from near them. Location-dependent names are also resolved through lightweight exits in other places, shared by all clients; no client address or subnet is sent ([docs/private-locality.md](./docs/private-locality.md)).
- **DNS rebinding protection**: a public name that resolves to an address in your network is answered without it, so a web page cannot reach your router, NAS, or printer through it; your own names are exempt, and one click in the query log allows a public name you gave a device on your network.

### On the internet

- **Public or private**: open to any client within rate limits, or only to the client networks you allow; behind load balancers, PROXY protocol v1 and v2 from the ones you list.
- **Cache poisoning defenses**: randomized source ports and IDs, responses checked against the server and the question asked, and DNS Cookies. Forged responses, including those injected on the path, are dropped and the genuine one is used; an attack in progress moves the query to TCP. A network that intercepts port 53 is detected, and its responses are never cached ([details](./docs/restricted-networks.md)).
- **Abuse prevention**: per-client and per-network rate limits, response rate limiting (RRL) against reflection, and DNS Cookies that exempt legitimate clients.
- **Secure by default**: on a public resolver the admin interface is served only to the host itself until HTTPS is available; two-step verification; a security self-check at startup and after every change.

### Many servers

- **One configuration for a fleet**: followers pull shared settings from the primary over an encrypted, authenticated channel; a node that cannot apply them keeps serving with the last configuration it applied and reports why. The Nodes page shows each node's health, configuration version, software version, certificate, and anycast state ([docs/cluster.md](./docs/cluster.md)).
- **Anycast with health checks**: BGP routing determines which site serves each client; the route is announced while the node can resolve and withdrawn when it cannot, and first at shutdown, while traffic drains. Clients can ask which node answered (`dig +nsid`).

### Running it

- **Web interface**: queries per second, response times, cache hit rate and traffic history, query flow by protocol, upstream and resolution health, top domains, and the state of every capability. Manage supported settings in the web interface, preview changes, and review configuration history; unsaved changes are kept until you apply or discard them. Some node-specific settings require access to the host configuration file.
- **Newly observed domains**: reports, on its page and through alerts, a domain queried here for the first time in 30 to 60 days, often the first sign of phishing; one click adds it to the blocklist. DNSNova uses hashes to track previously seen domains; recent detections display domain names and may be included in alerts.
- **Alerts and monitoring**: Telegram, Discord, Slack or webhook notifications, a heartbeat for outside monitors, Prometheus metrics and a health check ([docs/alerts.md](./docs/alerts.md)).
- **Diagnostics**: trace any lookup from the root, server by server; a DNSSEC page that lists validation failures and lets an administrator add exceptions (RFC 7646); an in-memory live capture that stops automatically.
- **Performance**: in the single-core benchmark, DNSNova handled about 200,000 cached responses per second over UDP, 94,000 over DoT, and 23,000 cache-miss queries per second with a local upstream; a 225,000-rule blocklist costs about 14%. Real-world throughput depends on workload and network conditions ([method](./docs/benchmark.md)).
- **Persistent cache and resolver state**: the cache survives restarts (by default on public resolvers), together with what recursion learned about which name servers respond fastest, and recent failures are remembered so a broken domain cannot flood upstream resolvers. When the cache is full, frequently queried entries stay and one-off entries are evicted first. A host started with a wrong clock (which breaks DNSSEC) is detected and reports the clock offset.
- **Private by default**: no telemetry, and queries and client IP addresses are not written to disk ([PRIVACY.md](./PRIVACY.md)). Queries to encrypted upstream resolvers are padded, so their length does not reveal the name; non-recursive queries are refused, so nobody can probe what others queried from the cache. Live capture, archived query records, and dnstap export are configured separately: where an organization must account for its DNS, it can archive every query for a number of days (searchable and downloadable in the web interface, and stated on the status page) or export them as dnstap to a SIEM or log collector.
- **Status page** (optional): DNS endpoints, device setup steps, data retention, and a check that shows visitors whether they use the resolver.

## Encrypted DNS

Give the setup wizard (or Settings › Addresses & encryption) a domain that points to the server, and DNSNova obtains and renews a Let's Encrypt certificate (validated on port 443, or on 80 if nothing listens on 443). With the ports under [Install](#install) open, devices then use:

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
- [docs/restricted-networks.md](./docs/restricted-networks.md): resolving where DNS answers are forged or intercepted on the path.
- [docs/private-locality.md](./docs/private-locality.md): answers for where clients are, through exits, with nothing about them sent.
- [docs/server-itself.md](./docs/server-itself.md): programs on the server itself (apt, certificate renewal, mail) using DNSNova.
- [docs/api.md](./docs/api.md): the admin API used by the web interface, for scripts.
- [docs/benchmark.md](./docs/benchmark.md): performance, and how to measure it yourself.
- [tools/resolver-check.sh](./tools/resolver-check.sh): compares a running server with a reference resolver (popular domains, DNSSEC, minimal names, TCP, response times): `bash resolver-check.sh <server-ip>`.
- [CHANGELOG.md](./CHANGELOG.md), [PRIVACY.md](./PRIVACY.md), [SECURITY.md](./SECURITY.md) (report vulnerabilities privately).

Build from source (Go 1.27.4 or later): `CGO_ENABLED=0 go build -o dnsnova ./cmd/dnsnova`. Tests: `go test -race ./...`; every parser is also fuzzed weekly.

## License

[GNU Affero General Public License v3.0](./LICENSE): free for any use, including commercial. If you modify DNSNova and offer it as a network service, you must make your modified source available to its users. For other terms, see the commercial license in [COMMERCIAL.md](./COMMERCIAL.md), or ask at [novaod.com/licensing](https://novaod.com/licensing). Contributions are welcome under the [contributor license agreement](./CONTRIBUTING.md). Third-party components: [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
