# DNSNova

> A secure, lightweight DNS server for your home, office or a public resolver.

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](./LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-lightgrey.svg)](#)
[![CI](https://github.com/harryheros/dnsnova/actions/workflows/ci.yml/badge.svg)](https://github.com/harryheros/dnsnova/actions/workflows/ci.yml)

DNSNova answers your devices' DNS queries from its cache or from upstream resolvers you choose (Cloudflare, Quad9, Google or your own), over plain or encrypted DNS. It is set up and managed in the browser, keeps no logs of your queries, and is safe to put on the internet.

## Install

On Linux with systemd (amd64 or arm64), as root:

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sh
```

As a normal user it asks for your sudo password; without sudo (common on Debian), log in as root first with `su -`.

When it finishes, it prints the addresses of the web interface:

```
DNSNova is installed and running.
Open one of these addresses and follow the setup wizard:
  http://192.168.1.10:7000
  http://127.0.0.1:7000
```

Open one and follow the wizard: administrator password, the addresses and port to answer on, upstreams, and optionally a domain for encrypted DNS. DNS starts when you finish, and the last page says what to set on your router or devices.

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sh -s -- -u
```

This keeps the configuration in `/etc/dnsnova`. To remove everything, add `--purge`:

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sh -s -- -u --purge
```

To upgrade, run the install command again: the configuration is kept, and if the new version does not start, the previous one is put back.

Forgot the administrator password? Run `dnsnova -reset-admin` on the server; the web interface then offers to create the administrator again, and every setting is kept.

## What it does

- **Plain and encrypted DNS**: UDP and TCP on port 53, DNS over TLS, DNS over QUIC and DNS over HTTPS (HTTP/2 and HTTP/3), with an automatic Let's Encrypt certificate.
- **Its own resolver, or forwarding**: resolve names itself from the root servers, with DNSSEC validation and minimal names (no third party sees the queries), or forward to upstreams such as Cloudflare or Google over DNS over HTTPS, TLS or QUIC. With both, the upstreams step in when a domain's own servers cannot be reached.
- **Web interface**: response times, traffic, upstream health, most queried domains, every setting with a preview before it is applied, a setup guide for each kind of device, and light and dark appearance.
- **Optional filtering, without forcing it on anyone**: one server, two doors. The usual addresses answer everything; a second address, name or DoH path blocks ads, trackers and malware (the [ShieldNova](https://github.com/harryheros/shieldnova) list by default, or any AdGuard-style, hosts or domain list). Lists update by themselves, a broken update never replaces a good list, and a wrongly blocked domain is allowed again with one click in the query log. Trackers disguised as a site's own subdomain (CNAME cloaking) are blocked too.
- **Local names** such as `nas.home`, and a list of blocked clients.
- **Public or private**: open to everyone with rate limits that stop abuse, or only to the networks you list.
- **Fast**: on a single CPU core, about 200,000 answers per second from the cache, 94,000 over DNS over TLS, and 23,000 for names it has to look up; a 225,000-rule blocklist costs about 14%. [How this was measured](./docs/benchmark.md).
- **Built for busy servers**: one UDP socket per CPU core, cache hits answered without extra work, failures remembered briefly so a broken domain cannot flood the upstreams, and Extended DNS Errors that tell clients why an answer failed.
- **Privacy**: queries and client addresses are never written to disk, no telemetry. A query log for troubleshooting runs in memory and stops by itself. See [PRIVACY.md](./PRIVACY.md).
- **Status page** (optional): a public page with the addresses, setup steps, and a check that shows a visitor whether their device is using the server.

## Encrypted DNS

Give the setup wizard (or Settings › Encrypted DNS) a domain that points to the server. Port 443 must be reachable while the certificate is issued; open TCP 853, UDP 853 and TCP + UDP 443 in the firewall. Devices then use:

| Protocol | Address |
|---|---|
| DNS over TLS | `dns.example.com` |
| DNS over QUIC | `quic://dns.example.com` |
| DNS over HTTPS | `https://dns.example.com/dns-query` |

## More

- [`dnsnova.example.toml`](./dnsnova.example.toml): every setting, explained. The file is `/etc/dnsnova/dnsnova.toml`; changes apply when it is saved.
- [docs/api.md](./docs/api.md): the admin API used by the web interface, for scripts.
- [docs/benchmark.md](./docs/benchmark.md): performance, and how to measure it yourself.
- [tools/resolver-check.sh](./tools/resolver-check.sh): checks a running server from the outside (popular domains, DNSSEC, minimal names, TCP, response times) next to a reference resolver: `bash resolver-check.sh <server-ip>`.
- `install.sh --help`: options to configure everything from the command line instead.
- [CHANGELOG.md](./CHANGELOG.md), [SECURITY.md](./SECURITY.md) (report vulnerabilities privately).

Build from source (Go 1.27 or later): `CGO_ENABLED=0 go build -o dnsnova ./cmd/dnsnova`. Tests: `go test -race ./...`.

## License

[GNU Affero General Public License v3.0](./LICENSE). If you modify DNSNova and offer it to others as a network service, you must make your modified source available to them.

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
