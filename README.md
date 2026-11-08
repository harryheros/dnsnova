# dnsnova

A forwarding DNS server for people who run public or private resolvers on
their own servers: secure by default, light on resources, and easy to
operate.

> **Status: under development.** This is a pre-release of 1.0. DNS over
> QUIC, DNS over HTTP/3 (served directly), the web interface and the setup
> wizard are planned for later stages and are not in this release yet.

## Quick start

On a Linux server with systemd (amd64 or arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sudo bash
```

The installer downloads the latest release, verifies its SHA-256 checksum,
asks a few questions (which addresses to serve, public or private, which
upstreams to use, and a domain name if you want encrypted DNS), checks that
the configuration is valid and that the ports are free, then starts dnsnova
as a sandboxed systemd service. With a domain, a Let's Encrypt certificate
is obtained and renewed automatically.

Run the same command again to upgrade; the configuration is kept, and if the
new version fails its health check the previous one is restored.

Unattended install:

```sh
curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sudo bash -s -- \
  --yes --mode public --listen 203.0.113.10:53 \
  --upstream https://1.1.1.1/dns-query --fallback https://dns.google/dns-query#8.8.8.8 \
  --domain dns.example.com --email ops@example.com
```

Remove it with `--uninstall` (keeps the configuration) or
`--uninstall --purge` (removes everything). See `install.sh --help` for all
options.

## What it is

dnsnova forwards queries to upstream resolvers you choose (Cloudflare,
Google, Quad9, your own) and answers from a cache. It is in the same family
as dnsdist, CoreDNS, Blocky and AdGuard Home, not an authoritative server
like BIND or Knot, and not a recursive resolver like Unbound.

It is meant for operators with one or a few VPSs who want a resolver that is
safe to expose to the internet without becoming a DDoS amplifier.

## Features in this release

- **Protocols:** DNS over UDP and TCP (with pipelining), DNS over TLS, and
  DNS over HTTPS (HTTP/1.1 and HTTP/2) built in. DoH can also run behind a
  reverse proxy such as nginx, which can then add HTTP/3.
- **Certificates:** obtained and renewed automatically from Let's Encrypt
  with a built-in ACME client (tls-alpn-01 or http-01), or loaded from files
  managed elsewhere and reloaded when they change. 0-RTT is never accepted.
- **Automatic upgrade to encrypted DNS (DDR, RFC 9462):** dnsnova answers
  `_dns.resolver.arpa` with its DoT and DoH endpoints. With
  `tls.ip_addresses = true` the certificate also covers the server's IP
  addresses, which lets Windows 11, iOS and macOS verify the upgrade and switch
  to encrypted DNS by themselves.
- **Upstreams:** UDP, TCP, DNS over TLS and DNS over HTTPS. The fastest
  primaries are queried in parallel; fallback upstreams are used only when
  every primary fails or is slow. Upstream host names are resolved through
  fixed bootstrap servers (plain or encrypted), or pinned to an address.
- **Cache:** serve-stale (RFC 8767), prefetch, coalescing of identical
  queries, negative caching (RFC 2308). Cache keys include the DO and CD bits.
- **Two service modes:**
  - `public`: anyone may query, protected by limits per client, per network
    and for the whole server, response rate limiting (RRL), caps on
    upstream concurrency in total and per domain, refusal of ANY and zone
    transfers, and UDP response size limits.
  - `private`: only listed networks may query; everyone else is dropped
    without a reply.
- **Local answers:** reverse lookups of private, loopback and link-local
  addresses (RFC 6303) and `localhost.` are answered locally and never sent
  upstream.
- **DNSSEC:** signatures are passed through to clients that ask for them;
  the AD bit is only set for clients that ask, and never on answers dnsnova
  builds itself. dnsnova does not validate signatures itself; it relies on
  the upstream resolver.
- **Configuration:** one TOML file. Errors are reported with line numbers.
  Changes are applied without a restart when the file is saved or on
  `SIGHUP`; the cache and statistics are kept.
- **Observability:** Prometheus metrics and a `/healthz` endpoint.
- **Privacy:** no telemetry; queries are not logged unless you turn it on.
  See [PRIVACY.md](PRIVACY.md).
- **No external dependencies:** only the Go standard library, including the
  ACME client.

## Manual installation

Requirements: Linux with systemd, amd64 or arm64.

```sh
# build (Go 1.24 or later)
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dnsnova ./cmd/dnsnova

sudo install -m 755 dnsnova /usr/local/bin/dnsnova
sudo useradd --system --no-create-home --shell /usr/sbin/nologin dnsnova
sudo install -d -o dnsnova -g dnsnova -m 750 /etc/dnsnova /var/lib/dnsnova
sudo install -o dnsnova -g dnsnova -m 640 dnsnova.example.toml /etc/dnsnova/dnsnova.toml

sudoedit /etc/dnsnova/dnsnova.toml   # set mode, listen and upstream
dnsnova -t -c /etc/dnsnova/dnsnova.toml

sudo install -m 644 deploy/dnsnova.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dnsnova
journalctl -u dnsnova -f
```

Only one program can use port 53 on an address. Stop any other DNS server on
the addresses you list (for example `systemctl stop AdGuardHome`).
systemd-resolved listens on 127.0.0.53 only and does not conflict when you
list your public addresses.

## Configuration

Start from [dnsnova.example.toml](dnsnova.example.toml); every setting is
explained there. The minimum is:

```toml
[server]
mode = "public"
listen = ["203.0.113.10:53"]

[upstream]
primary = ["https://1.1.1.1/dns-query"]
```

On hosts with several IP addresses, list each address in `server.listen`
instead of `:53`, so UDP replies leave from the address the query was sent
to.

After editing the file, dnsnova applies it within a few seconds. If the new
file is invalid, the error is logged with its line number and the running
configuration stays in place. Previous versions are kept in
`/etc/dnsnova/history/`.

### Encrypted DNS

```toml
[dot]
listen = ["203.0.113.10:853"]

[doh]
https_listen = ["203.0.113.10:443"]

[tls]
certificate = "acme"
domains = ["dns.example.com"]
ip_addresses = true
```

The domain must point to the server and port 443 must be reachable from the
internet while the certificate is issued (or port 80, if nothing listens on
443). Progress is logged with a `tls:` prefix. Certificates and the ACME
account are stored in `/var/lib/dnsnova`.

### DNS over HTTPS with nginx

Set `[doh] listen = "127.0.0.1:8053"` and proxy to it; see
[deploy/nginx-doh.conf](deploy/nginx-doh.conf). nginx must send
`X-Real-IP` so limits and access lists apply to the real client.

## Metrics and health

With `[metrics] listen = "127.0.0.1:9153"`:

- `GET /metrics`: Prometheus metrics (queries by protocol, answers by
  source, response codes, rejections by reason, response time histograms,
  cache size, per-upstream queries, errors, latency and health).
- `GET /healthz`: `200` with a small JSON body when at least one upstream is
  healthy, `503` otherwise. It contains no addresses, so it can be exposed to
  an external monitor.

## Building and testing

```sh
go vet ./...
go test -race ./...
go test ./internal/dnsmsg -run '^$' -fuzz FuzzParseQuery -fuzztime 1h
```

## License

dnsnova is licensed under the [GNU Affero General Public License v3.0](LICENSE).
If you modify dnsnova and offer it to others as a network service, you must
make your modified source available to them.

Contributions require agreeing to a contributor license agreement, which
will be published before external contributions are accepted.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
