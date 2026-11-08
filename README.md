# dnsnova

A forwarding DNS server for people who run public or private resolvers on
their own servers: secure by default, light on resources, and easy to
operate.

> **Status: under development.** This is a pre-release of the 1.0 core.
> Built-in DoT, DoH, DoQ and HTTP/3, the web interface, the setup wizard and
> the one-line installer are planned for later stages and are not in this
> release yet.

## What it is

dnsnova forwards queries to upstream resolvers you choose (Cloudflare,
Google, Quad9, your own) and answers from a cache. It is in the same family
as dnsdist, CoreDNS, Blocky and AdGuard Home, not an authoritative server
like BIND or Knot, and not a recursive resolver like Unbound.

It is meant for operators with one or a few VPSs who want a resolver that is
safe to expose to the internet without becoming a DDoS amplifier.

## Features in this release

- **Protocols:** DNS over UDP and TCP (with pipelining). DNS over HTTPS behind
  a reverse proxy such as nginx, which handles TLS, HTTP/2 and HTTP/3.
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
- **No external dependencies:** only the Go standard library.

## Install (manual, until the installer exists)

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
