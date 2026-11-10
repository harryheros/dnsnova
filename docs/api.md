# Admin API

Everything the DNSNova web interface does goes through this API, so scripts
and tools such as Ansible can do the same. The interface has no special
access of its own.

The API is served on `[admin] listen` (port 7000 by default when the
installer sets it up). All endpoints are under `/api/v1/` and use JSON.
The web interface itself is served on the same port: `/` and `/assets/`,
built into the binary, with a Content Security Policy that allows no inline
code and no other origins. `/#setup=CODE` opens the setup wizard with the
code filled in.

## Access

- **Host names.** Requests are answered only when the `Host` header is an IP
  address, `localhost`, or one of `tls.domains`. Anything else gets `421`.
  This stops other web pages from reaching the API through a visitor's
  browser (DNS rebinding).
- **HTTPS.** The admin port speaks HTTPS as soon as a certificate is
  available, on the same port as plain HTTP. When the admin interface is
  reachable from other machines, plain requests addressed to one of
  `tls.domains` are redirected to HTTPS.
- **Sessions.** `POST /api/v1/setup` and `POST /api/v1/login` set a
  `dnsnova_session` cookie (`HttpOnly`, `SameSite=Strict`, `Secure` over
  HTTPS) and return a `csrf` token. Sessions live in memory: they end after
  12 hours without use, after 7 days in any case, and when DNSNova restarts.
- **State-changing requests** (`POST`, `PUT`, `PATCH`, `DELETE`) must:
  - send their body as `Content-Type: application/json`;
  - carry the session's token in an `X-CSRF-Token` header (except setup and
    login);
  - come from the same origin, if they send an `Origin` header.
- **Lockout.** Five failed logins, setup codes or password checks within 15
  minutes lock the client out for 15 minutes (`429` with `Retry-After`).
  IPv6 clients are counted per /64.
- **Errors** are `{"error": "…"}` with a suitable status. Validation errors
  also list `problems`: `[{"line": 12, "key": "server.mode", "message": "…"}]`.

A session from the command line:

```sh
api=http://127.0.0.1:7000/api/v1
csrf=$(curl -s -c jar -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"…"}' $api/login | jq -r .csrf)
curl -s -b jar $api/status
curl -s -b jar -X POST -H "X-CSRF-Token: $csrf" $api/cache/clear
```

## Setup and sign-in

| Method and path | Body | Result |
| --- | --- | --- |
| `GET /setup` | | `{"needed": true, "code_required": false, "secure": false}`: whether an administrator still has to be created, whether this client must give the setup code (not from loopback, private networks or the installer's SSH address; a request forwarded by a reverse proxy, recognised by its Forwarded, X-Forwarded-For, X-Real-IP or Via header, always needs the code), and whether this connection is HTTPS |
| `POST /setup` | `{"code", "username", "password"}` | `201` and a session. `code` is the one-time setup code from `<data_dir>/secrets/setup-code`, which the installer prints: 8 letters and digits as `XXXX-XXXX`; case, spaces and dashes are ignored. After 20 wrong codes from any addresses, a new code replaces it. Passwords need at least 10 characters. |
| `POST /login` | `{"username", "password", "totp"}` | A session: `{"username", "csrf", "totp", "secure", "client_ip"}`. With two-step verification on and no `totp`, `401` with `"totp_required": true`. |
| `POST /logout` | | `204` |
| `GET /session` | | `{"username", "csrf", "totp", "secure", "client_ip"}`. `client_ip` is the address DNSNova sees, used by the setup wizard to fill in the allow list. |

## Account

| Method and path | Body | Result |
| --- | --- | --- |
| `POST /account/password` | `{"current", "new"}` | `204`. Every other session is logged out. |
| `POST /account/totp` | | `{"secret", "uri"}` to add to an authenticator app (`uri` is an `otpauth://` link for a QR code). Not active until confirmed. |
| `POST /account/totp/confirm` | `{"code"}` | `204`: two-step verification is on. |
| `DELETE /account/totp` | `{"password"}` | `204`: two-step verification is off. |

Codes are TOTP (RFC 6238: SHA-1, 6 digits, 30 seconds), accepted one step
early or late, and each code works only once.

## Status

| Method and path | Result |
| --- | --- |
| `GET /status` | Version, start time, mode, domains, every open listener by protocol, certificate state, cache size, privacy facts, configuration warnings and `filter` (`{"enabled", "rules", "lists": [{"source", "rules", "skipped", "updated", "checked", "error"}]}`). |
| `GET /stats?range=1h\|24h\|7d` | Totals for the range: queries by protocol (`udp`, `tcp`, `dot`, `doh`, `doh3`, `doq`), rejections by reason, answers by source, `cache_ratio`, response-time percentiles (`p50_ms`, `p95_ms`) for cache hits, upstream answers and all; `series`, one point per minute, five minutes or hour, for charts; `top_domains` and `top_nxdomains` (`[{"name", "count"}]`, domains asked for by at least 5 networks within an hour); and `top_limited_networks`, the /24 and /48 networks that hit the rate limits most (at most the last 24 hours). Kept in memory only. |
| `GET /querylog?limit=500&q=` | The query log: `{"state": {"on", "until", "full_ip", "stopped", "count"}, "entries": [{"time", "client", "proto", "name", "type", "rcode", "source", "ms", "filtered"}]}`, newest first. `source` is `blocked` for a name the filter answered; `filtered` marks queries that came in through a filtered address. `q` keeps entries whose name or client contains it. |
| `GET /upstreams` | Each upstream: `address`, `role` (`primary` or `fallback`), `healthy`, `latency_ms` (smoothed), `queries`, `errors`, `last_ok`, `last_error`. |
| `GET /events?limit=50` | Recent log records, newest first (up to 200): start-up, errors, setting changes with the user and keys, certificates. Queries are never among them. |
| `POST /cache/clear` | `204` |
| `POST /filter/update` | `204`: downloads every filter list now, whatever its age, and applies them. |
| `POST /stats/clear` | `204`: forgets the statistics and domain lists (Prometheus counters keep counting). |
| `GET /guide` | The setup guide's data: the status page fields, `plain` with every address DNS listens on, and `profile`, where the Apple profile can be downloaded (null when the status page is off). |

## Query log

| Method and path | Body | Result |
| --- | --- | --- |
| `POST /querylog` | `{"minutes": 15\|60\|360\|1440, "full_ip": false}` | Starts the query log: `{"state"}`. Earlier records are deleted. Client addresses are shortened unless `full_ip` is true. It stops by itself after `minutes`; its records are deleted an hour later. |
| `DELETE /querylog` | | `204`: stops it and deletes every record. |

Starting and stopping are written to the service log with the user, the
length and `full_ip`. `GET /status` reports `privacy.query_log` and
`privacy.query_log_full_ip`, and `privacy.client_subnet`: the network sent
as EDNS Client Subnet (`ecs.address`), or `""` when off.

## Tools

| Method and path | Body | Result |
| --- | --- | --- |
| `GET /system/addresses` | | `{"addresses": [{"address", "interface", "public", "loopback"}]}`: the server's IP addresses, for choosing `server.listen`. |
| `POST /tools/lookup` | `{"name", "type", "upstreams"}` | `{"results": [{"upstream", "rcode", "answers", "ms", "error"}]}`: asks each upstream directly, bypassing the cache, in parallel with a 5-second limit. `type` is a record type such as `A` or `HTTPS`; `upstreams` is optional; by default the configured ones are asked. |

## Public status page

Not part of the admin API: when `[status] enabled = true`, these are served
on the DNS-over-HTTPS addresses, without sign-in. In private mode they are
404 for clients outside `access.allow`.

| Method and path | Result |
| --- | --- |
| `GET /` | The page. |
| `GET /status.json` | `{"domain", "mode", "healthy", "encrypted", "doh", "http3", "dot", "doq", "plain", "check", "query_log", "query_log_full_ip", "filtered"}`. `plain` lists public port-53 addresses in public mode; `filtered` (only while filtering is on) holds the filtered service's `doh`, `dot`, `doq`, `plain` and `rules`. |
| `GET /check/{token}` | `{"seen", "proto"}`: whether a query for `{token}.check.<domain>` reached this server in the last five minutes, and over `udp`, `tcp`, `dot`, `doh`, `doh3` or `doq`. Tokens are 16 to 40 letters and digits. |
| `GET /dnsnova.mobileconfig?p=doh` | An Apple configuration profile for DNS over HTTPS (`p=dot`: DNS over TLS, only when it listens on port 853; `p=doh-filtered` and `p=dot-filtered`: the filtered service, installed next to the unfiltered one). |

Queries for `{token}.check.<domain>` are answered by DNSNova itself
(NXDOMAIN, not cached) and never sent upstream.

## Configuration

The API edits the same file you would edit by hand,
`/etc/dnsnova/dnsnova.toml`. Only the lines of the settings that change are
rewritten; comments, blank lines and order stay as they are. Every write
needs the `hash` of the version it was based on, so a change made in the
meantime (by hand or in another browser tab) is never overwritten: such a
write gets `409` with the current `hash`.

A change is validated first, written atomically, and then applied without a
restart. If it cannot be applied (for example, a port is already in use),
the previous file is put back and the response is `422` with
`"reverted": true`. The previous ten versions of the file are kept.

| Method and path | Body | Result |
| --- | --- | --- |
| `GET /config` | | `{"hash", "settings", "warnings"}`. Each setting: `key`, `value` (in force), `default`, `in_file`, `line`. |
| `POST /config/preview` | an edit | What the edit would do, without writing anything: `changes`, `diff`, `warnings`, `restart_required`. |
| `PATCH /config` | an edit | The same, applied. `hash` is the new version's. |
| `GET /config/file` | | `{"hash", "content"}`: the whole file. |
| `PUT /config/file` | `{"hash", "content", "preview"}` | Replaces the whole file; with `"preview": true` only checks it. |
| `GET /config/history` | | `{"versions": [{"name", "saved"}]}`, newest first. |
| `GET /config/history/{name}` | | `{"name", "content", "diff"}`: a saved version and how it differs from the current file. |
| `POST /config/history/{name}/restore` | `{"hash"}` | Makes that version current. The version it replaces is saved too, so a restore can be undone. |

An edit names settings as `table.key`, the way the file groups them:

```json
{
  "hash": "9f2c…",
  "set": {
    "doq.listen": ["203.0.113.10:853"],
    "doh.http3": true,
    "limits.client_qps": 30,
    "upstream.timeout": "2s"
  },
  "unset": ["cache.size"]
}
```

Values are JSON strings, numbers, booleans or arrays of strings. Durations
are strings such as `"500ms"`, `"3s"` or `"24h"`, or a number of seconds.
`unset` removes a setting from the file, so its default applies.

The result of a preview or a change:

```json
{
  "hash": "4b1e…",
  "changes": [{"key": "doq.listen", "from": [], "to": ["203.0.113.10:853"]}],
  "diff": [
    {"op": " ", "old": 7, "new": 7, "text": "[doq]"},
    {"op": "-", "old": 8, "text": "listen = []"},
    {"op": "+", "new": 8, "text": "listen = [\"203.0.113.10:853\"]"}
  ],
  "warnings": [],
  "restart_required": []
}
```

`diff` shows changed lines with two lines of context; a jump in the line
numbers marks a gap. `restart_required` lists changes that take effect only
after a restart (`server.data_dir`).
