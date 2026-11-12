# Privacy

DNSNova runs on your server. This page describes what the software itself
does with data. If you operate a DNSNova server for other people, you are
responsible for telling them how you run it.

## What DNSNova never does

- It never writes queries or client addresses to disk. Everything about
  queries is held in memory and is gone after a restart. The one exception
  is the answer cache of a public server: it is saved (names and their
  records, never who asked or when) so it survives a restart. With many
  users, a cached name says nothing about any one of them. A server for a
  home or office network (private mode), where it would, does not save it.
  `cache.persist` changes either; see the table below.
- It sends no telemetry, usage statistics or crash reports, to anyone.
- It does not forward client IP addresses to upstream resolvers. Upstreams
  see your server's address only. EDNS Client Subnet is off by default; if
  you set `ecs.address`, that one address of your choosing is sent with
  every query, never a client's.
- It does not forward the EDNS options that clients send, such as cookies
  or padding.
- It does not send reverse lookups of private addresses (10.0.0.0/8,
  192.168.0.0/16, fd00::/8 and similar) upstream.

## What is kept, where, and for how long

| Data | Where | How long |
| --- | --- | --- |
| Cached DNS answers | Memory | Their TTL, plus up to `cache.serve_stale` |
| The same answers, in public mode or with `cache.persist = "on"` (names and records; no client addresses, no times of queries) | `/var/lib/dnsnova/cache.bin`, mode 0600, saved every 10 minutes and on shutdown | Replaced at each save; answers past their TTL plus `cache.serve_stale` are left out. Deleted when saving is off (private mode, or `cache.persist = "off"`) and when the cache is cleared |
| DNS Cookie secret (makes server cookies; no client data) | `/var/lib/dnsnova/secrets/cookie-secret`, mode 0600 | Until you delete it (a new one is then made) |
| Counters and response-time histograms | Memory | Until the process stops |
| Rate-limit state (per client address or network) | Memory | About a minute after the last query |
| Configuration and its previous versions | `/etc/dnsnova/` | Until you delete them (10 versions are kept) |
| Statistics history for the admin charts (totals and response times, no addresses or names) | Memory | Up to 7 days; lost on restart |
| Most queried domains and domains that do not exist (domain and count only; see below) | Memory | Up to 7 days; lost on restart |
| Names whose answers failed DNSSEC validation (name, type, reason, count, first and last time; no client data) | Memory | The 200 most recent; lost on restart or when cleared on the DNSSEC page |
| Networks that hit the rate limits (IPv4 /24, IPv6 /48, and a count) | Memory | 24 hours; lost on restart |
| Status page check names (random token and protocol, no address) | Memory | 5 minutes |
| Query log, only while an administrator runs it (see below) | Memory | At most 10,000 queries; deleted an hour after it stops |
| Recent log records shown in the admin interface | Memory | The last 200; lost on restart |
| Administrator name, password hash (Argon2id) and two-step verification secret | `/var/lib/dnsnova/secrets/admin.json`, mode 0600 | Until you remove them |
| One-time setup code | `/var/lib/dnsnova/secrets/setup-code`, mode 0600 | Until the administrator is created |
| Admin sessions | Memory | 12 idle hours, 7 days at most; lost on restart |
| Service log | journald | Your journald retention |

The service log records start-up, errors, configuration changes (with the
administrator who made them) and admin logins, including failed ones with
the client address. It does not record queries.

The web interface is served from the binary itself. It loads no fonts,
scripts or images from other sites, and its Content Security Policy forbids
it to. It keeps the appearance (dark, light or auto) in the browser's local
storage. For as long as the tab is open it also keeps the chart's range and
view, and the upstreams' response times it has seen, to draw their trend;
nothing about clients or queries.

## Domain lists

The admin overview lists the most queried domains and the domains that do
not exist. Names are reduced to the domain they belong to
(`mail.example.com` counts as `example.com`), and reverse lookups are
counted together. No client addresses are kept for these lists.

A domain that only a few people visit could still say something about
them, so a domain is listed only once at least five different networks
(IPv4 /24, IPv6 /48) asked for it within one hour. To check this without
storing addresses, each domain carries a 64-bit sketch: a network sets one
bit, chosen by a hash with a random key. The key is replaced every hour and
never stored, so the sketch cannot be turned back into addresses, and it is
discarded with the hour.

## Status page check

The public status page (off by default) can tell a visitor whether their
device uses this server. The page makes the browser look up a random,
one-time name under `check.<domain>`. If that query reaches DNSNova, it
keeps the name and the protocol it arrived over, in memory, for five
minutes, so the page can ask about it. It does not keep the address it came
from. Queries for these names are answered locally and never sent upstream.

## Query log

There is no setting that writes queries to a file or to the system log.
For troubleshooting, an administrator can start the query log in the admin
interface:

- It runs for 15 minutes, 1 hour, 6 hours or 24 hours, then stops by itself.
  A restart stops it too.
- It records the time, client, protocol, name, type, result, whether the
  answer came from the cache, and how long it took.
- Client addresses are shortened (`203.0.113.x`, the first 48 bits of IPv6)
  unless the administrator asks for full addresses when starting it.
- It is held in memory, at most 10,000 queries, and deleted an hour after it
  stops, or at once with "Stop and delete".
- The service log records who started it, for how long and whether full
  addresses were kept. The admin status shows whether it is running.

`[log] queries` from earlier versions is still accepted in the configuration
file, but does nothing and produces a warning.

## Metrics

The `/metrics` and `/healthz` endpoints expose counts and timings only:
no client addresses and no query names. `/metrics` names the upstream
servers you configured, so keep it on a private address.

## Alerts

Alerts are off unless you turn them on, and go only to the destinations you
set up (docs/alerts.md). They describe the server: upstreams, error rates,
response times, the certificate, configuration errors. They carry no client
addresses. One alert names domains: DNSSEC failures lists the names whose
answers failed validation, as the DNSSEC page does, without who asked for
them. The service you send alerts to (Telegram, Discord, Slack, your
webhook) receives that text.
