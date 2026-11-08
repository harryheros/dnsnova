# Privacy

DNSNova runs on your server. This page describes what the software itself
does with data. If you operate a DNSNova server for other people, you are
responsible for telling them how you run it.

## What DNSNova never does

- It never writes queries or client addresses to disk. Everything about
  queries is held in memory and is gone after a restart.
- It sends no telemetry, usage statistics or crash reports, to anyone.
- It does not forward client IP addresses to upstream resolvers. Upstreams
  see your server's address only. (EDNS Client Subnet is not sent.)
- It does not forward the EDNS options that clients send, such as cookies
  or padding.
- It does not send reverse lookups of private addresses (10.0.0.0/8,
  192.168.0.0/16, fd00::/8 and similar) upstream.

## What is kept, where, and for how long

| Data | Where | How long |
| --- | --- | --- |
| Cached DNS answers | Memory | Their TTL, plus up to `cache.serve_stale` |
| Counters and response-time histograms | Memory | Until the process stops |
| Rate-limit state (per client address or network) | Memory | About a minute after the last query |
| Configuration and its previous versions | `/etc/dnsnova/` | Until you delete them (10 versions are kept) |
| Statistics history for the admin charts (totals and response times, no addresses or names) | Memory | Up to 7 days; lost on restart |
| Most queried domains and domains that do not exist (domain and count only; see below) | Memory | Up to 7 days; lost on restart |
| Networks that hit the rate limits (IPv4 /24, IPv6 /48, and a count) | Memory | 24 hours; lost on restart |
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
it to. It keeps the appearance (light, dark or auto) in the browser's local
storage, and the chart range for as long as the tab is open.

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
