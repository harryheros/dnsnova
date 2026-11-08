# Privacy

DNSNova runs on your server. This page describes what the software itself
does with data. If you operate a DNSNova server for other people, you are
responsible for telling them how you run it.

## What DNSNova never does

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
| Service log | journald | Your journald retention |

The service log records start-up, errors and configuration changes. It does
not record queries.

## Query logging

`[log] queries = true` writes every query (client address, name, type,
result) to the service log. It is off by default and is meant for
troubleshooting; turn it off again afterwards. Later releases will replace it
with a temporary in-memory log that turns itself off.

## Metrics

The `/metrics` and `/healthz` endpoints expose counts and timings only:
no client addresses and no query names. `/metrics` names the upstream
servers you configured, so keep it on a private address.
