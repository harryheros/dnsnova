# Alerts

DNSNova can tell you when something is wrong, and again when it is fixed:
on Telegram, Discord, Slack, or any service that takes a JSON webhook
(PagerDuty, Opsgenie, ntfy, n8n, your own). It is off until you turn it on.

## Setting it up

1. In the web interface, open **Settings › Alerts** and set up one or more
   destinations under **Destinations**.
2. Turn on **Send alerts** and apply.
3. Press **Send a test**: each destination says whether it got it.

Destinations are kept in `data_dir/secrets/alerts.json` (mode 0600), not in
the configuration file: webhook addresses and bot tokens are credentials,
so they are not in the configuration history, not copied to a cluster's
followers, and never shown again once saved (only a hint, such as the
host). To change one, replace it.

| Destination | What to enter |
|---|---|
| Telegram | A bot token from @BotFather, and the chat ID (a number, `-100…` for a group or channel, or `@channelname`). Add the bot to the chat first. |
| Discord | A channel webhook: Channel settings › Integrations › Webhooks › New Webhook › Copy Webhook URL. |
| Slack | An Incoming Webhook of a Slack app. |
| Webhook | A URL (`http://` or `https://`) and optionally a signing secret. |
| Heartbeat | A check URL (Healthchecks.io, Uptime Kuma, Better Stack…): see below. |

Messages carry no client addresses. Names in them (a domain that fails
DNSSEC, for example) are sent as plain text: they cannot mention anyone on
Discord or Slack or turn into links.

## What is checked

Every 30 seconds, over the last five minutes. A threshold of 0 turns its
check off.

| Alert | When | Severity | Settings |
|---|---|---|---|
| Every upstream failing | Each upstream's last query failed, for `upstream_down_for` (30s). Queries not in the cache get no answer. Not with recursion. | critical | `upstream_down_for` |
| One upstream failing | At least half of at least 20 queries to it failed, for `upstream_failing_for` (5m), while others answer. | warning | `upstream_failing_for` |
| Many SERVFAIL | SERVFAIL is at least `servfail_ratio` (5%) of at least `servfail_min_queries` (500) answers, for `servfail_for` (5m). Answers refused for DNSSEC are not counted here. Critical from 50%. | warning | `servfail_*` |
| Slow answers | The 95th percentile of the time to answer queries not in the cache is above `latency_p95` (500ms), over at least `latency_min_queries` (100) of them, for `latency_for` (5m). Answers from the cache are not counted: they would hide a slow upstream. | warning | `latency_*` |
| DNSSEC failures | At least `dnssec_failures` (100) answers refused for failing validation. The message names the domains; see the DNSSEC page. | warning | `dnssec_failures` |
| Certificate expiring | `cert_warn_days` (14) days before expiry, critical from `cert_critical_days` (3). | warning, critical | `cert_*_days` |
| Certificate not renewed | The last attempt failed, with its reason. Critical when there is no certificate at all. | warning, critical | |
| Configuration not applied | The configuration file changed on disk but is not valid, with the reason; the previous configuration stays in force. | warning | |
| Block list not updated | A list could not be downloaded; its previous copy stays in use. | warning | |
| Cluster configuration refused | A follower cannot apply the primary's configuration (docs/cluster.md). | warning | |
| Anycast withdrawn | The route has been withdrawn for a minute because the health checks fail. | critical | |
| Node offline | A follower stopped checking in with its primary. | critical | `nodes` |

A problem that shows up and goes away before its time is up sends nothing.
Once sent, it is **resolved** after it has been gone for a minute (so a
value hovering at its threshold does not flap), with how long it lasted.
While it lasts, a reminder goes out every `repeat` (4h; `0s`: once). A
warning that becomes critical is sent again at once.

Every check and setting is in the `[alerts]` table (dnsnova.example.toml)
and in **Settings › Alerts**.

## Delivery

Each destination has its own queue and sends in the background, so a slow
or failing one holds up neither the others nor any DNS query. A send gives
up after 10 seconds and is tried again after 2, 10 and 30 seconds, unless
the destination refused it (a 4xx: wrongly set up). The last 50
notifications, and how each destination took them, are listed under
**Sent**; failures are also in the log.

## Clusters

On a follower nothing is sent: it reports its alerts to the primary with
each sync, and the primary sends them with the node's name (`fra-1/…`).
When a follower stops checking in, the primary sends **Node offline**, and
keeps that node's last alerts open rather than calling them resolved. With
`nodes = false` the primary only reports on itself.

Set the destinations on the primary. Each node can have its own heartbeat.

## Heartbeat

A server that is down, or has lost its network, cannot say so. With a
heartbeat URL, DNSNova requests it every minute while alerts are on; a
monitoring service alerts you when the requests stop. This is the only way
to hear about the server itself going away, so it is worth setting up.

## Webhook format

A `POST` with `Content-Type: application/json`:

```json
{
  "version": 1,
  "status": "firing",
  "key": "upstream_failing:udp://9.9.9.9:53",
  "kind": "upstream_failing",
  "severity": "warning",
  "node": "fra-1",
  "summary": "Upstream udp://9.9.9.9:53 is failing",
  "details": ["31 of 40 queries failed in the last 5 minutes; the others answer instead"],
  "since": "2026-11-11T09:12:00Z",
  "time": "2026-11-11T09:17:00Z",
  "server": "ams-1"
}
```

- `status`: `firing`, `reminder` (still firing), `resolved`, or `test`.
- `key` is the same for every notification about one problem: match
  `firing` and `resolved` on it.
- `node` is where the problem is; `server` is the node that sent it (a
  cluster's primary).
- `version` changes only if a field changes meaning; fields may be added.

With a signing secret, two headers are added:

- `X-DNSNova-Timestamp`: Unix seconds when it was sent.
- `X-DNSNova-Signature`: `sha256=` and the hex HMAC-SHA256, keyed with the
  secret, of the timestamp, a `.`, and the body.

Check the signature, in constant time, and that the timestamp is within a
few minutes, to know a message is from your server and not replayed:

```python
import hmac, hashlib, time

def genuine(secret: bytes, headers, body: bytes) -> bool:
    ts = headers["X-DNSNova-Timestamp"]
    want = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, headers["X-DNSNova-Signature"]) and abs(time.time() - int(ts)) < 300
```

Redirects are not followed: give the final address.

## Alongside metrics

Alerts are for a server, or a small fleet, without a monitoring system. If
you already scrape `/metrics` with Prometheus, alerting there works as well
and can be kept; the two do not interfere.
