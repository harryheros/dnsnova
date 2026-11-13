# Alerts

DNSNova notifies you when something goes wrong and when it is fixed, on
Telegram, Discord, Slack or any JSON webhook (PagerDuty, Opsgenie, ntfy,
n8n, your own). Off by default.

## Setting it up

1. In **Settings › Alerts**, add one or more **Destinations**.
2. Turn on **Send alerts** and apply.
3. Press **Send a test**: each destination reports whether it arrived.

Destinations are credentials, so they are kept in
`data_dir/secrets/alerts.json` (mode 0600) rather than the configuration:
never in its history, never copied to followers, and never shown again once
saved (only a hint, such as the host). To change one, replace it.

| Destination | What to enter |
|---|---|
| Telegram | A bot token from @BotFather, and the chat ID (a number, `-100…` for a group or channel, or `@channelname`). Add the bot to the chat first. |
| Discord | A channel webhook: Channel settings › Integrations › Webhooks › New Webhook › Copy Webhook URL. |
| Slack | An Incoming Webhook of a Slack app. |
| Webhook | A URL (`http://` or `https://`) and optionally a signing secret. |
| Heartbeat | A check URL (Healthchecks.io, Uptime Kuma, Better Stack…): see below. |

Messages carry no client addresses. Domain names in them are sent as plain
text, so they cannot mention anyone on Discord or Slack or become links.

## What is checked

Every 30 seconds, over the last five minutes. A threshold of 0 turns a
check off.

| Alert | When | Severity | Settings |
|---|---|---|---|
| Every upstream failing | Each upstream's last query failed, for `upstream_down_for` (30s). Queries not in the cache get no answer. Not with recursion. | critical | `upstream_down_for` |
| No name server answers | With recursion: no root or authoritative server has answered recently, for `upstream_down_for` (30s). | critical | `upstream_down_for` |
| DNS intercepted | With recursion: the network answers in place of the name servers ([restricted networks](./restricted-networks.md)), for `upstream_down_for`. | critical | `upstream_down_for` |
| One upstream failing | At least half of at least 20 queries to it failed, for `upstream_failing_for` (5m), while others answer. | warning | `upstream_failing_for` |
| Many SERVFAIL | SERVFAIL is at least `servfail_ratio` (5%) of at least `servfail_min_queries` (500) answers, for `servfail_for` (5m). Answers refused for DNSSEC are not counted here. Critical from 50%. | warning | `servfail_*` |
| Slow answers | The 95th percentile response time of queries not in the cache exceeds `latency_p95` (500ms), over at least `latency_min_queries` (100), for `latency_for` (5m). Cached answers are excluded: they would hide a slow upstream. | warning | `latency_*` |
| DNSSEC failures | At least `dnssec_failures` (100) answers refused for failing validation. The message names the domains; see the DNSSEC page. | warning | `dnssec_failures` |
| Certificate expiring | `cert_warn_days` (14) days before expiry, critical from `cert_critical_days` (3). | warning, critical | `cert_*_days` |
| Certificate not renewed | The last attempt failed, with its reason. Critical when there is no certificate at all. | warning, critical | |
| Configuration not applied | The configuration file changed on disk but is not valid, with the reason; the previous configuration stays in force. | warning | |
| Block list not updated | A list could not be downloaded; its previous copy stays in use. | warning | |
| Cluster configuration refused | A follower cannot apply the primary's configuration (docs/cluster.md). | warning | |
| Anycast withdrawn | The route has been withdrawn for a minute because the health checks fail. | critical | |
| Node offline | A follower stopped checking in with its primary. | critical | `nodes` |

A problem that clears before its time is up sends nothing. Once sent, it is
**resolved** after a minute without it (so a value near its threshold does
not flap), with its duration. Meanwhile a reminder goes out every `repeat`
(4h; `0s`: once). A warning that turns critical is sent again at once.

Every check and setting is in the `[alerts]` table (dnsnova.example.toml)
and in **Settings › Alerts**.

## Delivery

Each destination has its own background queue, so a slow or failing one
delays neither the others nor DNS. A send times out after 10 seconds and is
retried after 2, 10 and 30 seconds, except when refused with a 4xx
(misconfigured). **Sent** lists the last 50 notifications and each
destination's result; failures are also logged.

## Clusters

Followers send nothing themselves: they report alerts to the primary with
each sync, and the primary sends them under the node's name (`fra-1/…`). A
follower that stops checking in raises **Node offline**, and its last alerts
stay open rather than resolve. With `nodes = false` the primary reports
only on itself.

Set the destinations on the primary. Each node can have its own heartbeat.

## Heartbeat

A server that is down or offline cannot report it. With a heartbeat URL,
DNSNova requests it every minute while alerts are on, and the monitoring
service alerts you when the requests stop. It is the only way to learn that
the server itself is gone.

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

Verify the signature in constant time and the timestamp within a few
minutes, to know a message is genuine and not replayed:

```python
import hmac, hashlib, time

def genuine(secret: bytes, headers, body: bytes) -> bool:
    ts = headers["X-DNSNova-Timestamp"]
    want = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, headers["X-DNSNova-Signature"]) and abs(time.time() - int(ts)) < 300
```

Redirects are not followed: give the final address.

## Alongside metrics

Alerts serve a server or small fleet without a monitoring system. If you
already scrape `/metrics` with Prometheus, alerting there works as well; the
two do not interfere.
