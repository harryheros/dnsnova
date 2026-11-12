# Changelog

All notable changes are listed here. Versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked
**Security**.

## Unreleased

## 1.3.6 (2026-11-12)

- Names in `local.records` are checked more strictly: a name with an
  empty label (`nas..home`, or two dots at the end as in `nas.home..`)
  or with a label that starts or ends with a hyphen (`-nas.home`) is
  refused when the configuration loads, instead of being served as
  written. Such a name was never a valid host name; if one is in your
  configuration, correct it before upgrading. Found by the fuzz tests.
- The fuzz tests run once a week instead of every night.

## 1.3.5 (2026-11-11)

Two more causes of SERVFAIL found the same way as in 1.3.4:

- With QNAME minimisation, a shortened name that no server of a zone
  answers usably is asked again in full, instead of ending the lookup.
  Some servers mishandle names that only exist as part of longer ones
  (Huawei Cloud's CDN name servers, behind nia.gov.cn and others).
- A name server whose only known addresses are IPv6, when they fail, has
  its IPv4 addresses looked up and asked. On a server whose IPv6 path to
  some networks is poor, a zone could fail although its name servers
  answered over IPv4 (esspt.com's, for one).

## 1.3.4 (2026-11-11)

Found by comparing, for some 5,000 domains hosted in Asia, what this
resolver answers with what a large public resolver answers:

- An answer from a zone's server without the AA flag is accepted when it
  is for the very name asked. Some load balancers that zones delegate
  their names to leave AA off (Huawei Cloud's storage endpoints, for
  one); their answers were taken for lame replies and the lookup failed.
- When every address known for a zone's name servers fails, its other
  name servers are looked up and asked. Name servers without glue were
  looked up only partly, two or three of them; when those did not answer
  from where this server is (sgcc.com.cn's, for one), the lookup gave up
  although other name servers would have answered.
- When no name server of a zone gives a usable answer, the error says
  which question, which zone, and what each server did (timed out,
  REFUSED, not authoritative, ...) instead of only "no authoritative
  server answered". It shows in the log of `ecs.client_path`, in Trace a
  lookup and in the DNSSEC page's failures.

## 1.3.3 (2026-11-11)

- Resolving from the root, with DNSSEC on: some names under zones that are
  not signed failed with SERVFAIL ("no authoritative server answered"),
  qqmusic.com among them. To check a zone, the resolver asked its parent
  for the zone's DS record, and some parents (qq.com's servers, for one)
  wrongly send that question down to the child zone instead of answering
  it, which ended the lookup. Two changes:
  - below a zone that is not signed, nothing is checked any more and no DS
    question is asked (RFC 4035 5): the zone above is looked at first. This
    also saves queries for every name under an unsigned domain;
  - a parent server that sends a DS question down is passed over, and the
    parent's other servers are asked, instead of giving up.

## 1.3.2 (2026-11-11)

- Trace a lookup can show how a name resolves for another network: give a
  client network (or an address, which stands for its /24 or /56) under
  "As seen from another network", and every question carries it as EDNS
  Client Subnet. With recursion only. API: `subnet` in
  `POST /tools/trace`.
- `ecs.client_path`: a lookup that gets no answer is logged with the
  reason (timed out, too many queries, no server reachable), the name and
  the network, so a name that fails there can be traced.

## 1.3.1 (2026-11-11)

- `ecs.client_path`: a lookup may take up to 9 seconds instead of 6. Each
  name of such a lookup is asked afresh, and from a server with a lossy
  path to the name servers (Hong Kong to mainland China, for one) the
  first servers tried often do not answer in time; the spare seconds go
  into trying the others. Measured from Hong Kong, a few percent of
  mainland domains failed for this alone.

## 1.3.0 (2026-11-11)

DNSNova grows from a home and office resolver into one for public and
company-wide service: several nodes with one configuration and anycast,
DNS Cookies, PROXY protocol, a cache that survives restarts, a DNSSEC page
and lookup traces, and alerts. Every new feature is off or set safely by
default, and configuration files from 1.2 work unchanged.

**Upgrading from 1.2: check this first.** On a public server
(`server.mode = "public"`), the admin interface no longer opens over plain
HTTP from other machines. If you reach it at `http://` from another
computer, after upgrading either open it through an SSH tunnel
(`ssh -L 7000:127.0.0.1:7000 server`, then http://127.0.0.1:7000), put it
behind a reverse proxy with HTTPS, or give the server a certificate for
the name you use to reach it (Settings › Encrypted DNS): plain HTTP is then
redirected to HTTPS. A home or office
server (private mode) is reached over plain HTTP from its networks as
before. Details below.

Licensing: DNSNova stays AGPL-3.0, free for any use including commercial;
commercial licenses are available for other terms (COMMERCIAL.md).
Contributions are accepted under a contributor license agreement
(CONTRIBUTING.md, CLA.md). The licenses of the components compiled into
the binary are now in THIRD_PARTY_NOTICES.md, included in the release
archives. ShieldNova, the default list of the filtered service, may be used
in DNSNova free of charge, commercial deployments included.

- A query whose OPT record is rejected (FORMERR) no longer keeps a client
  cookie or other EDNS details read before the error. Nothing used them on
  that path; found by the nightly fuzzing.
- `ecs.client_path`: a secret DNS over HTTPS path for measurement tools.
  A query there has its own EDNS Client Subnet sent to the domains' name
  servers (cut to /24 or /56), so a tool sees how names resolve for that
  network, without a public resolver in between. Those answers bypass the
  cache in both directions (delegations and DNSSEC keys are still shared)
  and reach no other client. Needs recursion. On every other path, as
  before, nothing a client sends shapes what name servers are told.
- Alerts (`[alerts]`, off by default; docs/alerts.md): notifications to
  Telegram, Discord, Slack or a signed JSON webhook when every upstream
  fails, one keeps failing, the SERVFAIL share or the response time of
  queries not in the cache stays high, DNSSEC failures pile up, the
  certificate nears expiry or cannot be renewed, a changed configuration
  file or a block list update fails, or anycast withdraws the route; and
  again when it is fixed, with reminders while it lasts. Each has a
  threshold and a time it must last, so a blip does not page anyone.
  Delivery runs in the background, per destination, with a timeout and
  retries; it never holds up a query. In a cluster the followers report
  their alerts to the primary, which sends them (and says when a node
  stops checking in). A heartbeat URL lets an outside monitor notice the
  server being down, which it cannot report itself. Destinations are set
  in Settings › Alerts, with a test button, and kept in
  `secrets/alerts.json` (0600), never shown again.
- DNS Cookies when resolving (RFC 7873, `recursion.cookies`, on by
  default): every question to a name server carries a client cookie made
  for that server (servers cannot link them), and the server cookie it gave
  last time. A UDP answer with another client cookie is forged; so is one
  without a cookie from a server that has always sent one. Either way the
  question goes again over TCP. If the genuine TCP answer has no cookie
  either (anycast instances that differ), cookies are not insisted on for
  that server for an hour, so such servers do not cost a TCP connection
  each time; an attacker cannot cause this, as TCP answers cannot be
  forged. BADCOOKIE is answered once with the new server cookie; a server
  that rejects the option is asked without it. New metric:
  `dnsnova_recursion_cookie_rejected_total{reason}`.
- Clusters: the top bar shows the fleet ("3 of 3 nodes online"; amber when
  a node is offline, unhealthy or behind on settings) and links to the
  Nodes page; a follower says so when it is out of touch with its primary.
  This server's own trouble still comes first.
- **Trace a lookup** (Tools): resolves a name from scratch, without the
  cache, and shows every step: each server asked and what it answered
  (referral, answer, NXDOMAIN, lame, timeout, with its time), each CNAME
  followed, and the DNSSEC verdict on each zone's keys and on the answer,
  with the reason when it fails. With upstreams only, each upstream is
  asked instead. `POST /api/v1/tools/trace`. Ordinary queries do not pay
  for it: same allocations and speed as before.
- **DNSSEC page** (Status, with recursion on): answers by result (secure,
  not signed, failed) and the names whose answers failed validation, with
  the reason (RFC 8914 code and detail), how often and when; each with a
  Trace button. `GET /api/v1/dnssec`. No client data is kept.
- Negative trust anchors (RFC 7646, `recursion.negative_trust_anchors`):
  domains whose answers skip the DNSSEC check, for a domain whose owner
  broke its DNSSEC. Added from the DNSSEC page ("Stop validating…") or in
  the settings, removed with "Validate again"; ordinary settings with
  preview and history, and a startup warning while any is set. Whole
  top-level domains cannot be exempted.
- Tests: DNSSEC is now tested end to end through iteration, against a
  signed hierarchy served as real servers would (good, bad and expired
  signatures, negative trust anchors), and the same hierarchy can be
  served over the network for manual tests (`TestServeSignedFixture`).
- Several servers, one configuration (docs/cluster.md): a `[cluster]`
  primary keeps the settings and followers sync them every few seconds,
  each keeping what its own file sets (its addresses, for example) and
  never the primary's `[cluster]` or `[anycast]`. A follower that cannot
  use new settings keeps the last ones that worked and says why; without
  its primary it keeps answering, and starts again from its copy. The
  exchange is encrypted and authenticated with AES-256-GCM under a shared
  key, with a timestamp and a challenge against replay, so it needs no
  certificates. The web interface gains a Nodes page (state, region,
  settings version, anycast, version, certificate) and `GET /api/v1/cluster`.
  Without `[cluster]` nothing of this runs, and queries never pass through
  it.
- Anycast (`[anycast]`): the server checks itself (it can resolve, and its
  own UDP listener answers) and runs your commands to announce or withdraw
  its route, after `rise` good or `fall` failed checks in a row; at
  shutdown it withdraws first and keeps answering for `drain`. State in
  `/healthz`, the metrics and the Nodes page.
- **Security**: `[cluster]` and `[anycast]` can only be changed in the file
  on the server, never through the admin API, so a stolen admin password
  cannot point a server at another primary or run commands.
- Fuzzing: the configuration merge of a cluster follower (`FuzzMerge`).
- PROXY protocol (HAProxy's, versions 1 and 2) for servers behind a load
  balancer: `server.proxy_protocol` lists the balancers, and from them a
  header is required and gives each client's real address, so access
  lists, rate limits, DNS Cookies and logs see the client rather than the
  balancer. Versions 1 and 2 on TCP, DoT and DoH over HTTPS (the header
  comes before TLS); version 2 on UDP, one header per datagram as dnsdist
  sends it, with answers going back to the balancer without one. From
  anyone else a header is never read. Headers are read off the accept loop,
  so a slow balancer holds up no other connection. DoQ and HTTP/3 have no
  PROXY protocol. The security self-check warns when the list covers
  everyone.
- Fuzzing: new targets for the PROXY protocol header (datagram and stream),
  DNS Cookies, the saved cache file, EDNS options, upstream addresses and
  the network and local-name lists, twelve in all. Each runs briefly in CI
  on every change, and for ten minutes every night (`fuzz.yml`), keeping
  the corpus between nights and uploading any input that fails.
- UDP on Linux reads and sends in batches (recvmmsg and sendmmsg, up to 32
  datagrams per system call): answers from the cache are sent together.
  Under load a call moved 5 to 8 datagrams instead of one, and answers
  from the cache rose from about 163,000 to 190,000 a second on one core
  in the benchmark setup (p50 0.34 to 0.29 ms), where the load generator
  itself was then the limit. What remains is mostly the kernel's work per
  packet; SO_REUSEPORT already spreads that over every core. Other
  systems read one datagram at a time as before.
- `go build -tags pprof` adds the Go profiler on 127.0.0.1:6060, for
  performance work (see docs/benchmark.md); release builds do not have it.
- DNS Cookies (RFC 7873), with the interoperable server cookie of RFC 9018
  that BIND, Knot and Unbound also make: on by default (`server.cookies`).
  A client that sends back its cookie has shown that its address is not
  forged, so response rate limiting no longer applies to it; when RRL would
  answer a client that sent a cookie with a truncated response, it gets
  BADCOOKIE and a fresh cookie instead, and asks again over UDP rather than
  TCP. A malformed COOKIE option is answered FORMERR. The secret is in
  `secrets/cookie-secret`; nodes behind one anycast address share it by
  copying that file. New metrics: `dnsnova_cookie_queries_total{cookie}`
  and `dnsnova_badcookie_total`.
- The answer cache survives restarts on a public server: it is saved to
  `data_dir/cache.bin` every 10 minutes and on shutdown, and loaded before
  the server starts answering. Every saved answer is checked again as a new
  upstream answer, with the current `cache.*` limits; a damaged file is
  ignored. `cache.persist = "auto"` (the default) saves it in public mode
  and not in private mode: with a few users, as at home, the names looked
  up are close to their browsing. `"on"` and `"off"` decide either way.
  Whenever saving is off, and when the cache is cleared, the file is
  deleted.
- **Security**: who reaches the admin interface without HTTPS now follows
  what the server is for. On a server for a home or office network
  (`server.mode = "private"`: the installer's new `--lan`, or "My network"
  in the setup wizard) it opens over plain HTTP from the allowed private
  networks, and the administrator is created there without the setup code,
  as before. On a public server, plain HTTP is answered only on the server
  itself (loopback, an SSH tunnel) or for a reverse proxy there that sends
  `X-Forwarded-Proto: https`; other machines are redirected to HTTPS when
  the certificate covers the name they used, and otherwise refused with
  directions. The setup code is needed from everywhere but the server
  itself: a private address on a public server (a cloud network) says
  nothing about who is behind it. Behind such a proxy the session cookie is
  now `Secure`.
- **Security**: the installer no longer writes the SSH client's address to
  `secrets/setup-trust` to skip the setup code from there: behind a shared
  or carrier-grade NAT, that address also belongs to other people. A
  leftover file is removed at startup, with a warning.
- **Security**: a self-check at startup, and after each settings change,
  logs (and shows among the events) what weakens the server: on a public
  server, an admin port open to other machines without a certificate, or
  without two-step verification; secrets, the TLS key or the configuration
  file readable or writable by other users; metrics open to other machines;
  public mode without rate limits or with ANY answered; running as root.
- Installer: `--lan` installs for a home or office network (private mode for
  the private networks, web interface open to them). Without it, the
  install is for the internet: the web interface listens on 127.0.0.1 and
  the installer prints the SSH tunnel command; on a machine with only
  private addresses it also mentions `--lan`.
- **Security**: with DNSSEC, a validated negative answer (NXDOMAIN or no
  data) could stay in the cache, and be served as secure (AD), after the
  signatures that proved it had expired. It is now kept no longer than the
  SOA's and the NSEC/NSEC3 records' signatures; the same limit applies to
  wildcard answers and to the NSEC records remembered for RFC 8198.
- A panic while answering one query is now answered SERVFAIL and logged
  with its stack, instead of stopping the whole server (UDP, TCP) or, for
  DoH, leaving every later query for the same name waiting forever.
- DoH: a POST must have the exact media type application/dns-message
  (parameters allowed), and a body over 65535 bytes is refused with 413
  instead of being cut off and answered.
- Settings history: versions saved within the same millisecond no longer
  replace each other.
- Public status page: with recursion on, the server is shown as working
  when the resolver works, even without upstreams, as /healthz already did.

## 1.2.0 (2026-11-10)

- New look for the web interface ("Deep Ocean", see docs/design.md): dark
  by default, a brand rail with the new trident and a chrome wordmark set
  in Exo 2 ExtraBold (SIL OFL 1.1, stored as outlines, no font is loaded),
  and a top bar with search, the server's state and an account menu
  (appearance, sign out).
- The overview is rebuilt: four key figures (queries per second, response
  time, cache hit rate, uptime) with trend lines and, once the server has
  run long enough, the change against the previous period; a traffic chart
  of queries per second or response time; Traffic Flow, showing queries
  arriving by protocol and where answers come from; then top domains,
  upstreams with their latency trend, recent activity and the details.
- The Upstreams page opens with a summary (healthy, latency, success rate,
  queries) and a latency trend per upstream.
- Sign-in, setup and the public status page use the new mark and colors.
- Built for long shifts: light is kept to the brand; charts, figures and
  tables are flat and high-contrast, and nothing on screen moves on its own.

## 1.1.1 (2026-11-10)

- **Security**: DNS over HTTPS connections were not counted toward
  `limits.tcp_connections`. A client could open them until the server ran
  out of file descriptors, which stops every service, the resolver's own
  queries included. They now count like TCP and DoT connections.
- **Security**: new `limits.client_connections` (default 100): open
  connections from one address (IPv4, or IPv6 /56) over TCP, DoT, DoH and
  DoQ together, so that one address cannot take every connection. The
  machine itself and trusted proxies are not limited. An address with
  half of them open must prove it is real (QUIC Retry) before opening
  more over QUIC, so forged packets cannot use up a real client's share.
- The ECS setting's help is shorter.

## 1.1.0 (2026-11-09)

- **Security**: forged answers are noticed. When a question sent over UDP
  draws a run of wrong answers from the address of the server asked (an
  attacker guessing the query ID to poison the cache), it is asked again
  over TCP, which cannot be forged from outside the path. This works for
  the resolver and for plain DNS upstreams; the overview and `/metrics`
  (`dnsnova_recursion_spoofed_total`) count it.
- New: *Check a domain* (Settings › Filtering) tells which lists block a
  name and which rules let it through, with a button to never block it.
  API: `POST /api/v1/filter/why`.
- Filter lists are downloaded only when they have changed: DNSNova asks
  with the list's ETag or date (HTTP 304 when unchanged), and a download
  identical to the copy in use is not processed again.

## 1.0.5 (2026-11-09)

- A change of `ecs.address` now waits for lookups still asking for the old
  network, then clears the cache. An answer for the old network that
  arrived just after the change could be cached before.
- `ecs.address` refuses ranges that are nobody's network on the internet:
  carrier NAT (100.64.0.0/10), documentation, benchmarking, reserved and
  NAT64 addresses.
- `GET /status` reports `privacy.client_subnet`.

## 1.0.4 (2026-11-09)

- New: `ecs.address` (Settings › DNS & upstreams › Resolution, "Answer as
  if from"). The address or network given is sent with every query as its
  EDNS Client Subnet (RFC 7871), so name servers that support it answer as
  they would for that network, wherever the server is. It works with
  recursion (sent to each domain's own name servers, not with the NS, DS
  and DNSKEY questions on the way there) and with upstreams that support
  it. It is one address for everyone, so the cache keeps a single view and
  clients' addresses are never sent; changing it clears the cache. A name
  server that rejects the option is asked again without it. Off by
  default.

## 1.0.3 (2026-11-09)

- **Security**: a reply from an upstream or a name server is matched to
  its query by the exact record type and class. Letter case was ignored
  over the whole question, so type 97 passed for type 65 (HTTPS).
- **Security**: a DNS over HTTPS upstream that answers with a redirect is
  an error. The query is no longer sent on to the address it points to.
- **Security**: a filter list download that is redirected cannot connect
  to this machine or a private network. The address is now checked when
  the connection is made, so a name that resolves to such an address is
  stopped too.
- **Security**: the sign-in page turns extra logins away (503) while
  password checks are queueing, and the table of failed attempts has a
  fixed limit.
- Queries without the "recursion desired" flag are refused. They ask what
  is in the cache, which shows what others have looked up.
- DNSSEC: a validated answer is kept no longer than the TTL of its
  signature record. `cache.min_ttl` does not stretch a validated answer
  for clients that get no signatures either. The "validated" flag (AD)
  is not set on stale answers, nor for clients that check for themselves
  (CD).
- An upstream answer with an extended error code (such as BADVERS) is a
  failure. It was read as "no such data" and cached.
- `limits.global_qps` below 1 refused every query.
- `recursion.allow_networks` opens private networks, this machine and the
  local link. It no longer opens addresses that are never a name server
  (0.0.0.0/8, multicast, broadcast), nor IPv6 while `recursion.ipv6` is
  off.
- `recursion.trust_anchors` are checked strictly: no negative numbers,
  digest type 1, 2 or 4, and a digest of the matching length.
- A changed `cache.size` resizes the resolver's own cache without a
  restart, and expired NSEC records are removed every minute.

## 1.0.2 (2026-11-09)

- The setup wizard asks who the server is for: "Anyone on the internet"
  (public mode with its limits, the default) or "My network (home or
  office)", which sets private mode for the private networks (192.168.x.x,
  10.x.x.x, 172.16-31.x.x, 100.64.x.x and IPv6 ULA), so recursion may also
  ask name servers inside them and a router forwarding for every device is
  not limited as one client.
- Private mode always answers the machine itself (127.0.0.1, ::1), without
  listing it in `access.allow`.

## 1.0.1 (2026-11-09)

- Recursion uses IPv6 only where it works. A machine without an IPv6
  route to the internet never tries it (the route is looked up every
  minute; nothing is sent). Sending over IPv6 that is refused (a firewall
  rule, IPv6 turned off in the system, no address to send from) pauses it
  for 10 minutes at once, instead of failing again for every name, which
  could end in SERVFAIL. Where IPv6 works it is used as before.
- `cache.size` is honoured: a small cache was rounded up to 4,096 entries.
- `cache.min_ttl` no longer stretches answers that carry DNSSEC
  signatures, which a validating client could then use past their time.
- Filtering: a CNAME chain too long to check every name (over 32) is
  blocked on the filtered service rather than let through; rules for
  older settings can no longer be published after newer ones when lists
  are rebuilt at the same time.
- Filter list downloads follow at most 5 redirects, never from HTTPS to
  plain HTTP or to an address on this machine or a private network; lists
  fetched over plain HTTP are warned about.
- Recursion remembers at most 100,000 name servers.
- The installer downloads over HTTPS only.
- The installer shows a progress bar while it downloads, when run in a
  terminal.

## 1.0.0 (2026-11-08)

First stable release.

- Web interface made easier on phones and for newcomers: rarely changed
  settings fold under "Advanced"; the overview shows the ports DNSNova
  really listens on and "off" for protocols that are not; empty lists say
  what will appear instead of showing placeholders; the upstreams table
  becomes one card per upstream on narrow screens.
- Default limits sized for a public resolver: 100 queries a second per
  address (burst 400) and 1,000 per network (burst 4,000), since mobile
  carriers put many people behind one address; 10,000 TCP and DoT
  connections and 3,000 DoQ and HTTP/3 connections (measured at about
  25 KB and 70 KB each), as each phone keeps one open.
- Setup in the browser: the wizard asks who can use plain DNS (everyone,
  chosen addresses, with 127.0.0.1 ticked so programs on the server itself
  can use it, or only this server for an encrypted-only resolver), and warns
  that devices and the server's own resolver can only use port 53,
  offers a separate filtered address when there is a domain, and can
  filter everyone instead.
  Encrypted DNS settings start with the domain: entering one chooses a free
  Let's Encrypt certificate and turns on DoT, DoQ and DoH. Let's Encrypt
  reads that answer 404 for a moment after issuance (database replicas a
  few seconds behind) are tried again instead of ordering another
  certificate.
- Recursion (off by default, `[recursion]`): DNSNova resolves names itself,
  from the root servers down, so no third party sees the queries. DNSSEC
  validation from the built-in root keys (KSK-2017 and KSK-2024): RSA,
  ECDSA and Ed25519 signatures, NSEC and NSEC3 proofs, and answers
  synthesised from validated NSEC records (RFC 8198). Forged answers become
  SERVFAIL with an Extended DNS Error saying why. QNAME minimisation
  (RFC 9156), IPv6, TCP and EDNS fallback, protection against cache
  poisoning, name server loops and oversized delegations, and no queries
  into private networks on a public server. The upstreams can step in when
  a domain's own servers cannot be reached, never after a failed DNSSEC
  check. In the setup wizard, the web interface and the metrics.
  Where IPv6 is configured but silently broken, recursion prefers IPv4
  until IPv6 has answered, and turns IPv6 off for 10 minutes after three
  timeouts in a row, instead of waiting for it on many names.
  What is learnt about a name server's speed and failures is forgotten
  after 15 minutes, so a server that timed out once is tried again instead
  of being avoided for good.
- Filtering, as a second door on the same server (off by default,
  `[filter]`). The usual addresses stay unfiltered; clients that want
  blocking use the filtered plain-DNS address (`filter.listen`), a filtered
  name for DoT, DoQ and DoH (`filter.names`, told apart by the TLS name), or
  the DoH path `/filtered`. `filter.all` filters every address instead.
  Blocked names are answered NXDOMAIN with Extended DNS Error 15 (Blocked).
  Answers whose CNAME chain leads to a blocked name are blocked as well
  (trackers disguised as a site's own subdomain), unless the name asked for
  is allowed explicitly.
  Lists in AdGuard (`||domain^`, `@@||domain^`), hosts and plain-domain
  format, by URL or file; the ShieldNova list is suggested. Copies are kept
  on disk, so filtering works at once after a restart and while a list
  cannot be downloaded; an update that loses more than half of a list's
  rules is refused. About 50 ns per check with 200,000 rules.
- Web interface: Settings › Filtering with each list's state and "Update
  now"; blocked answers in the Overview and statistics; in the query log,
  blocked queries are marked, with an "Allow" button that adds the domain
  to `filter.allow`; the setup guide and the status page list the filtered
  addresses, with their own Apple profiles. Prometheus:
  `dnsnova_answers_total{source="blocked"}`.
- About 75% more answers per second for names not in the cache: the
  buffer for each upstream answer over UDP is reused instead of allocated
  (64 KB per query, most of the CPU time went to garbage collection).
- `tools/resolver-check.sh`: checks a running server from the outside next
  to a reference resolver.
- `tools/bench`: a load generator (UDP, DoT, DoH) and a stand-in upstream;
  results and method in docs/benchmark.md.
- Changing `doh.path` on a running server no longer fails with "address
  already in use".

- **Security**: setup through a reverse proxy. Behind nginx or Caddy on the
  same machine every visitor arrives from 127.0.0.1, which counted as "the
  server itself", so the first visitor from the internet could create the
  administrator without the setup code. Requests carrying proxy headers
  (Forwarded, X-Forwarded-For, X-Real-IP, Via, ...) now always need the code.
- **Security**: simultaneous setup requests could each create an
  administrator (the last one stayed, every one got a session). Setup now
  runs one request at a time.
- An upstream's EDNS options are no longer passed to clients. Padding an
  upstream added for its encrypted link reached plain-UDP clients (an
  answer of about 40 bytes could leave as 450), as did cookies and NSID.
  Extended DNS Errors from the upstream are still passed on.
- EDNS version other than 0 is answered with BADVERS (RFC 6891).
- Extended DNS Errors (RFC 8914): Stale Answer when serving from an expired
  entry, Network Error when no upstream answered, Not Supported for ANY and
  zone transfers; the upstream's own (for example DNSSEC Bogus) are kept.
- Resolution failures (SERVFAIL) are remembered for 2 seconds (RFC 9520),
  so a broken domain or an unreachable upstream is not asked again for every
  client. A failure never replaces an answer that can still be served stale.
- EDNS padding (RFC 7830, RFC 8467): answers over DoT, DoH and DoQ are
  padded to blocks of 468 bytes for clients that pad their queries, so the
  size of an encrypted answer reveals less about the name.
- Faster UDP: on Linux each address has one socket per CPU core (up to 16,
  SO_REUSEPORT), and answers from the cache are sent without starting a
  goroutine per query. About 47% more answers per second in a 2-core test.
- Queries are recorded in the query log before the answer is sent, so a
  client that reads the log right after its answer finds the query there.
- Web interface: the Overview no longer stays narrow after visiting Settings
  or the setup guide; no focus ring around the whole page after navigating;
  the median response figure no longer spreads out ("<0.1", not "< 0 . 1").
- golang.org/x/sys is now a direct dependency (SO_REUSEPORT).

- DNS over UDP and TCP; DNS over TLS; DNS over QUIC (RFC 9250, UDP 853);
  DNS over HTTPS over HTTP/1.1, HTTP/2 and HTTP/3 (same port, TCP and UDP),
  built in or behind a reverse proxy. HTTP/1.1 and HTTP/2 responses advertise
  HTTP/3 with Alt-Svc; `doh.http3 = false` turns it off.
- 0-RTT is never accepted on TLS or QUIC.
- QUIC connections are capped (`limits.quic_connections`); when busy, new
  clients must prove their address with a QUIC Retry. Clients outside the
  access list (private mode) are refused before the handshake.
- Automatic certificates from Let's Encrypt through a built-in ACME client
  (tls-alpn-01, http-01, short-lived IP address certificates), or certificate
  files reloaded when they change.
- DDR (RFC 9462): SVCB answers for `_dns.resolver.arpa` advertising the DoT,
  DoH (`alpn=h2,h3` when HTTP/3 is on) and DoQ endpoints.
- Upstreams over UDP, TCP, DNS over TLS, DNS over HTTPS and DNS over QUIC
  (`quic://`, one reused connection, no 0-RTT), with parallel
  primaries, fallback upstreams, bootstrap resolution and pinned addresses.
- Cache with serve-stale, prefetch, coalescing and negative caching.
- Public and private service modes; limits per client, per network and
  global; response rate limiting; upstream concurrency caps in total and per
  domain.
- Local answers for private reverse zones and localhost.
- TOML configuration with line-numbered errors, automatic reload, atomic
  writes and version history.
- Prometheus metrics (queries by protocol, including `doq` and `doh3`) and a
  health endpoint.
- Admin API (`[admin] listen`, documented in docs/api.md): one-time setup
  code, Argon2id passwords, sessions in HttpOnly SameSite=Strict cookies,
  CSRF tokens, Host header checks against DNS rebinding, login lockout,
  optional TOTP two-step verification; status, statistics history (1 hour,
  24 hours, 7 days), upstream health, recent events, cache clearing; reading
  and editing the configuration by key or as a whole file with preview,
  line diff, conflict detection, automatic revert when a change cannot be
  applied, and restore from history. HTTPS on the same port once a
  certificate exists.
- Web interface on the admin port, built into the binary (plain HTML, CSS
  and JavaScript, no external requests, strict Content Security Policy):
  setup wizard, overview with response times, protocols, upstreams, events,
  certificate and privacy; upstream health; settings pages that show every
  change before it is applied; password, two-step verification,
  configuration history and the raw file; Compare upstreams, which asks
  every upstream the same question and shows each answer and its time. Light and dark appearance, or follow the system.
- Admin API: `GET /system/addresses`, `POST /tools/lookup`, and `client_ip`
  in session responses.
- Colors with jobs, as in AdGuard Home: green main buttons and switches,
  softer blue for links and the current page, a color mark per key figure,
  deep-grey text and lightly shadowed cards, in light and dark.
- Sign-in page as in AdGuard Home: the form, "Forgot password?" with what
  to do, and a footer with links and the appearance as three icons.
- `dnsnova -reset-admin`: for a forgotten password, removes the
  administrator account and restarts DNSNova; settings are kept and the
  web interface offers to create the account again.
- Install as root with `curl ... | sh` (no sudo needed, as many Debian
  systems have none); as a normal user it uses sudo when there is one.
- The name in the sidebar is larger.
- Setup wizard: the address list was empty under systemd, because the
  sandbox did not allow the netlink socket that lists network interfaces
  (the unit now allows AF_NETLINK). The wizard also offers "All addresses
  of this server" (and falls back to it when none are listed) and a port
  other than 53. The public/private step is gone (Public is the default;
  Private stays in Settings › Access & limits). "Next" instead of
  "Continue". On phones the steps are a compact bar.
- Changing between one address and all addresses on the same port (DNS or
  the web interface, for example ":7000" to "127.0.0.1:7000") no longer
  fails with "address already in use".
- Installer: lists every address of the web interface when it finishes,
  with the service and uninstall commands; `-u` uninstalls; it also works
  when piped to `sh`. A silent exit after installing, when no SSH session
  was found, is fixed.
- README shortened to install, uninstall, what DNSNova does and where to
  read more.
- Local names (`[local] records`, Settings › DNS & upstreams): names such
  as "nas.home 192.168.1.5" or "*.lab.home 10.0.0.9" answered by DNSNova
  itself, never sent upstream.
- Blocked clients (`access.deny`, Settings › Access & limits): addresses or
  networks that never get an answer, in either mode.
- Setup guide (Tools › Setup guide): the server's addresses and steps for
  Android, iPhone and Mac, Windows, browsers, the router and Linux, for
  plain DNS on a home network as well as encrypted DNS. Shared with the
  public status page.
- Statistics retention (`[stats] retention`: 24h, 7d or 30d, in memory) and
  "Clear statistics" (Settings › Admin); the overview offers 30d when kept.
- Setup without a code from the server itself, private networks, and the
  address the installer was run from over SSH; the installer prints a
  plain address. Only visitors from elsewhere on the internet are asked for
  the setup code.
- Installing is like AdGuard Home: the installer asks nothing, starts only
  the web interface (port 7000) and prints its address with the setup code,
  using the server's LAN or public address. The wizard sets the
  administrator, the interface's port and reach, who may use the server,
  addresses (all real interfaces preselected), upstreams (Cloudflare and
  Quad9 over DoH filled in) and encrypted DNS; DNS starts when it is
  finished, and a last page says what address to give devices or the
  router. The configure-everything options remain for scripts.
- A configuration without DNS listeners is valid while the admin interface
  is on (a fresh install); /healthz reports "setup".
- The setup code, when it is asked for, is short: 8 characters as
  XXXX-XXXX (no 0/O/1/I/L), case and dashes ignored; 20 wrong codes from
  anywhere replace it.
- The admin layout no longer drops the sidebar above the page at widths
  between phone and desktop (landscape phones, "desktop site" mode).
- Public status page (`[status] enabled`, off by default) at the DoH
  address: addresses with copy buttons, setup steps per platform (Android,
  iPhone and Mac with a downloadable configuration profile, Windows,
  browsers, routers and Linux), what the server keeps, whether the query
  log is on, and "is this device using it?", answered with a one-time check
  name under check.<domain> that DNSNova notes (token and protocol only) for
  five minutes. No statistics; private mode limits it to allowed networks.
- Overview as a fixed grid: equal card heights, fixed list lengths with
  placeholders, so it looks the same with little data as with a lot.
- Interface polish: navigation and event icons (line icons in the style of
  Lucide, ISC), a clearer summary with three key figures, a response-time
  chart with an area, a pointer readout and an empty state, upstream states
  Healthy, Slow, Failing and Standby with success rates, repeated events
  folded into one, and a blue-grey dark appearance. The design rules are in
  docs/design.md.
- Privacy: queries and client addresses are never written to disk.
  `[log] queries` no longer logs anything (it is accepted with a warning).
  Instead, the admin interface has a query log held in memory: it runs for
  15 minutes to 24 hours and stops by itself, shortens client addresses
  unless asked not to, keeps at most 10,000 queries and deletes them an hour
  after it stops. Starting it is recorded in the service log and shown in
  the status.
- Overview lists the most queried domains and domains that do not exist
  (by registrable domain, only once 5 networks asked within an hour, using
  an hourly-keyed sketch instead of addresses), and the networks that hit
  the rate limits most. All in memory.
- CI: actions/checkout v5 and actions/setup-go v6 (Node 24). The QUIC
  connection-cap test now allows for a lost close packet on busy runners.
- golang.org/x/net is now a direct dependency (public suffix list).
- Durations of a second or more read back as `1.5s` rather than `1500ms`.
- The installer asks whether the admin interface is local (SSH tunnel) or
  public (`--admin local|public|off`, `--admin-port`) and prints a setup
  link with the one-time code. Existing installations are not changed: add `[admin]` to enable it.
- First third-party dependency: quic-go v0.65.0 (MIT, with its golang.org/x
  dependencies), for DoQ and HTTP/3.
- golang.org/x/crypto is now a direct dependency (Argon2id).
- Requires Go 1.27 to build (`go 1.27` in go.mod); release binaries are
  built with the latest Go 1.27 patch release.
- One-line installer with optional encrypted DNS setup, checksum verification, upgrade with automatic
  rollback, and uninstall; release builds for linux/amd64 and linux/arm64.
