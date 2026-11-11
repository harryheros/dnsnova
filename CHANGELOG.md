# Changelog

All notable changes are listed here. Versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked
**Security**.

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
