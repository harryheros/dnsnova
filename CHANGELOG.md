# DNSNova Changelog

All notable changes are listed here. Versions follow
[Semantic Versioning](https://semver.org/). Security fixes are marked
**Security**.

## 1.9.0 (2026-11-25)

**Private locality**, off by default: clients far from the server get the
answers name servers give where they are, without anything about them
being sent ([docs/private-locality.md](./docs/private-locality.md)).

- **Exits.** `[locality] exits` lists small hosts in other places, reached
  through tunnels, that only pass questions on. Each serves clients by
  country code or network (a network wins, the narrowest first); every
  other client gets the server's own answers, as before.
- **Which zones vary is learnt.** Now and then a question just answered is
  asked again through an exit; a zone whose addresses share no /24 (IPv6:
  /48) with the server's three times in a row is marked, and checked again
  as it is used (`relearn`). The root, top-level domains, DS and DNSKEY are
  always asked from the server itself, so the chain of trust never passes
  through an exit.
- **Private by construction.** A name in a marked zone is asked from the
  server and every exit at once, whoever needs it, and all its answers
  expire together, so what is sent never depends on who asked. A client's
  address, country or network only pick its answer inside the server. Each
  place keeps its own delegations and what it learns about name servers
  (round trips, cookies).
- **When an exit fails.** A client waits `exit_timeout` (800 ms) for its
  exit, then gets the server's answer. An exit with eight timeouts in a
  row, or three names only it fails to resolve, is left out for 30 seconds
  (doubling up to 10 minutes) and raises an alert. Over `fanout_qps`
  (200 a second), names are asked from the server alone.
- **Countries** come from the five regional registries' daily files, kept
  in `data_dir/locality/`, and are downloaded only when an exit serves
  clients by country.
- **Seeing it work.** A *Private locality* page (exits, zones that vary,
  and queries counted by country, to choose where an exit would help); a
  line on the overview's Resolution card; *Trace a lookup* lists what each
  place got and can ask through one exit; `dig CH TXT locality.server`
  tells a client which answer it gets; `GET /api/v1/locality`; metrics
  `dnsnova_locality_*`; the status page says a visitor's location only
  picks its answer.
- **Measuring.** `measure_path`, a secret DoH path, answers
  `<path>/<exit>` as asked through that exit, without the cache.
- `[locality]` is each node's own (never taken from a primary) and is set
  only in the file. It cannot be used with `ecs.address`.
- Off, nothing changes: an answer from the cache takes as long as before
  (419 ns against 418, the median of 12 alternated runs), with the same
  allocations. On, 60 to 70 ns more.
- New fuzz targets: exit lines, registry files and the zones file.

## 1.8.4 (2026-11-23)

- **A quieter top of the overview.** The DNSNova title was more than twice
  the size of the logo beside it in the menu and larger than every figure
  on the page; it is now 40 px instead of 56, the tagline 16 px instead of
  22, and the settings search box 300 × 34 instead of 380 × 40 (40 high on
  touch screens). On a laptop the server's name, mode and version now fit
  beside the title, so the figures start a row higher. Phones are
  unchanged.
- **The state light glows** on the dark theme (green, amber or red), where
  its pale ring looked dim; the light theme keeps the ring.

## 1.8.3 (2026-11-23)

- **Injected answers are no longer taken for the network taking over port
  53.** An injector on the path forges answers for the names it targets
  and resets their TCP connections. When the genuine answer to such a name
  was lost on the way, often for an HTTPS or TXT question, which the
  injector answers with an address, that one failed exchange was taken for
  interception: the log warned that names could not be resolved privately,
  the lookup gave up without asking the other servers, and health checks
  failed until the next answer. Now that lookup asks another server, and
  below the root interception is concluded only when a second name fails
  the same way before any server has answered again. At the root, where
  injectors do not forge, it is still recognised at once.

## 1.8.2 (2026-11-22)

The admin interface, gone through page by page for where things are and
where links lead. Nothing about DNS changes.

- **Settings › Encrypted DNS is now Addresses & encryption.** It is where
  the plain DNS addresses are set too, which nobody would look for under
  "Encrypted DNS"; the address stays `#/settings/encryption`.
- **Discovery (DDR) moved there**, next to the protocols it tells clients
  about, from DNS & upstreams › Clients. It shows once an encrypted
  protocol is on.
- **A settings page of its own for what is kept and where it is sent:
  Logs & statistics** (`#/settings/logs`), with how long statistics are
  kept, query records and the log collector (dnstap), all three moved out
  of Admin. Admin now holds the admin and metrics addresses, the account
  and the configuration file.
- **Links that name a setting open the page at that setting**, as the
  query log's link to query records does: from DNSSEC (resolving names
  itself, DNSSEC checking), New domains, the Upstreams page, the
  overview's certificate card and "DNS is not served yet" notice, the
  setup guide, the dnstap notice and the query records page. Account &
  security in the account menu opens at the password.
- Each page has its own browser tab title (`Query log · DNSNova`), for
  tabs, history and bookmarks.
- Admin's section of the admin and metrics addresses was named "Access",
  like the Access & limits page; it is now "Admin and metrics addresses".
- Addresses for clients links to the setup guide; the Nodes page links to
  the cluster documentation instead of naming the file.
- **The whole menu fits on laptop screens.** Below 1,000 px of height it
  was cut off and had to be scrolled (Tools was out of sight on most
  laptops); it now tightens in steps and stays whole down to about 600 px.

## 1.8.1 (2026-11-22)

- **The query log says what it is for, and where to go instead.** When it
  is off, the page now says it is a live log for troubleshooting that stops
  by itself and is never written to disk, and that keeping queries for days
  or months is what query records are for, with a link that opens
  Settings › Admin at that setting.
- **Keeping query records: pick 7, 30, 90 or 365 days**, or Off, instead of
  typing a number. Custom takes any other number (up to 3,650 days, as
  before), and shows one set earlier that is not on the list.
- A link to a setting can now open the settings page at that setting
  (`#/settings/<page>?focus=<key>`), as the settings search already did.

## 1.8.0 (2026-11-21)

Hardening. Attacks on resolvers found and fixed in recent years were gone
through one by one, and each checked against DNSNova's code. Where DNSNova
was open to one it is fixed; where it was not, a test now holds it there.
No new features; lookups are as fast as before.

DNSSEC

- An RRSIG whose labels field is smaller than its signer's label count is
  refused: it would make the wildcard it claims to be expanded from lie
  above the zone.
- NSEC3: at most 50 iterations (was 150) and a salt of at most 64 bytes;
  beyond, the proof is treated as insecure, as RFC 9276 allows. Only NSEC3
  records of the zone that signed the answer are used (a child zone's
  cannot speak for its parent), all with one set of parameters, so each
  name is hashed once however many records a response carries.
- An NSEC record whose next name lies outside its zone is not used as a
  proof, nor kept for answering from the cache (the cache already refused
  them).
- Matching DS records to DNSKEY records does bounded work, however many
  keys with matching tags but no matching digest a zone sends: at most 64
  keys looked at, 8 DS records used, 16 digests computed.

Responses from name servers

- A response with more than 1,024 records, or whose names take more than
  256 KB once the compression is undone, is refused: a 64 KB message of
  pointers to long names would otherwise take megabytes to hold.
- A name server name is taken at no more than six addresses, a zone's
  servers at no more than 32, each address once: a zone whose many NS
  records share a long list of addresses cannot make every lookup score
  hundreds.

Checked and found sound (now with tests where there were none)

- Signature checks per lookup are bounded (64), for answers and for
  negative answers and their proofs alike, and a key that cannot be used
  counts against the bound (KeyTrap, CVE-2023-50387).
- Denial proofs and the wildcard they go with must be signed by the same
  zone; NSEC3 proofs reject a closest encloser that is a delegation or a
  DNAME, so an ancestor zone's opt-out cannot make a signed delegation
  look unsigned.
- Records outside the zone of the server asked are dropped, NS records
  are taken only from referrals, and DNAME only from the answer section.
- Query IDs come from Go's ChaCha8 generator, which cannot be predicted
  from its output.
- Names inside record data must end within the record; compression
  pointers only point backwards, at most 64 times per name.
- CNAME chains (12), referrals (40), depth (8) and queries per lookup
  (150) are bounded; a server that keeps failing cannot loop a lookup. One
  TCP attempt per question, so a server that closes connections cannot
  cause a storm of them.
- Queries for classes other than IN are refused. TSIG, TKEY, SIG(0),
  UPDATE, NOTIFY, zone transfers, DNS64 and RPZ rewriting, where many such
  attacks lie, are not part of DNSNova.

## 1.7.1 (2026-11-21)

- **Anycast self-check on servers without plain DNS over UDP.** The check
  that decides whether to announce the route asked the server's own UDP
  socket; a server with DNS over TCP or encrypted DNS only was judged by
  its health alone, so a listener that had stopped answering kept the
  route. Now it asks over TCP, else over DNS over TLS (with a PROXY header
  first where the listener requires one); only a server with DoH or DoQ
  alone still goes by its health.
- **The self-check accepts only an answer to its own question**: a
  response (QR set), with its ID, one question equal to the one asked, and
  NOERROR. Before, a packet with the same ID and NOERROR was enough.
- **Signed build provenance for releases.** Each release file is now
  attested by the release workflow (Sigstore, through GitHub's artifact
  attestations): `gh attestation verify dnsnova-linux-amd64.tar.gz -R
  harryheros/dnsnova` shows it was built by this repository's workflow from
  the tagged commit. SHA256SUMS only detected damage: a file replaced
  together with its checksum passed it.

## 1.7.0 (2026-11-21)

- **DNS rebinding protection** (on by default). A web page can point a
  name of its own at an address on the visitor's network and so reach a
  router, NAS or printer from the browser. A name from outside that answers
  with an address of a private network (10/8, 172.16/12, 192.168/16,
  127/8, 169.254/16, 100.64/10, fc00::/7, fe80::/10, ::1) now gets no
  address (NOERROR, no records, Extended DNS Error "Blocked" saying why),
  so the client does not go on to ask another resolver.
  - Let through: names under the domains in `local.forward` (the
    network's own servers), names under `lan`, `home`, `internal`,
    `home.arpa` and other private-use domains, names of one label, names
    in `local.records`, and domains in the new `local.allow_private` (a
    public name you gave a device at home). 0.0.0.0 and :: are not
    blocked: blocking services answer with them.
  - The query log shows such answers as *blocked (rebinding)*, with an
    *Allow* that adds the name to `local.allow_private`. Turn it off with
    `local.rebinding_protection = false` (Settings › DNS & upstreams ›
    Local names).
  - An upstream on the local network (a router, an office's own server)
    makes the configuration warn: names it answers with private addresses
    are blocked unless their domains are listed.
  - Speed: whether an answer holds such an address is found once, when it
    is cached; a cache hit reads one flag.
- **Queries to encrypted upstreams are padded** to a multiple of 128 bytes
  (RFC 8467). Encrypted, a query's length still told the length of the
  name; now names of up to about 90 characters all look the same.
- **A wrong clock is noticed.** A machine without a battery-backed clock
  can start with a time days off, and then every signed answer fails
  DNSSEC with nothing but SERVFAIL to show for it. With recursion, when
  the root's key set fails only for its time but its signature is genuine,
  DNSNova says the clock is wrong and by at least how much: in the log, on
  the overview (top bar and Resolution card), as a critical alert, and as
  `dnsnova_clock_off_seconds`. It clears once the clock is right.
- **Popular answers stay in a full cache.** When the cache was full, the
  sampled answer expiring first was evicted, which is often the most
  asked-for one (a CDN's TTL is short). Now an answer no client has used
  since eviction last looked at it goes first, and used ones get a second
  chance (a sampled form of the SIEVE policy). In a
  simulation of three million queries over a million names, the share
  answered from the cache rose by 1.9 to 3.5 points, so 2 to 7% fewer
  lookups go out; a cache hit costs the same.
- **Faster when a name server loses a packet, and back to the fastest one
  sooner.**
  - Round trips are tracked with how much they vary (RFC 6298). A steady
    server is hedged soon after its usual round trip (round trip plus four
    times its variation, at least 20 ms more), an unsteady one no later
    than twice its round trip, as before.
  - A server out-run by another once no longer counts as that slow at
    once: a quarter of the difference is taken in, as one lost packet says
    little; a server slow again and again soon gives way.
  - A server not chosen, because another answered faster, has its round
    trip lowered a little (2%) each time; so a server once slow, or never
    asked, is tried again after some dozens of lookups, its answer sets
    its round trip anew, and the hedge keeps that try short.
    Its timeout is the generous one of an unknown server meanwhile.
  - Measured on a test network, 400 lookups each, 1.6.8 → 1.7.0: steady
    servers with 2% loss, mean 51 → 46 ms, median 49 → 42 ms, slowest 1%
    150 → 120 ms; unsteady servers with spikes, slowest 1% 245 → 164 ms;
    distant servers with 3% loss, median 196 → 172 ms, slowest 1%
    559 → 425 ms. No more queries are sent per lookup.
- Already done, now said: queries without RD (recursion desired) are
  refused, so the cache cannot be read for what others looked up.
- **Web interface.** On a narrow card, the figures at the foot stay on one
  line at the right while the words beside them wrap.
- The private-mode top lists' test no longer fails once in 64 runs (two
  devices can share a bit of the counting sketch).

## 1.6.8 (2026-11-20)

- **Name servers remembered across restarts.** With recursion and
  `cache.persist` on (the default on public servers), what was learnt
  about name servers is saved with the cache, every 10 minutes and at
  shutdown, in `data_dir/servers.bin`, and read back at start: how fast
  each answered, and the quirks some have (no EDNS, unusual but genuine
  answers, no TCP). The first lookups after a restart or an upgrade then
  go to the fast servers at once instead of learning them again; in tests
  where one of a zone's two servers is down, the first lookup after a
  restart took 401 ms half the time, and now takes no extra time.
  - Only what still counts is kept: round trips of servers used in the
    last 15 minutes, and quirks still in force (an hour at most). Failures
    and back-offs are not kept, so every server gets a fresh try after a
    restart; nor are lame zones or DNS Cookies.
  - The file is checked as a whole (CRC-32) and value by value: a damaged
    file, a round trip from the future or a quirk longer than an hour is
    ignored. It is fuzzed with the other parsers.
  - Privacy: name server addresses and timings only; no names, zones or
    clients. It is kept and deleted with `cache.bin`: never in private
    mode unless `cache.persist = "on"`.
  - Speed: lookups are unchanged; a save of 5,000 servers takes about
    1 ms, in the background.
- The weekly fuzzing now also covers the query records, the newly seen
  domains file and dnstap's control frames, which had fuzz targets but
  were not run.

## 1.6.7 (2026-11-20)

- **A slow name server no longer holds up a lookup.** When the server
  asked first has not replied within twice its usual round trip (and at
  least 50 ms more than it; 400 ms when not known yet), the next of the
  zone's servers is asked too, and the first good answer is used. Before,
  a lost packet cost the whole timeout (three round trips, at least
  150 ms) before the next server was asked. In tests with 5% of packets
  lost, the slowest 1% of lookups went from 151 ms to 56 ms; with no loss
  nothing changes, and no question is sent twice. At most two servers are
  waited for at once; a zone with one server, a server asked again, IPv6
  not yet known to work and servers set aside after failures are not
  hedged with.
  - The server that was out-run is not counted as failed (it may only
    have been slow once): it is no longer preferred, and is tried again
    once its round trip is forgotten. A question called off this way is
    not taken further (no TCP, no counting as a timeout).
  - The first server is asked as before, on the lookup's own goroutine; a
    second goroutine starts only when a hedge is sent. An uncached lookup
    costs about 1.5 µs more CPU; cached answers are unchanged.
  - Privacy: the question only ever goes to another authoritative server
    of the same zone, the one that would have been asked next anyway,
    with the same minimised name. No new party sees it.
  - Metric: `dnsnova_recursion_hedges_total`, by whether the hedge's
    answer was the one used; also `hedges` and `hedges_won` in the
    recursion status.
- **Round trips measured more truly.** An answer checked over TCP after a
  doubtful UDP one now counts the TCP exchange as the server's round
  trip, not the wait for a UDP answer before it, so a server whose
  answers are merely unusual is not taken to be slow.
- **Query log you can read and copy.** The live query log redrew its
  whole table every five seconds, even with nothing new, so rows moved
  under the pointer and text could hardly be selected or copied. Now the
  table changes only when queries arrive; while text in it is selected,
  or after *Pause*, new queries wait behind a *Show N new* button instead.
  *Copy* puts the queries shown on the clipboard as tab-separated text
  (for a message or a spreadsheet), *Download* saves them as a `.tsv`
  file, and a click on a client or a domain shows only its queries. The
  same buttons, and *Refresh*, are on the Query records search.
- **Copy buttons work over plain HTTP.** Browsers offer the clipboard only
  to HTTPS pages and to the server itself, so on a home network, where the
  web interface is opened over plain HTTP, every *Copy* button did nothing.
  They now fall back to copying a hidden text field.
- **Top domains on home and office servers.** A domain was listed only
  once five different networks (IPv4 /24, IPv6 /48) had asked for it,
  which a server for one home or office never sees: *Top Domains* and
  *Not Found* stayed empty. In private mode devices are counted instead
  (an IPv4 address, an IPv6 /64), and two are enough. A domain that only
  one device looks up is still never listed, and no addresses are kept;
  public servers are unchanged. The overview says which rule applies.
- **Web interface.** Upstream names and roles on the overview, and the
  reasons on the Rejected card, are no longer cut short; the upstream
  table keeps its last two columns apart; phones no longer show the search
  box's keyboard shortcut over its placeholder. The setup guide, when DNS
  answers only on the server itself, now says so and points to where the
  addresses are set (Encrypted DNS › Protocols), not to Access & limits.
- **ACME account key** encoded without the elliptic-curve coordinates
  deprecated since Go 1.26; the result is the same.
- **Documentation.** The README is shorter: the release history is left to
  this changelog, and the notes on using DNSNova for the server's own
  programs moved to [docs/server-itself.md](./docs/server-itself.md).
  Documentation and this changelog describe behaviour, not particular
  networks or sites.

## 1.6.6 (2026-11-20)

- **A lost packet no longer fails a lookup.** A name server that did not
  answer in time was not asked again, so a zone with a single name server
  gave SERVFAIL on the first lost packet, where other resolvers, retrying,
  answered. Now, when no server of a zone answered and one only timed out,
  the best such server is asked once more. It is given three times its
  usual round trip (400 ms to 2 s; 1 s when not known), not the 2 s its
  failure has just raised the estimate to: a lost packet is not a slow
  server, and a server that is down costs little more than before. One
  server only, so that when every server is down the error still comes in
  time for the upstreams to answer instead; and not one that has timed
  out three times in a row (down, most likely), IPv6 not yet known to
  work, or one that refused or answered without authority.
- **How fast recursion is, measured.** The overview's Resolution card shows
  the typical time of a lookup that asked name servers, and the time 95%
  of them finish within; answers from the cache are not counted, and cost
  no clock reading. Metrics: `dnsnova_recursion_lookup_seconds` and
  `dnsnova_recursion_server_rtt_seconds` (histograms), and
  `dnsnova_recursion_retries_total` by whether the retried server replied.
  Only times and counts are kept: no names, no addresses.

## 1.6.5 (2026-11-20)

Recursion resolves names served by load balancers that answer unusually
over UDP and not at all over TCP; such names failed with SERVFAIL after about six seconds. What is done
against forged answers is unchanged.

- **An unusual UDP answer is used when TCP cannot be had.** An answer
  without EDNS or AA (or without the cookie the server usually sends) was
  dropped and the question asked over TCP for up to five seconds. It is
  now kept, TCP gets a second (or four round trips), and if the connection
  is refused or silent the kept answer is used. It is not used if anything
  forged came with it, if two answers differ, or if TCP was reset after the
  question, as injectors do. New metric `dnsnova_recursion_no_tcp_total`.
- **Servers without TCP are remembered for an hour**, and TCP is not tried
  again. Their unusual answers are used at once only when they come no
  sooner than the server's own answers do (an injector on the path is
  nearer and answers first); one that comes sooner waits as any doubtful
  answer does, and is used only if no other answer comes.
- **A missing DNS Cookie is doubtful, no longer proof of forgery.**
  Instances of one anycast server can differ; a wrong cookie is still
  proof.
- **QNAME minimisation no longer marks servers lame for a whole zone.** A
  server that gives no usable reply to a shortened name is not set aside
  for the zone for ten minutes; the zone's other servers are asked it, and
  if none answers, the full name. (Giving up minimisation because of one
  server would send the full name to every later server.)

## 1.6.4 (2026-11-20)

- **Configuration history can be deleted.** Admin › Configuration history
  has *Delete all*, after a confirmation (`DELETE /api/v1/config/history`,
  recorded in the service log). The last ten versions are still kept
  automatically; a webhook address or key taken out of the settings stayed
  in them until ten more changes pushed it out.
- **The web interface no longer opens zoomed in on phones.** It put the
  cursor in the first field, and Safari zooms into a field whose text is
  under 16 pixels when it gets the cursor, without zooming back: the page
  opened larger than the screen until pinched. On touch screens fields now
  use 16-pixel text, and the cursor is not placed by itself (it opened the
  keyboard before anything was tapped).
- The DNSNova heading on the overview is a little smaller (56 pixels instead
  of 64; 39 instead of 44 on phones).
- **A query-record search could miss the last second's queries.** Before
  searching, the records still queued are written out; one the writer had
  just taken could be written right after that and stay unwritten to the
  file, so the search missed it until the next second. Found by the tests
  on 32-bit ARM in CI, where the emulator is slow enough to hit it.

## 1.6.3 (2026-11-20)

Starts and keeps running on more machines, and installs cleanly on more of
them. How queries are answered is unchanged.

Starting and running:

- **One listen address that is not there no longer stops the server.** At
  boot an address can come up after DNSNova starts (DHCP, or IPv6 still
  checking that the address is unique), and a home server's address can
  change; any listen address that could not be bound stopped DNSNova on
  every address, and after a few quick restarts systemd gave up. DNS
  listeners now bind such an address anyway (`IP_FREEBIND`), answer on it
  once it is up, and the log says it is
  missing. Saving a new address this machine does not have in the web
  interface is still refused, as a likely typo.
- **The metrics or the web interface failing to bind no longer stops DNS.**
  Another program on 127.0.0.1:9153 (a common metrics port) or on the
  admin port kept DNSNova from starting. Now the error is logged and DNS is
  served; the address is tried again when the configuration is next
  applied. Changing either to a port that is taken is still refused.
- **systemd keeps restarting it**: after five quick failures (another
  program still holding port 53 at boot, say) systemd gave up for good;
  now it tries again every 5 seconds. The installer updates the unit.
- **32-bit ARM** (Raspberry Pi OS 32-bit, every Pi from the Zero up): a
  release build (`dnsnova-linux-arm`), and the installer picks it. The
  tests run on 32-bit ARM in CI.
- A certificate file dnsnova may not read says why and what to do
  (certbot's files are root's only; dnsnova runs as its own user).

Installing:

- **Another DNS server on its own address is no conflict.** dnsmasq for
  libvirt (192.168.122.1) or NetworkManager (127.0.1.1) made the installer
  refuse every install; conflicts are now checked address by address, and
  addresses another program already answers on are left out with a note.
- **Default addresses leave out virtual bridges and IPv6 privacy
  addresses**, as the web setup does: Docker, libvirt, LXD and the like,
  and temporary IPv6 addresses, which change every day or so.
- **Containers that cannot sandbox services** (LXC without nesting,
  OpenVZ): the unit's sandbox kept DNSNova from starting
  (`status=226/NAMESPACE`). The installer tries it first and, where it
  fails, adds a drop-in that runs DNSNova without it (still as its own user
  with only the right to bind low ports); `-u` removes it.
- **Certificates from certbot** (`--cert-file` under `/etc/letsencrypt/live`,
  as with `--doh-proxy` behind nginx): dnsnova could not read them, so it
  did not start. The installer now copies them to `/etc/dnsnova/tls` and
  writes a certbot deploy hook that copies them again on every renewal.
- **Using DNSNova on the server itself.** `install.sh` run with DNS options
  but no `--listen` now also listens on 127.0.0.1:53, as the web setup
  already did, so `nameserver 127.0.0.1` in `/etc/resolv.conf` works; it
  had listened only on the public addresses, and that setting left the
  server unable to resolve anything (apt, certificate renewal). Not when
  `ss` shows another program on 127.0.0.1:53 or on every address, and
  never for DNS over TLS, QUIC or HTTPS. New installs only: existing
  configurations are not changed. The README has a new section on
  `/etc/resolv.conf`: 127.0.0.1 alone, with `trust-ad`, and why not a
  public resolver as a second line; and on machines without a
  battery-backed clock.
- **Metrics port**: 9153, or the next free one when another program has it.
- **Firewall**: with ufw or firewalld on, the summary gives the exact
  commands for the ports in use.
- A server with only private addresses is no longer taken for a home one:
  the hint to use `--lan` also says that cloud servers behind NAT (AWS,
  Google Cloud) look the same and should keep the internet install.
- Options given to an installed server are reported as ignored (they are
  for new installs) instead of silently ignored.
- Started by `sh` with wget but no curl, the installer now runs.

## 1.6.2 (2026-11-19)

Fixes to what the web interface and the metrics show; how upstreams are
picked and when the fallbacks are asked are unchanged.

- **Upstream latency counts answers only.** A failure raised the latency by
  at least the timeout (3 s) and took dozens of answers to wear off; a
  fallback, asked rarely, showed seconds for days while it answered in a
  few milliseconds. Failures still lower an upstream's rank when upstreams
  are picked. Also in `dnsnova_upstream_latency_seconds`.
- **Idle instead of Failing.** An upstream whose last query failed more
  than five minutes ago, with none sent since, is shown as Idle: how it is
  now is not known. A fallback stayed Failing for hours after one failed
  query. `/healthz`, the alerts and `dnsnova_upstream_healthy` still go by
  the last query.
- **With recursion on, upstreams are fallbacks everywhere.** The Upstreams
  page and the metrics called them primary while the overview called them
  fallback. All four `dnsnova_upstream_*` metrics now carry the same role
  (two of them disagreed before), and the public status page still counts a
  healthy one as a way to answer, as `/healthz` does.
- **Settings changes keep the upstreams' numbers.** Saving any setting,
  even an unrelated one, reset every upstream's counters, latency and
  health, and a failing upstream then ranked first again (an unknown
  latency sorts as the fastest). Upstreams whose address and role stay the
  same keep what was known about them.
- **Percentages never round to 100% or 0% unless they are**: 99.6% of
  queries over DoH3 next to 0.4% over UDP read as 100% and 0.4%. The same
  for an upstream's success rate, which showed 100% with errors.
- **The newest point of the traffic chart** covers only the time since the
  last sample, and was divided as if it were a full minute (or hour), so
  every chart ended in a drop. Each point is now divided by the time it
  covers, a newest point under half a step is left off the chart (its
  queries stay in the totals), and the average rate uses the report's real
  span.
- Large numbers switch unit where they round up (1.00M, not 1000.0k).
- The overview's Resolution card says its counters run since start; the
  rest of the page follows the chosen range.

## 1.6.1 (2026-11-16)

Wording and documentation only; the resolver behaves exactly as in 1.6.0.

- Forged answers dropped on the path are described as injected on the
  path, in the documentation, the web interface (Overview › Forged answers
  dropped) and the code.
- `install.sh --help`: `--admin` no longer says "port 7000"; the port is
  the one set with `--admin-port`.
- COMMERCIAL.md: the abuse.ch data in ShieldNova's security list keeps its
  own terms for commercial use.

## 1.6.0 (2026-11-14)

For offices and other networks that must account for their DNS: everything
here is off by default, and the status page says what is on.

- **Query records** (`log.query_days`, off by default): every query kept on
  disk for a number of days, for networks that must be able to tell later
  which device looked up what. One plain tab-separated file per day in
  data_dir/querylog, gzipped after the day, deleted past the days kept, and
  all deleted when turned off. The Query log page then searches them (by
  domain, client, blocked or failed answers, and day) and downloads each
  day's file. Writing never delays an answer: if the disk falls behind,
  records are dropped and counted. Client addresses are shortened unless
  `log.query_full_ip` is set. The status page and the admin overview say
  that queries are kept, for how long and with which addresses.
- **Client groups** (`clients.groups`, Settings › DNS & upstreams ›
  Clients): devices sorted by network, each group with its own filtering:
  the block lists always, never, or as the address used decides, plus the
  group's own blocked and allowed domains (which also apply to CNAME
  chains). A device in several groups belongs to the narrowest network.
  The query log and query records show each query's group, and blocks by a
  group's rule are told apart from the block lists (and carry their own
  Extended DNS Error text).
- **dnstap** (`[dnstap]`, Settings › Admin › Log collector): every query
  and answer sent as dnstap to a log collector (Vector, dnscollector, a
  SIEM) over a Unix socket or TCP, with the Frame Streams handshake fstrm
  readers expect; tested against dnstap-receiver. Queries, answers or
  both; client networks only unless `dnstap.full_ip`. It reconnects by
  itself and never delays an answer: while the collector is gone, messages
  are dropped and counted (`dnsnova_dnstap_*` metrics, and the Query log
  page). The status page says that queries are sent to a log collector.
- **New domains** (`[nod]`, Settings › Filtering › New domains, and a
  Status › New domains page): tells when a domain is looked up here for the
  first time in 30 to 60 days, often the first sign of phishing or malware,
  with the name asked and who asked first; one click blocks it. Sent to the
  alert destinations as a notice at most every 10 minutes (webhook `status`
  `event`, `kind` `new_domains`). It keeps no list of domains: two Bloom
  filters of hashes under a random key (4 MB), saved so a restart does not
  make every domain new, and deleted when turned off. When first on, it
  learns quietly (`nod.learn`, 24h). Only real answers count (not blocked,
  local or failed ones); `nod.ignore` exempts domains. Metrics
  `dnsnova_new_domains_*`; the query log tags such queries "new".
- Uninstalling without `--purge` now says when query records are left in
  /var/lib/dnsnova/querylog, and how to delete them.
- Documentation: a dnstap Unix socket belongs under /run, not /tmp (the
  service has a /tmp of its own); in a cluster, each node keeps its own
  query records and newly seen domains.

## 1.5.0 (2026-11-14)

- **Domains with their own servers** (`local.forward`): names under a
  domain are asked from the servers listed for it, never from upstreams or
  the root, such as an office's Active Directory (`corp.example 10.0.0.53`)
  or a router's device names (`lan 192.168.1.1`). Private reverse zones
  listed there (`168.192.in-addr.arpa`) go to those servers instead of being
  answered NXDOMAIN. Servers are written as upstreams are (plain, TLS,
  HTTPS, HTTP/3, QUIC) and asked at once; no client subnet is sent, and
  their answers never carry the AD bit. Changing the list clears the cache.
  In the web interface under Settings › Local names.
- **RPZ block lists**: filter lists in RPZ zone format, as threat feeds
  publish them (URLhaus, ThreatFox, HaGeZi), now work. NXDOMAIN, NODATA,
  drop and local-data rules block; `rpz-passthru` and triggers on addresses,
  name servers or clients are skipped (and counted).
- **Which node answered**: a node of a cluster or behind anycast gives its
  `cluster.name` to clients that ask with NSID (RFC 5001, `dig +nsid`) or a
  CH TXT query for `id.server` or `hostname.bind`. A single server says
  nothing.

## 1.4.1 (2026-11-14)

- **UDP socket buffers**: the system caps them (on Linux,
  net.core.rmem_max, often about 200 KB), silently, below the 4 MB dnsnova
  asks for to absorb bursts of queries; in bursts, queries were dropped
  with no sign of why. dnsnova now reads back what it got and, when cut
  short, says so in the log with the command that fixes it. The installer
  raises the caps to 7.5 MB in /etc/sysctl.d/90-dnsnova.conf (never lowers
  them; removed on uninstall), which also ends quic-go's warning about its
  buffers for DoQ and HTTP/3.
- **Building from source needs Go 1.27.4 or later**: earlier 1.27 releases
  have security fixes missing in parts dnsnova uses (HTTP/2 for DoH,
  crypto/tls, crypto/x509, net/http). The release binaries were already
  built with the newest 1.27 release.
- **Logo glow**: the page no longer adds a glow of its own around the
  mark. That glow had a fixed size, so on small icons (the narrow layout's
  top bar) it showed as a wide blue ring. The mark's own glow is tighter
  too.

## 1.4.0 (2026-11-14)

Recursion without upstreams on networks that tamper with DNS
([docs/restricted-networks.md](./docs/restricted-networks.md)):

- **Forged answers injected on the path are dropped and the genuine
  answer is used.** Some networks answer for certain names themselves,
  from the name server's address and ahead of it, and reset TCP. The first matching answer was taken: for signed zones it failed
  validation (SERVFAIL); for unsigned zones the forged address was used and
  cached. Each UDP answer is now judged on arrival. Dropped: an address from
  a root server, no authority from a root or top-level-domain server, an
  unsigned answer from a signed zone, a record of another type than asked,
  an AAAA address in 2001::/32, a wrong or missing DNS Cookie. The socket
  stays open for the genuine answer (up to 500 ms more, within the query's
  timeout), then the question goes to TCP. Answers that pass are used at
  once.
- An answer without EDNS to a question with it, or without authority from a
  zone's own server, is used only if nothing better arrives. A server whose
  genuine TCP answers look like that (some load balancers) is trusted over
  UDP for an hour; its first lookup takes up to 500 ms longer than before.
- **Networks that intercept port 53 are detected.** Their answers were
  taken as the name servers': an NXDOMAIN with an SOA could be cached for a
  whole top-level domain, and recursion reported itself healthy while every
  lookup failed. Now nothing from them is used, recursion is unhealthy
  (`/healthz`, the status page), the top bar shows *DNS intercepted by the
  network*, the log explains it, and lookups fail at once instead of trying
  every root server.
- While recursion cannot work (name servers unreachable or intercepted),
  queries go straight to the upstreams instead of waiting for their own
  lookup to fail; one lookup at a time keeps probing the name servers, so
  recursion resumes as soon as they answer.
- **New alerts**: *No name server answers* and *DNS intercepted*, both
  critical, after `alerts.upstream_down_for`. Before, a server using
  recursion sent no alert when it could not resolve.
- New metrics: `dnsnova_recursion_forged_total`,
  `dnsnova_recursion_rewritten_total`, `dnsnova_recursion_intercepted`. The
  API's recursion status has `forged`, `rewritten` and `intercepted`;
  `status.json` has `recursion`.

Also:

- **DNS over HTTP/3 upstreams**: `h3://1.1.1.1/dns-query`, or pinned as
  for the other transports: `h3://dns.google/dns-query#8.8.8.8`.
- **A new mark**: a mechanised trident in silver with blue light, drawn as
  a vector; the browser tab icon is a solid silhouette of it.
- In the light appearance, the *Menu* button of the narrow layout could
  not be read; it now keeps the dark rail's colors.
- The DNSNova logo in the web interface goes to the overview, also in the
  narrow layout, and refreshes it when already there.
- The status page says, with recursion, that queries go to each domain's
  name servers, not upstreams.
- Documentation, settings help and the privacy page were tightened; the
  privacy page now covers name servers and `ecs.client_path`.

## 1.3.6 (2026-11-12)

- Names in `local.records` are checked more strictly: a name with an
  empty label (`nas..home`, or two dots at the end as in `nas.home..`)
  or with a label that starts or ends with a hyphen (`-nas.home`) is
  refused when the configuration loads, instead of being served as
  written. Such a name was never a valid host name; if one is in your
  configuration, correct it before upgrading. Found by the fuzz tests.
- The fuzz tests run once a week instead of every night.

## 1.3.5 (2026-11-12)

Two more causes of SERVFAIL found the same way as in 1.3.4:

- With QNAME minimisation, a shortened name that no server of a zone
  answers usably is asked again in full, instead of ending the lookup.
  Some servers mishandle names that only exist as part of longer ones.
- A name server whose only known addresses are IPv6, when they fail, has
  its IPv4 addresses looked up and asked. On a server whose IPv6 path to
  some networks is poor, a zone could fail although its name servers
  answered over IPv4.

## 1.3.4 (2026-11-12)

Found by comparing, for some 5,000 domains, what this resolver answers
with what a large public resolver answers:

- An answer from a zone's server without the AA flag is accepted when it
  is for the very name asked. Some load balancers that zones delegate
  their names to leave AA off; their answers were taken for lame replies
  and the lookup failed.
- When every address known for a zone's name servers fails, its other
  name servers are looked up and asked. Name servers without glue were
  looked up only partly, two or three of them; when those did not answer
  from where this server is, the lookup gave up
  although other name servers would have answered.
- When no name server of a zone gives a usable answer, the error says
  which question, which zone, and what each server did (timed out,
  REFUSED, not authoritative, ...) instead of only "no authoritative
  server answered". It shows in the log of `ecs.client_path`, in Trace a
  lookup and in the DNSSEC page's failures.

## 1.3.3 (2026-11-12)

- Resolving from the root, with DNSSEC on: some names under zones that are
  not signed failed with SERVFAIL ("no authoritative server answered").
  To check a zone, the resolver asked its parent for the zone's DS record,
  and some parents wrongly send that question down to the child zone instead of answering
  it, which ended the lookup. Two changes:
  - below a zone that is not signed, nothing is checked any more and no DS
    question is asked (RFC 4035 5): the zone above is looked at first. This
    also saves queries for every name under an unsigned domain;
  - a parent server that sends a DS question down is passed over, and the
    parent's other servers are asked, instead of giving up.

## 1.3.2 (2026-11-12)

- Trace a lookup can show how a name resolves for another network: give a
  client network (or an address, which stands for its /24 or /56) under
  "As seen from another network", and every question carries it as EDNS
  Client Subnet. With recursion only. API: `subnet` in
  `POST /tools/trace`.
- `ecs.client_path`: a lookup that gets no answer is logged with the
  reason (timed out, too many queries, no server reachable), the name and
  the network, so a name that fails there can be traced.

## 1.3.1 (2026-11-12)

- `ecs.client_path`: a lookup may take up to 9 seconds instead of 6. Each
  name of such a lookup is asked afresh, and from a server with a lossy
  path to the name servers the
  first servers tried often do not answer in time; the spare seconds go
  into trying the others. Measured on such a path, a few percent of
  domains failed for this alone.

## 1.3.0 (2026-11-12)

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
  comes before TLS); version 2 on UDP, one header per datagram, with
  answers going back to the balancer without one. From
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
- DNS Cookies (RFC 7873), with the interoperable server cookie of RFC 9018:
  on by default (`server.cookies`).
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

## 1.2.0 (2026-11-11)

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

## 1.1.0 (2026-11-10)

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

## 1.0.5 (2026-11-10)

- A change of `ecs.address` now waits for lookups still asking for the old
  network, then clears the cache. An answer for the old network that
  arrived just after the change could be cached before.
- `ecs.address` refuses ranges that are nobody's network on the internet:
  carrier NAT (100.64.0.0/10), documentation, benchmarking, reserved and
  NAT64 addresses.
- `GET /status` reports `privacy.client_subnet`.

## 1.0.4 (2026-11-10)

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

## 1.0.0 (2026-11-09)

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
- Colors with jobs: green main buttons and switches,
  softer blue for links and the current page, a color mark per key figure,
  deep-grey text and lightly shadowed cards, in light and dark.
- Sign-in page: the form, "Forgot password?" with what
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
- Installing asks nothing: the installer starts only
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
