# Resolving where DNS is tampered with

DNSNova resolves names from the root servers so that no third party sees
the queries. Some networks interfere. This page covers what DNSNova handles
by itself and what you need to set up.

## Answers injected on the path

**What happens:** on some networks, for a question about certain names, a device on the path
sends a forged answer at once, from the name server's address, with the
right port, ID and question. It cannot stop the genuine answer, which
arrives later (in published measurements, 99% of forged answers led by at
most 364 ms). Over TCP, it resets the connection.

A resolver that takes the first matching answer takes the forged one: for
signed zones (the root, `com`, `net` and most top-level domains) validation
then fails (SERVFAIL); for unsigned zones the forged address is used and
cached.

**What DNSNova does:** each UDP answer is judged on arrival. An answer the
server would not send is dropped, and the socket stays open for the genuine
one:

| Answer | Why it is not the server's |
| --- | --- |
| An address from a root server | Root servers only refer to top-level domains |
| No authority (AA) from a root or top-level-domain server | They always set it |
| Unsigned, from a zone whose referral had DS records | Signed zones sign their answers |
| A record of another type than asked | No server does that |
| An AAAA address in `2001::/32` | The Teredo prefix injectors use |
| A wrong DNS Cookie | Only the server knows the cookie |
| No EDNS to a question with EDNS, no AA from the zone's own server, or no cookie from a server that always sends one | Unusual: kept only if nothing better arrives (see below) |

Answers that pass are used at once, so other names cost nothing extra.
After a dropped answer, DNSNova waits up to 500 ms for the genuine one,
within the query's timeout, then asks over TCP. A server whose genuine TCP
answer looks like the dropped ones (some load balancers omit EDNS or AA) is
trusted over UDP for an hour.

No upstreams are needed. The Overview shows *Forged answers dropped*; the
metric is `dnsnova_recursion_forged_total`.

**Your clients:** the same device also forges answers sent to clients that
reach DNSNova across it. Those clients must use DNS over HTTPS, TLS or QUIC.

## Servers that do not answer over TCP

Some load balancers in front of large sites answer over UDP without EDNS or AA, so their answers look
unusual, and never answer over TCP: the connection is refused, or accepted
and left silent.

Treating such an answer as forged and waiting for TCP would make every
lookup there fail. Instead, an unusual answer is kept while TCP is tried. TCP gets a short chance
(a second, or four round trips); if the connection is refused or not
answered, the kept answer is used, and the server is asked only over UDP
for an hour. The answer is used only when it is all that came: one
answer, or the same one repeated. If an answer that cannot be the server's
came too, or two that differ, or the TCP connection was reset after the
question (what injectors do), it is not.

During that hour, an unusual answer from the server is used at once only
when it comes no sooner than the server's answers do (three quarters of
its usual round trip, less a millisecond). An injector on the path is
nearer than the server and answers first: its answer waits, as any
doubtful answer does, and the genuine one that follows is used.
They are counted in the metric `dnsnova_recursion_no_tcp_total`.

The same servers often give an empty reply without authority for a name
that only exists as part of longer ones, which QNAME minimisation asks
for. DNSNova does not mark such a server lame for its whole zone: it asks
the zone's other servers for the shortened name, and only if none answers,
for the full name, so that one server does not end minimisation for the
rest of the lookup.

## Networks that take over port 53

**What happens:** on some networks, every DNS question, to any address, is answered or refused
by the network's own resolver, often over TCP too. No name server is
reachable, so no resolver can resolve privately there.

**What DNSNova does:** it recognises the interception (a root server never
answers without authority, or with an address) instead of trusting it:

- nothing intercepted is used or cached, so it cannot become an NXDOMAIN
  for a whole top-level domain;
- the top bar shows *DNS intercepted by the network*, `/healthz` reports
  unhealthy, `dnsnova_recursion_intercepted` is 1, and the log explains it;
- each lookup then fails at once instead of trying every root server.

**What to set up:** run DNSNova with recursion on another network (a VPS),
and use it as an encrypted upstream:

```toml
[upstream]
primary = ["https://dns.your-domain.example/dns-query", "quic://dns.your-domain.example"]

[recursion]
enabled = true
fallback = true
```

Queries leave encrypted and are resolved by your own server: no third party
sees them. Where DoT and DoQ are blocked, DoH on port 443 is the hardest to
single out. While interception lasts, queries go straight to the upstream,
and one lookup at a time keeps probing the name servers, so recursion
resumes when the network allows it.

## Networks that drop DNS

Some networks silently drop questions to outside name servers. DNSNova
reports the name servers unreachable and, with upstreams set, uses them at
once instead of waiting for each lookup to time out. The remedy is the same:
your own DNSNova elsewhere, over an encrypted transport.
