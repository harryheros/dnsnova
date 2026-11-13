# Resolving where DNS is tampered with

DNSNova resolves names from the root servers so that no third party sees
the queries. Some networks interfere. This page covers what DNSNova handles
by itself and what you need to set up.

## Censors on the path

**Where:** China (the Great Firewall) and some other national networks.

**What they do:** for a question about a blocked name, the censor sends a
forged answer at once, from the name server's address, with the right port,
ID and question. It cannot stop the genuine answer, which arrives later (in
China, 99% of forged answers lead by at most 364 ms). Over TCP, it resets
the connection.

Before 1.4, DNSNova took the first matching answer, the forged one. For
signed zones (the root, `com`, `net` and most top-level domains) it failed
DNSSEC validation (SERVFAIL); for unsigned zones the forged address was
used and cached.

**What DNSNova does:** each UDP answer is judged on arrival. An answer the
server would not send is dropped, and the socket stays open for the genuine
one:

| Answer | Why it is not the server's |
| --- | --- |
| An address from a root server | Root servers only refer to top-level domains |
| No authority (AA) from a root or top-level-domain server | They always set it |
| Unsigned, from a zone whose referral had DS records | Signed zones sign their answers |
| A record of another type than asked | No server does that |
| An AAAA address in `2001::/32` | The Teredo prefix censors use |
| A wrong DNS Cookie, or none from a server that always sends one | Only the server knows the cookie |
| No EDNS to a question with EDNS, or no AA from the zone's own server | Unusual: kept only if nothing better arrives |

Answers that pass are used at once, so uncensored names cost nothing extra.
After a dropped answer, DNSNova waits up to 500 ms for the genuine one,
within the query's timeout, then asks over TCP. A server whose genuine TCP
answer looks like the dropped ones (some load balancers omit EDNS or AA) is
trusted over UDP for an hour.

No upstreams are needed. The Overview shows *Forged answers dropped*; the
metric is `dnsnova_recursion_forged_total`.

**Your clients:** the censor also forges answers sent to clients that reach
DNSNova across it (a server in Hong Kong with clients in mainland China).
Those clients must use DNS over HTTPS, TLS or QUIC.

## Networks that take over port 53

**Where:** Iran, parts of China, and some ISPs and corporate networks
(RIPE Labs found it in 48 countries in 2022).

**What they do:** every DNS question, to any address, is answered or refused
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
