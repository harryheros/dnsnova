# Private locality

Some name servers answer by where the question comes from: a content network
gives the addresses of its servers nearest the resolver that asks. Clients
far from their resolver are then sent to servers near the resolver, and
their content comes from far away: the name resolves quickly, the page loads
slowly.

EDNS Client Subnet fixes that by telling name servers each client's network.
Private locality fixes it without telling them anything: DNSNova also asks
from a few other places, called exits, and gives each client the answer that
name servers give where the client is. It is off by default, and needs
recursion (`recursion.enabled`).

## How it works

An exit is a small host somewhere else, reached through a tunnel. It runs no
DNSNova and keeps nothing: it only passes questions from the server to name
servers and their answers back. The server is still the only resolver.

```
clients ──► DNSNova ──────────────────────────────► name servers
               │  (from here: the root, top-level domains, DNSSEC keys,
               │   and every name whose answers do not vary)
               ├─► tunnel ─► exit-a ──────────────► name servers
               └─► tunnel ─► exit-b ──────────────► name servers
```

1. **Learning which zones vary.** Now and then, a question just answered
   from here is asked again through an exit. A zone whose addresses share
   no /24 (IPv6: /48) with the server's three times in a row is marked:
   its answers depend on where they are asked from. Below a marked zone,
   everything does too.
2. **Asking from every place at once.** When a lookup reaches a marked zone,
   the rest of its chain is resolved from here and through every exit at
   once, whoever needs it. Each place keeps its own answers and its own
   delegations: some content networks also delegate to name servers near
   whoever asks.
3. **Each client gets its own place's answer.** A client is placed by the
   network or country its address is in. A client no exit serves gets the
   server's own answer, as without private locality.

The root, top-level domains, DS and DNSKEY are always asked from here: they
do not depend on where they are asked from, and the chain of trust never
passes through an exit.

## What stays private

These rules decide every part of the design; nothing that breaks one is
done.

- **A client's address, and the country or network it is in, only pick an
  answer inside the server.** They are never sent, and never written to
  disk.
- **What is sent does not depend on who asked.** A name in a marked zone is
  asked from every place at once whenever any client needs it, and all of a
  name's answers expire together (with the first of them), so the next
  lookup is not set off by one place's answer running out. Name servers and
  exits see what they would without private locality: that the server
  asked for a name. Over `fanout_qps`, names are asked from here alone,
  never through the client's exit alone, which would tell where it is.
- **Off, nothing changes.** No exit is used and no country table is
  downloaded or loaded.

An exit sees the questions the server sends through it, as the server's own
network sees the ones it sends; it never sees a client's address. The
country table comes from the files the regional Internet registries publish
for everyone; looking a client up in it sends nothing anywhere.

## When it helps

- A server whose clients are in several places far from it, or an
  organisation whose offices use one central resolver.
- Not a home or office resolver near its clients: name servers already see
  a resolver where the clients are.
- Not content networks that choose their server when the client connects
  (anycast): they are right whatever the resolver.

Compared with `ecs.address`, which sends one network for every client:
that tells name servers the network, gives every client the same answer,
and some name servers honour a client subnet only from resolvers they have
an agreement with. Private locality sends no subnet and works with every
name server; it costs one small host per place, and more questions for
the names that vary. The two cannot be on together.

## Setting up an exit

The exit is a host in the place whose clients it serves; a small virtual
server is enough. The example uses WireGuard; any tunnel the system can
route into works.

On the exit, forward the tunnel's DNS questions to the internet and nothing
else. `fully-random` keeps the server's random source ports random after
the address translation, which DNS needs against forged answers:

```
# /etc/nftables.conf on the exit (interface names as on your host)
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat;
    iifname "wg0" oifname "eth0" masquerade fully-random
  }
}
table inet filter {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "wg0" oifname "eth0" meta l4proto { udp, tcp } th dport 53 accept
  }
}
```

and turn forwarding on (`net.ipv4.ip_forward = 1`). Keep no logs of the
forwarded traffic.

On the server, give the tunnel an address of its own and send everything
from that address into the tunnel:

```
# the tunnel to exit-a: the server's end is 10.66.1.2
ip rule add from 10.66.1.2 table 101
ip route add default dev wg-exit-a table 101
```

(with WireGuard's `Table = off` in the interface's `[Interface]` section,
and `AllowedIPs = 0.0.0.0/0` for the exit's peer). The MTU of a WireGuard
tunnel (1420) leaves room for DNSNova's largest UDP answers (1232 bytes).
For name servers over IPv6, give the tunnel an IPv6 address too and route
it the same way; an exit with only an IPv4 source address is asked only
for name servers' IPv4 addresses.

Then, in the configuration file:

```toml
[locality]
enabled = true
exits = [
  "exit-a 10.66.1.2 XA,XB",
  "exit-b 10.66.2.2,fd66:2::2 XC",
  "office-b 10.66.3.2 10.20.0.0/16",
]
```

(`XA`, `XB` and `XC` stand for country codes, ISO 3166 two letters.) Each
exit is a name, the source addresses that lead into its tunnel (an IPv4
address, an IPv6 address or both, separated by a comma) and the clients it
serves: country codes and networks, separated by spaces or commas. A
network wins over a country, and the narrowest network wins. Clients on
private addresses (an office) are placed by network only.

To check it, from a client:

```
dig @your-server CH TXT locality.server
```

answers which exit the client gets and why (`view=exit-a`, `by=XA`), to that
client alone. *Trace a lookup* shows, for a name whose answers vary, what
each place got, and can ask every zone below the top-level domains through
one exit (*Through an exit*). The *Private locality* page, under Status,
shows the exits, the zones found to vary and the siting report.

## Settings

All in `[locality]`. Like `[cluster]`, the table is the node's own (its
exits are its own tunnels): it is never taken from a primary, and it can be
changed only in the file on the server, not through the admin interface.

| Setting | Default | What it does |
|---|---|---|
| `enabled` | `false` | Turns it on (needs recursion, not with `ecs.address`) |
| `exits` | none | The exits, as above (up to 16) |
| `exit_timeout` | `800ms` | How long a client waits for its exit's answer |
| `fanout_qps` | `200` | Names asked from every place, per second at most |
| `relearn` | `168h` | How long a zone found not to vary stays so |
| `country_sources` | the 5 registries | Where the country table comes from |
| `measure_path` | none | A secret DoH path for measuring tools |

## Clients and countries

When an exit serves clients by country, the files of the five regional
Internet registries (delegated-extended) are downloaded once a day, kept in
`data_dir/locality/`, and the table is built from them; a download that
fails or does not look like a registry file keeps the copy in use. A
registry records where an address was assigned, which is where it is used
for most addresses but not all. `country_sources` replaces the five
sources (http(s) URLs or absolute paths, for a mirror or a server without
internet access to the registries).

## The siting report

The *Private locality* page counts, in memory since start, the queries
from each country and how many were for names whose answers vary. Counts
only: no names, no addresses. Its last column, the share of all queries
that came from a country for names that vary, shows where an exit would
help most.

## When an exit fails

- A client whose exit has not answered within `exit_timeout` gets the
  server's own answer; the exit's answer, when it comes, is kept for the
  next client.
- Eight timeouts in a row through an exit, or three names that it fails to
  resolve while the server resolves them, take it out: it is not asked for
  30 seconds, then tried again (the pause doubles each time, up to 10
  minutes). Its clients get the server's answers meanwhile, and an alert
  says so (`locality_exit`).
- A flood of random names under a zone that varies would ask every place
  for each: over `fanout_qps` a second, names are asked from here alone.
  The per-client limits apply as to every query.

## Measuring through an exit

With `measure_path` set (a secret path, like `ecs.client_path`), a DoH
query to `https://your-server<measure_path>/<exit>` is resolved with every
zone below the top-level domains asked through that exit. Its answers are
never cached or shared, and are neither filtered nor logged. It is for
tools that measure how names resolve in a place, which public resolvers
with a client subnet do only for name servers that honour one.

## Security

- **What a compromised exit can do:** change the answers that pass through
  it, for zones that vary, when they are not signed. Signed answers are
  validated as always, and DS and DNSKEY never pass through an exit, so an
  exit cannot change the chain of trust.
- **Between the server and an exit,** the tunnel is encrypted. On the far
  side, the questions are seen as the server's own network sees those it
  sends.
- **Forged answers:** every protection works through an exit as from here
  (random ports and IDs, DNS Cookies, TCP when an answer looks forged),
  each with what it has learnt about servers seen from that exit (round
  trips, cookies), which differ from what is seen from here.
- **An exit is not an open relay:** it forwards port 53 from its tunnel
  only.

## Costs

- **Questions:** each name in a zone that varies is asked from every place,
  (exits + 1) times; the root, top-level domains and every other name as
  before. Learning adds at most 20 probes a second, one per zone every 20
  seconds.
- **Memory:** an answer per place for the names that vary, which have
  short lifetimes (often 20 seconds); a table of the zones seen, at most
  20,000.
- **Speed:** off, nothing changes (the same allocations; an answer from
  the cache took 419 ns against 418 before, the median of 12 runs each,
  alternated). On, picking the client's answer and counting it adds 60
  to 70 ns to an answer from the cache. A client of an exit waits, the first
  time a name is needed, for its exit's lookup instead of the server's.
- **Disk:** the zones found to vary are saved with the cache, when it is
  kept (`locality-zones.bin`: zone names only). Answers that vary are not
  saved.
