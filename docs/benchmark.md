# Benchmark

How many queries DNSNova answers per second on one CPU core, and how that
compares with AdGuard Home, a popular DNS server written in the same
language. The tools are in [`tools/bench`](../tools/bench), so anyone can
repeat the test.

These numbers measure the server itself: the upstream answers instantly and
everything runs on one machine. On the internet, the time to reach the
server and the upstream adds to every answer.

## Results

Answers per second, average of two runs. Response times are the 99th
percentile: 99% of answers came faster.

| Test | DNSNova | AdGuard Home | |
|---|---:|---:|---:|
| UDP, from the cache | 200,900 (0.9 ms) | 28,200 (4.8 ms) | 7.1× |
| UDP, new names (upstream) | 23,200 (8.2 ms) | 13,300 (11.6 ms) | 1.7× |
| DNS over TLS, from the cache | 93,900 (2.5 ms) | 21,900 (8.6 ms) | 4.3× |
| DNS over TLS, new names | 20,100 (9.3 ms) | 12,800 (12.3 ms) | 1.6× |
| DNS over HTTPS, from the cache | 22,200 (10.8 ms) | 14,100 (12.1 ms) | 1.6× |
| DNS over HTTPS, new names | 11,700 (16.5 ms) | 8,300 (18.9 ms) | 1.4× |

With a blocklist of 225,344 rules loaded:

| Test | DNSNova | AdGuard Home | |
|---|---:|---:|---:|
| UDP, from the cache | 172,000 (0.9 ms) | 18,400 (8.1 ms) | 9.3× |
| UDP, blocked names | 147,500 (1.3 ms) | 18,200 (9.2 ms) | 8.1× |
| UDP, new names | 23,100 (7.9 ms) | 10,500 (16.8 ms) | 2.2× |

The blocklist costs DNSNova about 14% of its cache speed, AdGuard Home
about 35%.

Memory (resident): idle, 10 MB and 31 MB; idle with the blocklist, about
55 MB and 66 MB; after the tests with the blocklist, 138 MB and 218 MB.

## Setup

- A cloud virtual machine with 2 cores (Intel Xeon, 2.1 GHz), Linux.
- The DNS server runs on one core (`taskset -c 1`); the load generator and
  the upstream share the other.
- DNSNova 1.0 (development) and AdGuard Home v0.107.80, both with their
  default cache. Rate limits off on both, since all queries come from one
  address. AdGuard Home's query log off (it is on by default and then costs
  another 5 to 10%); DNSNova keeps no query log unless started.
- Encrypted DNS with the same self-signed ECDSA P-256 certificate; DoH over
  HTTP/2.
- 64 queries in flight: one per UDP socket, one per DoT connection, eight per
  DoH connection.
- "From the cache": 2,000 names asked again and again. "New names": a name
  never asked before for every query, spread over 10,000 domains, so each
  goes to the upstream. "Blocked names": 2,000 names taken from the list.
- Blocklist: [HaGeZi Pro](https://github.com/hagezi/dns-blocklists),
  AdGuard format, loaded in both. DNSNova answers blocked names NXDOMAIN,
  AdGuard Home 0.0.0.0 (its default).
- Each test runs 3 seconds to warm up, then 10 seconds measured.

## Repeat it

```sh
go build -o upstream ./tools/bench/upstream
go build -o load ./tools/bench/load
taskset -c 0 ./upstream -addr 127.0.0.1:5301 &
```

Start the server on another core, for example
`taskset -c 1 dnsnova -c bench.toml`, with `udp://127.0.0.1:5301` as its
only upstream and rate limits off:

```toml
[server]
mode = "public"
listen = ["127.0.0.1:5300"]

[upstream]
primary = ["udp://127.0.0.1:5301"]
bootstrap = []

[limits]
client_qps = 0
prefix_qps = 0
global_qps = 0
rrl_rate = 0
```

Then:

```sh
taskset -c 0 ./load -s 127.0.0.1:5300                # from the cache
taskset -c 0 ./load -s 127.0.0.1:5300 -unique        # new names
taskset -c 0 ./load -proto dot -s 127.0.0.1:853
taskset -c 0 ./load -proto doh -url https://127.0.0.1/dns-query
taskset -c 0 ./load -s 127.0.0.1:5300 -names blocked.txt
```

`load -h` lists the options. Use names that spread over many domains for
the "new names" test: DNSNova allows at most `limits.zone_concurrency`
(50) upstream queries in flight per domain, so that a flood of random
names under one domain cannot tie up the upstreams. `-unique` does this.
