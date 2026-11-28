# Use DNSNova as the host's DNS resolver

Programs on the server (apt, certificate renewal, mail) can use DNSNova too.
The web setup and the installer listen on 127.0.0.1:53 for this: check that
`127.0.0.1:53` is among the plain DNS addresses (Settings ›
Addresses & encryption › Protocols), then set `/etc/resolv.conf` to:

```
nameserver 127.0.0.1
options edns0 trust-ad
```

- **127.0.0.1 alone.** Do not add a public resolver as a second
  `nameserver`: the system asks it not only when DNSNova is down but
  whenever DNSNova answers SERVFAIL (a DNSSEC failure, for example), and
  `trust-ad` would then trust that answer's DNSSEC flag although it crossed
  the network unprotected. DNSNova itself does not use `/etc/resolv.conf`
  to reach its upstreams or name servers.
- **`trust-ad`** lets programs see that DNSNova validated an answer with
  DNSSEC (SSH `VerifyHostKeyDNS`, DANE). Without it the system clears the
  flag.
- **systemd-resolved.** If `/etc/resolv.conf` links to systemd-resolved
  (`127.0.0.53`), queries reach DNSNova only after `DNS=127.0.0.1` and
  `Domains=~.` in `/etc/systemd/resolved.conf`. DHCP clients and cloud-init
  may also rewrite the file.
- **Rate limits.** The server's own queries count against the per-address
  limit (`limits.client_qps`, 100 a second by default) like any other
  client's.
- **No battery-backed clock** (a Raspberry Pi, for example). After more
  than a week switched off, the machine starts with an old time, and DNSSEC
  rejects answers as not yet valid; but setting the time needs DNS. Give the
  time service a server by address so it works without DNS, for example
  `NTP=162.159.200.1` in `/etc/systemd/timesyncd.conf`, then
  `systemctl restart systemd-timesyncd`. With recursion, DNSNova notices a
  clock more than about a day off from the root's signatures and reports the clock offset,
  with by how much, on the overview and in alerts.
