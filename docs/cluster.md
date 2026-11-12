# Several servers

DNSNova servers can share one configuration, and each can take its anycast
route back when it cannot answer. Both are optional: a server without
`[cluster]` and `[anycast]` runs on its own, as before. Each server always
answers from its own cache; queries never go from one server to another.

## Shared settings

One server is the **primary**: its settings, edited in its web interface or
its file, are the cluster's. The others are **followers**: every few seconds
each one asks the primary whether the settings changed, applies them, and
tells the primary how it is doing. The primary needs no list of followers.

What a follower takes from the primary: everything except the primary's own
`[cluster]` and `[anycast]`. What it keeps: every setting in its own file,
which wins over the primary's. A follower's file is therefore short: the
settings that differ from server to server, usually the addresses.

### Set up the primary

In its configuration file (not the web interface, which cannot change
`[cluster]`):

```toml
[cluster]
role = "primary"
name = "ams-1"              # default: the host name
region = "Amsterdam"        # shown on the Nodes page
listen = "10.0.0.1:7001"    # where followers reach it
```

Restart it. It makes the cluster key, `/var/lib/dnsnova/secrets/cluster-key`,
and the web interface gains a **Nodes** page.

### Add a follower

Install DNSNova on the new server, then copy the key from the primary to the
same path, readable by the dnsnova user only:

```sh
install -d -m 700 -o dnsnova -g dnsnova /var/lib/dnsnova/secrets
install -m 600 -o dnsnova -g dnsnova cluster-key /var/lib/dnsnova/secrets/cluster-key
```

Its whole configuration file can be:

```toml
[server]
listen = ["203.0.113.53:53", "[2001:db8::53]:53"]   # this server's addresses

[admin]
listen = "127.0.0.1:7000"

[cluster]
role = "follower"
name = "fra-1"
region = "Frankfurt"
primary = "10.0.0.1:7001"
# interval = "10s"
```

Restart it. It fetches the settings, keeps a copy in
`/var/lib/dnsnova/cluster-shared.toml`, and appears on the primary's Nodes
page within seconds.

### How it behaves

- **A change** on the primary reaches every follower at its next sync
  (10 seconds by default). Changing the settings in a follower's web
  interface is refused; it says where to change them.
- **A setting that does not work on a follower** (with its own settings on
  top) is not applied there. The follower keeps the last settings that
  worked; the Nodes page shows it as *Refused*, with the reason.
- **When the primary is down**, followers keep answering with the settings
  they have, and start again from their copy. The primary is only needed
  for changes.
- **A node is offline** on the Nodes page after three missed syncs.
- `[cluster]` changes take effect after a restart.

### Security

Every exchange is encrypted and authenticated with AES-256-GCM under the
cluster key, and carries the time and a random challenge that the answer
must repeat. Without the key, nobody can read the settings, send a server
settings, or pose as a server, even on an open network; recorded answers
cannot be played back. Plain HTTP is therefore fine on the cluster port,
but keep it on a private network or behind a firewall anyway: there is no
reason for anyone else to reach it. The clocks of the servers must be
within five minutes of each other (use NTP).

Keep the key as secret as the administrator password. To change it, make
a new one on the primary (delete the file and restart), then copy it to
every follower and restart them.

## Anycast

With anycast, every server announces the same address over BGP and each
client reaches the nearest. A server that cannot answer must withdraw its
route, or the clients routed to it get no answers. DNSNova checks itself
and runs your commands to announce or withdraw:

```toml
[anycast]
enabled = true
announce = ["birdc", "enable", "anycast"]
withdraw = ["birdc", "disable", "anycast"]
interval = "2s"   # between checks
rise = 3          # good checks in a row before announcing
fall = 3          # failed checks in a row before withdrawing
drain = "5s"      # at shutdown: withdraw, then keep answering this long
```

- **A check passes** when the server can resolve (as `/healthz` reports)
  and its own UDP listener answers a query, through the socket clients use.
- **At start** the route is withdrawn, and announced after `rise` good
  checks. **At shutdown** (stop, restart, upgrade) it is withdrawn first and
  the server keeps answering for `drain` while the routers move traffic.
- **A command that fails** is logged and tried again at the next check.
- The state is on the Nodes page, in `/healthz` (`"anycast"`) and in the
  metrics (`dnsnova_anycast_announced`).

The commands run as the dnsnova user, without a shell, and come only from
the file on the server: neither the web interface nor a cluster primary can
set them. They must be safe to run more than once.

### With BIRD

A BIRD 2 protocol that announces the anycast address while it is enabled:

```
protocol static anycast {
  ipv4;
  route 192.0.2.53/32 blackhole;
}
```

with the address itself on a dummy interface, and your BGP session
exporting that route. `birdc enable anycast` and `birdc disable anycast`
then announce and withdraw it.

`birdc` needs BIRD's control socket. Give the dnsnova service access with a
drop-in, `systemctl edit dnsnova`:

```ini
[Service]
SupplementaryGroups=bird
ReadWritePaths=/run/bird
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
```

and check it: `sudo -u dnsnova birdc show protocols anycast`.

Other routing daemons work the same way: any command that announces, and
one that withdraws (`vtysh -c ...` for FRR, a call to ExaBGP's API).
