#!/usr/bin/env bash
# Tests for install.sh on simulated machines: a release served locally, and
# stand-ins for ip, ss, uname and ufw that describe each machine. Nothing is
# installed on this one (DNSNOVA_ROOT) and systemd is not used.
#   bash tools/test-install.sh        (needs go, python3; run from the repo)
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="$REPO/install.sh"
PASS=0 FAIL=0
W="$(mktemp -d)"
trap 'kill "$HTTP_PID" 2>/dev/null; rm -rf "$W"' EXIT

# ── a release: dnsnova-linux-{amd64,arm}.tar.gz and SHA256SUMS ──
mkdir -p "$W/rel"
for arch in amd64 arm; do
    d="$W/build/dnsnova-v9.9.9-linux-$arch"
    mkdir -p "$d"
    (cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=$( [ $arch = amd64 ] && echo amd64 || echo arm ) GOARM=6 \
        go build -ldflags "-X main.version=v9.9.9" -o "$d/dnsnova" ./cmd/dnsnova) || exit 1
    cp "$REPO/deploy/dnsnova.service" "$REPO/deploy/nginx-doh.conf" "$REPO/dnsnova.example.toml" "$d/"
    tar -C "$W/build" -czf "$W/rel/dnsnova-linux-$arch.tar.gz" "dnsnova-v9.9.9-linux-$arch"
done
# the arm binary cannot run here: the installer only asks it its version
# and to check the configuration, so a wrapper runs the amd64 one
cp "$W/build/dnsnova-v9.9.9-linux-amd64/dnsnova" "$W/amd64-dnsnova"
printf '#!/bin/sh\nexec %s "$@"\n' "$W/amd64-dnsnova" > "$W/build/dnsnova-v9.9.9-linux-arm/dnsnova"
chmod 755 "$W/build/dnsnova-v9.9.9-linux-arm/dnsnova"
tar -C "$W/build" -czf "$W/rel/dnsnova-linux-arm.tar.gz" "dnsnova-v9.9.9-linux-arm"
(cd "$W/rel" && sha256sum dnsnova-linux-*.tar.gz > SHA256SUMS)
PORT=$((20000 + RANDOM % 20000))
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$W/rel" >/dev/null 2>&1 &
HTTP_PID=$!
for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/SHA256SUMS" >/dev/null && break; sleep 0.1; done

# ── stand-ins, reading the machine description in $M ──
mkdir -p "$W/bin"
cat > "$W/bin/ip" <<'EOF'
#!/bin/sh
# ip -o -4|-6 addr show scope global ; ip -4|-6 route get X
case "$*" in
    *"-4 addr"*) cat "$M/addr4" 2>/dev/null ;;
    *"-6 addr"*) cat "$M/addr6" 2>/dev/null ;;
    *"-4 route get"*) [ -f "$M/src4" ] && echo "1.1.1.1 via 203.0.113.1 dev eth0 src $(cat "$M/src4") uid 0" ;;
esac
exit 0
EOF
cat > "$W/bin/ss" <<'EOF'
#!/bin/sh
# ss -H -lnup|-lntp "sport = :PORT"
proto=t; case "$*" in *-lnup*) proto=u ;; esac
port="${*##*:}"
cat "$M/ss-$proto-$port" 2>/dev/null
exit 0
EOF
cat > "$W/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in -m) cat "$M/arch" 2>/dev/null || echo x86_64 ;; *) echo Linux ;; esac
EOF
cat > "$W/bin/ufw" <<'EOF'
#!/bin/sh
[ -f "$M/ufw" ] && echo "Status: active" || echo "Status: inactive"
EOF
chmod 755 "$W/bin/"*

# machine NAME: a fresh machine description and an empty root
machine() {
    export M="$W/m/$1" R="$W/root/$1"
    mkdir -p "$M" "$R"
    printf '2: eth0    inet 203.0.113.10/24 brd 203.0.113.255 scope global eth0\\       valid_lft forever preferred_lft forever\n' > "$M/addr4"
    : > "$M/addr6"
    echo 203.0.113.10 > "$M/src4"
}
udp53() { printf 'UNCONN 0 0 %s 0.0.0.0:* users:(("%s",pid=1,fd=3))\n' "$2" "$1" >> "$M/ss-u-53"; }

run() { # run ARGS...: the installer on machine $M into root $R
    PATH="$W/bin:$PATH" DNSNOVA_ROOT="$R" DNSNOVA_SKIP_SYSTEMD=1 DNSNOVA_TEST_SANDBOX="${SANDBOX:-ok}" \
        DNSNOVA_RELEASE_URL="http://127.0.0.1:$PORT" bash "$INSTALL" "$@" > "$W/out.txt" 2>&1
}
conf() { cat "$R/etc/dnsnova/dnsnova.toml"; }
has() { grep -q -- "$1" "$2"; }
check() {
    local name="$1"; shift
    if "$@"; then PASS=$((PASS + 1)); echo "ok   $name"
    else FAIL=$((FAIL + 1)); echo "FAIL $name"; sed 's/^/     | /' "$W/out.txt" | tail -15; fi
}
listen_is() { [ "$(conf | grep -m1 '^listen = \[')" = "listen = $1" ]; }

# 1. The plain install (setup in the browser).
machine plain; run; rc=$?
check "plain install succeeds" test $rc -eq 0
check "  DNS left to the setup wizard" listen_is '[]'
check "  metrics on 9153" bash -c "grep -q '127.0.0.1:9153' '$R/etc/dnsnova/dnsnova.toml'"
check "  no sandbox drop-in where the sandbox works" test ! -e "$R/etc/systemd/system/dnsnova.service.d"

# 2. A server with containers, VMs and IPv6 privacy addresses: those are left
#    out; another DNS server on its own address is no conflict.
machine busy
cat >> "$M/addr4" <<'EOF'
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\       valid_lft forever preferred_lft forever
4: virbr0    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0\       valid_lft forever preferred_lft forever
EOF
cat > "$M/addr6" <<'EOF'
2: eth0    inet6 2001:db8::abcd/64 scope global temporary dynamic \       valid_lft 86000sec preferred_lft 14000sec
2: eth0    inet6 2001:db8::10/64 scope global dynamic mngtmpaddr \       valid_lft 86000sec preferred_lft 14000sec
EOF
udp53 systemd-resolve 127.0.0.53%lo:53
udp53 dnsmasq 192.168.122.1%virbr0:53
udp53 dnsmasq 127.0.1.1:53
run --upstream 1.1.1.1; rc=$?
check "server with libvirt, Docker and resolved: installs" test $rc -eq 0
check "  public addresses and 127.0.0.1; no bridges, no privacy address" \
    listen_is '["203.0.113.10:53", "[2001:db8::10]:53", "127.0.0.1:53"]'

# 3. Another DNS server on every address: nothing to serve on, said so.
machine wildcard; udp53 named 0.0.0.0:53
run --upstream 1.1.1.1; rc=$?
check "port 53 taken on every address: refused" test $rc -ne 0
check "  naming the program" has "named already answers there" "$W/out.txt"
check "  and why nothing is left" has "port 53 is taken on every address" "$W/out.txt"

# 4. An address given that another program uses: refused, unless --force.
machine given; udp53 dnsmasq 192.168.122.1%virbr0:53
printf '4: virbr0    inet 192.168.122.1/24 scope global virbr0\\ x\n' >> "$M/addr4"
run --upstream 1.1.1.1 --listen 192.168.122.1:53; rc=$?
check "--listen on a taken address: refused" test $rc -ne 0
check "  saying which" has "192.168.122.1:53 is already in use by: dnsmasq" "$W/out.txt"
run --upstream 1.1.1.1 --listen 203.0.113.10:53; rc=$?
check "  another address on the same machine: accepted" test $rc -eq 0

# 5. The metrics port taken (9153 is a common one): the next free one.
machine metrics
printf 'LISTEN 0 4096 127.0.0.1:9153 0.0.0.0:* users:(("exporter",pid=1,fd=3))\n' > "$M/ss-t-9153"
run; rc=$?
check "metrics port taken: installs" test $rc -eq 0
check "  on 9154" bash -c "grep -q '127.0.0.1:9154' '$R/etc/dnsnova/dnsnova.toml'"

# 6. A container that cannot sandbox services: a drop-in, removed again.
machine lxc; SANDBOX=fail run; rc=$?
check "container without sandboxing: installs" test $rc -eq 0
check "  with the drop-in" has "ProtectSystem=no" "$R/etc/systemd/system/dnsnova.service.d/sandbox.conf"
SANDBOX=fail run -u --purge
check "  removed on uninstall" test ! -e "$R/etc/systemd/system/dnsnova.service.d"

# 7. A certbot certificate (nginx in front): copied by a deploy hook.
#    Needs root: the installer recognizes certbot by its path in /etc.
if [ "$(id -u)" -ne 0 ]; then echo "skip certbot certificate (run as root)"; else
machine certbot
mkdir -p "$W/le/live/dns.example.com"
(cd "$W/le/live/dns.example.com" && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout privkey.pem -out fullchain.pem -subj /CN=dns.example.com -days 30 >/dev/null 2>&1)
CREATED_LE=0
[ -d /etc/letsencrypt/live ] || { mkdir -p /etc/letsencrypt/live && CREATED_LE=2; }
[ -e /etc/letsencrypt/live/dns.example.com ] || { ln -s "$W/le/live/dns.example.com" /etc/letsencrypt/live/dns.example.com && [ "$CREATED_LE" -eq 2 ] || CREATED_LE=1; }
run --upstream 1.1.1.1 --doh-proxy --cert-file /etc/letsencrypt/live/dns.example.com/fullchain.pem \
    --key-file /etc/letsencrypt/live/dns.example.com/privkey.pem; rc=$?
[ "$CREATED_LE" -ge 1 ] && rm -f /etc/letsencrypt/live/dns.example.com
[ "$CREATED_LE" -eq 2 ] && rm -rf /etc/letsencrypt
check "certbot certificate: installs" test $rc -eq 0
check "  configuration points at the copies" has 'cert_file = "/etc/dnsnova/tls/fullchain.pem"' "$R/etc/dnsnova/dnsnova.toml"
check "  deploy hook written" has 'RENEWED_LINEAGE' "$R/etc/letsencrypt/renewal-hooks/deploy/dnsnova.sh"
fi

# 8. Upgrading with options: they are for new installs, and said so.
machine upgrade; run --upstream 1.1.1.1
before="$(conf)"
run --lan; rc=$?
check "options on an installed server: a warning" has "apply only to new installations" "$W/out.txt"
check "  the configuration is kept" test "$(conf)" = "$before"

# 9. 32-bit ARM (Raspberry Pi OS 32-bit).
machine pi; echo armv7l > "$M/arch"
run --lan; rc=$?
check "armv7l: the arm release is installed" bash -c "[ $rc -eq 0 ] && grep -q 'dnsnova-linux-arm.tar.gz' '$W/out.txt'"

# 10. ufw on: the commands to run.
machine ufw; touch "$M/ufw"
run --upstream 1.1.1.1; rc=$?
check "ufw on: exact commands" bash -c "grep -q 'ufw allow 53/udp' '$W/out.txt' && grep -q 'ufw allow 53/tcp' '$W/out.txt'"

# 11. Only private addresses (a cloud server behind NAT, or a home server):
#     the hint does not take a cloud server for a home one.
machine nat
printf '2: ens5    inet 172.31.5.9/20 scope global ens5\\ x\n' > "$M/addr4"; echo 172.31.5.9 > "$M/src4"
run; rc=$?
check "private addresses only: the hint names cloud servers too" has "a cloud server behind NAT" "$W/out.txt"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
