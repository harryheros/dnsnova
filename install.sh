#!/usr/bin/env bash
# dnsnova installer
#
#   curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh | sh
#
# Installs or upgrades dnsnova, or removes it (--uninstall). With no options
# it asks nothing: it installs dnsnova for the internet, starts the web
# interface on port 7000 of this server only (reach it through an SSH tunnel)
# and prints how to open it; everything else is set up in the browser. With
# --lan it installs for a home or office network instead, and the web
# interface opens directly from that network. Run with
# --help for the options that configure everything here instead.
# Run by sh (curl ... | sh): fetch the script again and run it with bash.
if [ -z "${BASH_VERSION:-}" ]; then
    if command -v bash >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
        exec bash -c "$(curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh)" install.sh "$@"
    fi
    echo "error: this installer needs bash and curl" >&2
    exit 1
fi
set -euo pipefail

# Not root: use sudo when there is one (Debian often has none; then log in
# as root, for example with "su -", and run the command again).
if [ "$(id -u)" -ne 0 ] && [ -z "${DNSNOVA_ROOT:-}" ]; then
    if command -v sudo >/dev/null 2>&1; then
        if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then exec sudo bash "${BASH_SOURCE[0]}" "$@"; fi
        exec sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/harryheros/dnsnova/main/install.sh)" install.sh "$@"
    fi
    echo "error: run this as root (for example, log in with: su -)" >&2
    exit 1
fi

REPO="harryheros/dnsnova"
ROOT="${DNSNOVA_ROOT:-}"                      # install prefix (tests only)
BIN="$ROOT/usr/local/bin/dnsnova"
ETC="$ROOT/etc/dnsnova"
CONF="$ETC/dnsnova.toml"
VAR="$ROOT/var/lib/dnsnova"
UNIT="$ROOT/etc/systemd/system/dnsnova.service"
USER_NAME="dnsnova"
SKIP_SYSTEMD="${DNSNOVA_SKIP_SYSTEMD:-0}"     # tests only

# ── options ──
YES=0 FORCE=0 UNINSTALL=0 PURGE=0 DOH_PROXY=0 IP_CERT=1 LAN=0
MODE="" VERSION="" DOMAIN="" EMAIL="" CERT_FILE="" KEY_FILE="" ADMIN="" ADMIN_PORT=7000
LISTEN=() UPSTREAMS=() FALLBACKS=() ALLOW=()

usage() {
    cat <<'EOF'
Usage: install.sh [options]

With no options: install a server for the internet, start the web
interface on port 7000 of this server only and print how to open it through
an SSH tunnel. Choose addresses, upstreams and everything else in the browser.

  --lan                   install for a home or office network: DNS answers private
                          networks only, and the web interface opens directly from
                          them (http://<this server>:7000, no setup code)
  --admin-port PORT       port for the web interface (default 7000)
  --admin public          (without --lan) also open the web interface to other
                          machines, over HTTPS once a domain's certificate is ready
  --version vX.Y.Z        install this release instead of the latest

Configure here instead of in the browser (for scripts):
  --mode public|private   who may query: anyone (with rate limits) or listed networks
  --listen ADDR:PORT      address to serve DNS on; repeatable (default: every
                          public address of this host, port 53)
  --upstream URL          upstream resolver; repeatable, required for a new install
                          e.g. https://1.1.1.1/dns-query  tls://dns.google  8.8.8.8
  --fallback URL          upstream used only when the primaries fail; repeatable
  --allow CIDR            network allowed in private mode; repeatable
  --domain NAME           enable DNS over TLS (TCP 853), DNS over QUIC (UDP 853) and
                          DNS over HTTPS (TCP and UDP 443, HTTP/2 and HTTP/3) with
                          an automatic Let's Encrypt certificate for NAME
  --email ADDR            contact address for Let's Encrypt (optional)
  --no-ip-cert            do not include this host's IP addresses in the
                          certificate (they let clients upgrade to encrypted DNS
                          automatically; such certificates are renewed every few days)
  --doh-proxy             serve DNS over HTTPS on 127.0.0.1:8053 for nginx instead
  --cert-file PATH        with --doh-proxy: certificate for DNS over TLS and QUIC (e.g. nginx's)
  --key-file PATH         its private key
  --admin local|public|off
                          admin API and web interface on port 7000: local = only
                          from this server, through an SSH tunnel (the default for
                          the internet); public = also from other machines: from the
                          allowed private networks directly in private mode (the
                          default with --lan), otherwise over HTTPS only, once a
                          certificate exists; off = not at all
  --yes                   accepted for compatibility (the installer asks nothing)
  --force                 continue even if another program uses port 53

Remove:
  -u, --uninstall         stop and remove dnsnova, keep the configuration
  --purge                 with --uninstall: also remove configuration and data
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)      MODE="${2:-}"; shift ;;
        --listen)    LISTEN+=("${2:-}"); shift ;;
        --upstream)  UPSTREAMS+=("${2:-}"); shift ;;
        --fallback)  FALLBACKS+=("${2:-}"); shift ;;
        --allow)     ALLOW+=("${2:-}"); shift ;;
        --doh-proxy) DOH_PROXY=1 ;;
        --lan)       LAN=1 ;;
        --domain)    DOMAIN="${2:-}"; shift ;;
        --email)     EMAIL="${2:-}"; shift ;;
        --no-ip-cert) IP_CERT=0 ;;
        --cert-file) CERT_FILE="${2:-}"; shift ;;
        --key-file)  KEY_FILE="${2:-}"; shift ;;
        --admin)     ADMIN="${2:-}"; shift ;;
        --admin-port) ADMIN_PORT="${2:-}"; shift ;;
        --version)   VERSION="${2:-}"; shift ;;
        --yes|-y)    YES=1 ;;
        --force)     FORCE=1 ;;
        -u|--uninstall) UNINSTALL=1 ;;
        --purge)     PURGE=1 ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

# ── output ──
if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' N=$'\033[0m'; else B="" G="" Y="" R="" N=""; fi
step() { echo "${B}==>${N} $*"; }
ok()   { echo "  ${G}✓${N} $*"; }
warn() { echo "  ${Y}!${N} $*"; }
die()  { echo "${R}error:${N} $*" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The installer asks no questions: a plain install is finished in the
# browser, and the options cover unattended installs.
TTY=""
ask() { # ask "question" default -> REPLY
    local q="$1" def="${2:-}"
    if [ -z "$TTY" ]; then REPLY="$def"; return; fi
    if [ -n "$def" ]; then printf '%s [%s]: ' "$q" "$def" > /dev/tty; else printf '%s: ' "$q" > /dev/tty; fi
    IFS= read -r REPLY < /dev/tty || REPLY=""
    [ -n "$REPLY" ] || REPLY="$def"
}

have() { command -v "$1" >/dev/null 2>&1; }
systemd() { [ "$SKIP_SYSTEMD" = "1" ] || systemctl "$@"; }

# ── checks ──
preflight() {
    [ "$(id -u)" -eq 0 ] || [ -n "$ROOT" ] || die "run as root"
    [ "$(uname -s)" = "Linux" ] || die "dnsnova supports Linux only"
    if [ "$SKIP_SYSTEMD" != "1" ]; then
        [ -d /run/systemd/system ] || die "systemd is required"
    fi
    case "$(uname -m)" in
        x86_64|amd64)  ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) die "unsupported CPU architecture: $(uname -m) (amd64 and arm64 are supported)" ;;
    esac
    have sha256sum || die "sha256sum is required"
    have tar || die "tar is required"
    if have curl; then DL="curl"; elif have wget; then DL="wget"; else die "curl or wget is required"; fi
}

# HTTPS only: a download over plain HTTP could be swapped on the way. A
# mirror given in DNSNOVA_RELEASE_URL may be plain HTTP (a local test).
PROTO='=https'
case "${DNSNOVA_RELEASE_URL:-}" in http://*) PROTO='=https,http' ;; esac

fetch() { # fetch URL FILE [progress]
    # a progress bar for the download itself, when someone is watching
    if [ -n "${3:-}" ] && [ -t 2 ]; then
        if [ "$DL" = curl ]; then curl -fL -# --proto "$PROTO" --retry 2 -o "$2" "$1"
        elif wget --help 2>&1 | grep -q -- --show-progress; then wget -q --show-progress -O "$2" "$1"
        else wget -O "$2" "$1"; fi
        return
    fi
    if [ "$DL" = curl ]; then curl -fsSL --proto "$PROTO" --retry 2 -o "$2" "$1"
    else wget -q -O "$2" "$1"; fi
}

# ── download and verify ──
download() {
    local base
    if [ -n "${DNSNOVA_RELEASE_URL:-}" ]; then
        base="$DNSNOVA_RELEASE_URL"
    elif [ -n "$VERSION" ]; then
        base="https://github.com/$REPO/releases/download/$VERSION"
    else
        base="https://github.com/$REPO/releases/latest/download"
    fi
    local asset="dnsnova-linux-$ARCH.tar.gz"
    step "Downloading $asset"
    fetch "$base/$asset" "$TMP/$asset" progress || die "download failed: $base/$asset
  Has a release been published? See https://github.com/$REPO/releases"
    fetch "$base/SHA256SUMS" "$TMP/SHA256SUMS" || die "could not download SHA256SUMS"
    (cd "$TMP" && grep " $asset\$" SHA256SUMS | sha256sum -c --status) \
        || die "checksum mismatch for $asset: refusing to install"
    ok "checksum verified"
    tar -xzf "$TMP/$asset" -C "$TMP"
    PKG="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -name 'dnsnova-*' | head -n1)"
    [ -n "$PKG" ] && [ -x "$PKG/dnsnova" ] || die "unexpected archive layout"
    NEW_VERSION="$("$PKG/dnsnova" -v 2>/dev/null | awk '{print $2}')"
    ok "dnsnova ${NEW_VERSION:-unknown}"
}

# ── ports ──
port_users() { # port_users PORT -> "proc proc" (empty if free)
    have ss || return 0
    local users
    users="$(ss -H -lnup "sport = :$1" 2>/dev/null; ss -H -lntp "sport = :$1" 2>/dev/null)"
    # systemd-resolved's stub on 127.0.0.53/54 does not conflict with public addresses
    users="$(printf '%s\n' "$users" | grep -v -E '127\.0\.0\.5[34]%?[a-z0-9]*:' | grep -v 'dnsnova' || true)"
    [ -n "$(printf '%s' "$users" | tr -d '[:space:]')" ] || return 0
    local procs
    procs="$(printf '%s\n' "$users" | grep -o 'users:(("[^"]*"' | sed 's/users:(("//; s/"$//' | sort -u | tr '\n' ' ')"
    printf '%s' "${procs:-another program}"
}

check_ports() {
    local p busy=0 users
    for p in "$@"; do
        users="$(port_users "$p")"
        [ -n "$users" ] || continue
        busy=1
        warn "port $p is already in use by: $users"
        case "$users" in *AdGuardHome*) warn "stop it first: systemctl disable --now AdGuardHome" ;; esac
    done
    [ "$busy" -eq 1 ] || return 0
    if [ "$FORCE" -eq 1 ]; then warn "continuing because of --force"; return 0; fi
    if [ -n "$TTY" ]; then
        ask "Continue anyway? dnsnova will fail to start on addresses that are taken (y/N)" "n"
        case "$REPLY" in y|Y|yes) return 0 ;; esac
    fi
    die "a port dnsnova needs is in use; stop the other program or run with --force"
}

# ── configuration (new installs only) ──
public_addrs() {
    if ! have ip; then
        hostname -I 2>/dev/null | tr ' ' '\n' | grep -v -i -e '^$' -e '^fe80' -e '^127\.' -e '^::1$' || true
        return 0
    fi
    ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
    ip -o -6 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -v -i '^fe80' || true
}

public_listen_ips() { # prints listen IPs that a public CA could reach
    local l h
    for l in "${LISTEN[@]}"; do
        h="${l%:*}"; h="${h#[}"; h="${h%]}"
        case "$h" in
            10.*|127.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*|fc*|fd*|fe80*|::1|0.0.0.0|::|"") ;;
            *) echo "$h" ;;
        esac
    done
}

fmt_addr() { case "$1" in *:*) printf '[%s]:53' "$1" ;; *) printf '%s:53' "$1" ;; esac; }

toml_list() { # toml_list items... -> ["a", "b"]
    local out="" x
    for x in "$@"; do
        case "$x" in *[\"\\]*) die "invalid character in: $x" ;; esac
        out="$out${out:+, }\"$x\""
    done
    printf '[%s]' "$out"
}

# the address other machines most likely use to reach this one
primary_ip() {
    local a=""
    if have ip; then
        a="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
        [ -n "$a" ] || a="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
    fi
    [ -n "$a" ] || a="$(public_addrs | head -n1)"
    [ -n "$a" ] || a="$(hostname -I 2>/dev/null | awk '{print $1}')"
    case "$a" in *:*) a="[$a]" ;; esac
    printf '%s' "$a"
}

# LAN_NETS are the networks a home or office install serves (as the setup
# wizard's "My network"): private, shared (CGNAT, VPNs such as Tailscale)
# and unique local IPv6 addresses, none of them routed on the internet.
LAN_NETS=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7)

# simple: no DNS options given, so DNS is set up in the browser
simple() {
    [ ${#LISTEN[@]} -eq 0 ] && [ ${#UPSTREAMS[@]} -eq 0 ] && [ -z "$MODE" ] && [ ${#ALLOW[@]} -eq 0 ] &&
        [ -z "$DOMAIN" ] && [ -z "$CERT_FILE" ] && [ "$DOH_PROXY" -eq 0 ]
}

configure_simple() {
    step "Configuring"
    case "$ADMIN_PORT" in ''|*[!0-9]*) die "--admin-port must be a number" ;; esac
    local def=local mode=public
    [ "$LAN" -eq 0 ] || def=public mode=private
    case "${ADMIN:-$def}" in
        local)  ADMIN=local ;;
        public) ADMIN=public ;;
        *) die "--admin off needs the DNS options (--listen, --upstream, ...): there would be nothing to set it up with" ;;
    esac
    mkdir -p "$TMP/cfg"
    local f="$TMP/cfg/dnsnova.toml" listen=":$ADMIN_PORT"
    [ "$ADMIN" = local ] && listen="127.0.0.1:$ADMIN_PORT"
    {
        echo "# dnsnova configuration, written by install.sh on $(date -u +%Y-%m-%d)."
        echo "# Every setting is described in /usr/local/share/doc/dnsnova/dnsnova.example.toml."
        echo "# Changes are applied automatically when this file is saved."
        echo "# DNS starts once setup is finished in the web interface."
        echo
        echo "[server]"
        echo "mode = \"$mode\""
        echo "listen = []"
        echo
        if [ "$mode" = private ]; then
            echo "[access]"
            echo "# a home or office network: DNS, and the web interface over plain HTTP,"
            echo "# for these networks only"
            echo "allow = $(toml_list "${LAN_NETS[@]}")"
            echo
        fi
        echo "[upstream]"
        echo "primary = []"
        echo
        echo "[metrics]"
        echo 'listen = "127.0.0.1:9153"'
        echo
        echo "[admin]"
        echo "listen = \"$listen\""
    } > "$f"
    local errs
    if ! errs="$("$PKG/dnsnova" -t -c "$f" 2>&1)"; then
        echo "$errs" | sed "s#$TMP/cfg/##" >&2
        die "the configuration is not valid; nothing was installed"
    fi
    ok "configuration valid"
    NEW_CONF="$f"
}

configure() {
    step "Configuring"
    local addrs=() a
    while IFS= read -r a; do [ -n "$a" ] && addrs+=("$a"); done < <(public_addrs)

    # listen addresses
    if [ ${#LISTEN[@]} -eq 0 ]; then
        local defaults=()
        for a in "${addrs[@]}"; do defaults+=("$(fmt_addr "$a")"); done
        if [ -n "$TTY" ]; then
            echo "  This host's public addresses: ${addrs[*]:-(none found)}"
            ask "Serve DNS on (space-separated address:port)" "${defaults[*]:-}"
            read -r -a LISTEN <<< "$REPLY"
        else
            LISTEN=("${defaults[@]}")
        fi
    fi
    [ ${#LISTEN[@]} -gt 0 ] || die "no listen address: pass --listen 203.0.113.10:53"

    # mode
    if [ "$LAN" -eq 1 ]; then
        [ "${MODE:-private}" = private ] || die "--lan installs for a private network: it cannot be combined with --mode $MODE"
        MODE=private
        [ ${#ALLOW[@]} -gt 0 ] || ALLOW=("${LAN_NETS[@]}")
    fi
    if [ -z "$MODE" ]; then
        if [ -n "$TTY" ]; then
            echo "  Who may use this DNS server?"
            echo "    1) public  - anyone, protected by rate limits"
            echo "    2) private - only networks you list"
            ask "Choose" "1"
            case "$REPLY" in 2|private) MODE=private ;; *) MODE=public ;; esac
        else
            MODE=public
        fi
    fi
    case "$MODE" in public|private) ;; *) die "--mode must be public or private" ;; esac

    if [ "$MODE" = private ] && [ ${#ALLOW[@]} -eq 0 ]; then
        local mine="${SSH_CLIENT:-}"; mine="${mine%% *}"
        if [ -n "$TTY" ]; then
            ask "Allowed networks (space-separated, e.g. 198.51.100.0/24)" "$mine"
            read -r -a ALLOW <<< "$REPLY"
        elif [ -n "$mine" ]; then
            ALLOW=("$mine")
        fi
        [ ${#ALLOW[@]} -gt 0 ] || die "private mode needs --allow"
    fi

    # upstreams: there is deliberately no default
    while [ ${#UPSTREAMS[@]} -eq 0 ]; do
        [ -n "$TTY" ] || die "no upstream: pass --upstream (e.g. --upstream https://1.1.1.1/dns-query)"
        echo "  Upstream resolvers, for example:"
        echo "    https://1.1.1.1/dns-query   https://dns.google/dns-query   tls://dns.quad9.net   8.8.8.8"
        ask "Upstreams (space-separated)" ""
        read -r -a UPSTREAMS <<< "$REPLY"
    done
    if [ ${#FALLBACKS[@]} -eq 0 ] && [ -n "$TTY" ]; then
        ask "Fallback upstreams, used only if those fail (optional)" ""
        read -r -a FALLBACKS <<< "$REPLY"
    fi

    if [ "$DOH_PROXY" -eq 0 ] && [ -n "$TTY" ]; then
        ask "Serve DNS over HTTPS through nginx on 127.0.0.1:8053? (y/N)" "n"
        case "$REPLY" in y|Y|yes) DOH_PROXY=1 ;; esac
    fi

    # encrypted DNS
    if [ "$DOH_PROXY" -eq 0 ] && [ -z "$DOMAIN" ] && [ -n "$TTY" ]; then
        echo "  Encrypted DNS (DNS over TLS and QUIC on 853, DNS over HTTPS on 443) needs a domain"
        echo "  name pointing to this server. A Let's Encrypt certificate is obtained and"
        echo "  renewed automatically."
        ask "Domain for encrypted DNS (leave empty to skip)" ""
        DOMAIN="$REPLY"
        if [ -n "$DOMAIN" ] && [ -z "$EMAIL" ]; then
            ask "Contact email for Let's Encrypt (optional)" ""
            EMAIL="$REPLY"
        fi
    fi
    if [ "$DOH_PROXY" -eq 1 ] && [ -z "$CERT_FILE" ] && [ -n "$TTY" ]; then
        ask "Certificate file for DNS over TLS and QUIC on 853, e.g. nginx's fullchain.pem (leave empty to skip)" ""
        CERT_FILE="$REPLY"
        if [ -n "$CERT_FILE" ]; then
            ask "Private key file" "${CERT_FILE%/*}/privkey.pem"
            KEY_FILE="$REPLY"
        fi
    fi
    # admin interface: without a terminal, the safer one
    case "$ADMIN_PORT" in ''|*[!0-9]*) die "--admin-port must be a number" ;; esac
    [ "$ADMIN_PORT" -ge 1 ] && [ "$ADMIN_PORT" -le 65535 ] || die "--admin-port must be 1 to 65535"
    [ -n "$ADMIN" ] || [ "$LAN" -eq 0 ] || ADMIN=public
    while [ -z "$ADMIN" ]; do
        if [ -z "$TTY" ]; then ADMIN=local; break; fi
        echo "  How should the admin interface (port $ADMIN_PORT) be reached?"
        echo "    1) only from this server, through an SSH tunnel (more secure)"
        if [ "$MODE" = private ]; then
            echo "    2) also directly from the allowed networks, with a password"
        else
            echo "    2) also from other machines, over HTTPS with a password ${B}(needs a certificate: --domain or --cert-file)${N}"
        fi
        ask "Choose 1 or 2" ""
        case "$REPLY" in 1) ADMIN=local ;; 2) ADMIN=public ;; esac
    done
    case "$ADMIN" in local|public|off) ;; *) die "--admin must be local, public or off" ;; esac

    [ -z "$DOMAIN" ] || [ "$DOH_PROXY" -eq 0 ] || die "--domain and --doh-proxy cannot be combined: nginx owns port 443; use --cert-file/--key-file for DoT"
    if [ -n "$CERT_FILE" ] && [ -z "$KEY_FILE" ]; then die "--cert-file needs --key-file"; fi

    # DoT, DoQ and DoH listen on the same addresses as port 53
    DOT_LISTEN=() HTTPS_LISTEN=()
    if [ -n "$DOMAIN" ] || [ -n "$CERT_FILE" ]; then
        local l host
        for l in "${LISTEN[@]}"; do
            host="${l%:*}"
            DOT_LISTEN+=("$host:853")
            [ -n "$DOMAIN" ] && HTTPS_LISTEN+=("$host:443")
        done
    fi

    mkdir -p "$TMP/cfg"
    local f="$TMP/cfg/dnsnova.toml"
    {
        echo "# dnsnova configuration, written by install.sh on $(date -u +%Y-%m-%d)."
        echo "# Every setting is described in /usr/local/share/doc/dnsnova/dnsnova.example.toml."
        echo "# Changes are applied automatically when this file is saved."
        echo
        echo "[server]"
        echo "mode = \"$MODE\""
        echo "listen = $(toml_list "${LISTEN[@]}")"
        echo
        echo "[doh]"
        if [ "$DOH_PROXY" -eq 1 ]; then echo 'listen = "127.0.0.1:8053"'; else echo 'listen = ""   # e.g. "127.0.0.1:8053" behind nginx'; fi
        if [ ${#HTTPS_LISTEN[@]} -gt 0 ]; then echo "https_listen = $(toml_list "${HTTPS_LISTEN[@]}")"; fi
        echo
        if [ ${#DOT_LISTEN[@]} -gt 0 ]; then
            echo "[dot]"
            echo "listen = $(toml_list "${DOT_LISTEN[@]}")"
            echo
            echo "[doq]"
            echo "listen = $(toml_list "${DOT_LISTEN[@]}")   # UDP"
            echo
            echo "[tls]"
            if [ -n "$DOMAIN" ]; then
                echo 'certificate = "acme"'
                echo "domains = $(toml_list "$DOMAIN")"
                if [ "$IP_CERT" -eq 1 ] && [ -n "$(public_listen_ips)" ]; then
                    echo "ip_addresses = true   # lets clients upgrade to encrypted DNS automatically (DDR)"
                fi
                if [ -n "$EMAIL" ]; then echo "email = $(toml_list "$EMAIL" | tr -d '[]')"; fi
            else
                echo 'certificate = "files"'
                echo "cert_file = $(toml_list "$CERT_FILE" | tr -d '[]')"
                echo "key_file = $(toml_list "$KEY_FILE" | tr -d '[]')"
            fi
            echo
        fi
        echo "[upstream]"
        echo "primary = $(toml_list "${UPSTREAMS[@]}")"
        if [ ${#FALLBACKS[@]} -gt 0 ]; then echo "fallback = $(toml_list "${FALLBACKS[@]}")"; fi
        if [ "$MODE" = private ]; then
            echo
            echo "[access]"
            echo "allow = $(toml_list "${ALLOW[@]}")"
        fi
        echo
        echo "[metrics]"
        echo 'listen = "127.0.0.1:9153"'
        case "$ADMIN" in
            local)  printf '\n[admin]\nlisten = "127.0.0.1:%s"   # reach it through an SSH tunnel\n' "$ADMIN_PORT" ;;
            public) if [ "$MODE" = private ]; then
                        printf '\n[admin]\nlisten = ":%s"   # this server and the allowed private networks\n' "$ADMIN_PORT"
                    else
                        printf '\n[admin]\nlisten = ":%s"   # other machines over HTTPS only; plain HTTP on this server alone\n' "$ADMIN_PORT"
                    fi ;;
        esac
    } > "$f"

    local errs
    if ! errs="$("$PKG/dnsnova" -t -c "$f" 2>&1)"; then
        echo "$errs" | sed "s#$TMP/cfg/##" >&2
        die "the configuration is not valid; nothing was installed"
    fi
    ok "configuration valid"
    NEW_CONF="$f"
}

# ── install ──
install_files() {
    step "Installing"
    if [ -z "$ROOT" ] && ! id "$USER_NAME" >/dev/null 2>&1; then
        useradd --system --no-create-home --home-dir /var/lib/dnsnova --shell /usr/sbin/nologin "$USER_NAME"
        ok "created system user $USER_NAME"
    fi
    install -d -m 755 "$(dirname "$BIN")" "$(dirname "$UNIT")" "$ROOT/usr/local/share/doc/dnsnova"
    install -d -m 750 "$ETC" "$VAR"
    if [ -z "$ROOT" ]; then chown "$USER_NAME:$USER_NAME" "$ETC" "$VAR"; fi
    if [ -n "${NEW_CONF:-}" ]; then
        install -m 640 "$NEW_CONF" "$CONF"
        if [ -z "$ROOT" ]; then chown "$USER_NAME:$USER_NAME" "$CONF"; fi
        ok "wrote $CONF"
    fi
    local doc
    for doc in dnsnova.example.toml nginx-doh.conf; do
        if [ -f "$PKG/$doc" ]; then install -m 644 "$PKG/$doc" "$ROOT/usr/local/share/doc/dnsnova/$doc"; fi
    done
    install -m 644 "$PKG/dnsnova.service" "$UNIT"
    install -m 755 "$PKG/dnsnova" "$BIN.new"
    mv -f "$BIN.new" "$BIN"
    ok "installed $BIN"
}

healthy() { # wait up to 10 s for the service to answer its health check
    [ "$SKIP_SYSTEMD" = "1" ] && return 0
    local i
    for i in $(seq 1 20); do
        if systemctl is-active --quiet dnsnova; then
            if [ "$DL" = curl ]; then curl -fsS -m 2 http://127.0.0.1:9153/healthz >/dev/null 2>&1 && return 0
            else wget -q -T 2 -O /dev/null http://127.0.0.1:9153/healthz && return 0; fi
            grep -q '^listen = "127.0.0.1:9153"' "$CONF" 2>/dev/null || return 0 # metrics not enabled
        fi
        sleep 0.5
    done
    return 1
}

fresh_install() {
    preflight
    download
    if simple; then
        configure_simple
        check_ports "$ADMIN_PORT"
        local dns
        dns="$(port_users 53)"
        if [ -n "$dns" ]; then
            warn "port 53 is in use by: $dns"
            case "$dns" in *AdGuardHome*) warn "stop it before you finish setup: systemctl disable --now AdGuardHome" ;;
                *) warn "stop it before you finish setup, or choose other addresses there" ;; esac
        fi
        install_files
        systemd daemon-reload
        systemd enable --now dnsnova
        if healthy; then ok "dnsnova is running"; else
            warn "dnsnova did not report healthy; see: journalctl -u dnsnova -n 50"
        fi
        summary_simple
        return
    fi
    configure
    local ports=(53)
    [ ${#DOT_LISTEN[@]} -eq 0 ] || ports+=(853)
    [ ${#HTTPS_LISTEN[@]} -eq 0 ] || ports+=(443)
    [ "$ADMIN" = off ] || ports+=("$ADMIN_PORT")
    check_ports "${ports[@]}"
    install_files
    systemd daemon-reload
    systemd enable --now dnsnova
    if healthy; then ok "dnsnova is running"; else
        warn "dnsnova did not report healthy; see: journalctl -u dnsnova -n 50"
    fi
    summary
}

upgrade() {
    preflight
    local old
    old="$("$BIN" -v 2>/dev/null | awk '{print $2}' || true)"
    step "Upgrading dnsnova ${old:-}"
    download
    if [ -n "$old" ] && [ "$old" = "$NEW_VERSION" ] && [ -z "$VERSION" ]; then
        ok "already up to date"
        return
    fi
    "$PKG/dnsnova" -t -c "$CONF" >/dev/null || die "the new version does not accept $CONF; nothing was changed"
    cp -p "$BIN" "$VAR/dnsnova.prev"
    install_files
    systemd daemon-reload
    systemd restart dnsnova
    if healthy; then
        ok "upgraded to $NEW_VERSION"
    else
        warn "the new version is not healthy: rolling back to ${old:-the previous version}"
        install -m 755 "$VAR/dnsnova.prev" "$BIN"
        systemd restart dnsnova
        die "upgrade failed and was rolled back; see: journalctl -u dnsnova -n 50"
    fi
}

uninstall() {
    step "Removing dnsnova"
    if [ "$SKIP_SYSTEMD" != "1" ] && systemctl list-unit-files dnsnova.service >/dev/null 2>&1; then
        systemctl disable --now dnsnova >/dev/null 2>&1 || true
    fi
    rm -f "$UNIT" "$BIN" "$VAR/dnsnova.prev"
    rm -rf "$ROOT/usr/local/share/doc/dnsnova"
    systemd daemon-reload || true
    ok "service and program removed"
    if [ "$PURGE" -eq 1 ]; then
        rm -rf "$ETC" "$VAR"
        if [ -z "$ROOT" ] && id "$USER_NAME" >/dev/null 2>&1; then userdel "$USER_NAME" 2>/dev/null || true; fi
        ok "configuration, data and the $USER_NAME user removed"
    else
        ok "configuration kept in $ETC (remove everything with: -u --purge)"
    fi
}

summary() {
    echo
    echo "${B}dnsnova is installed.${N}"
    echo "  Configuration:  $CONF  (applied automatically when saved)"
    echo "  Logs:           journalctl -u dnsnova -f"
    echo "  Health:         curl http://127.0.0.1:9153/healthz"
    echo "  Serving DNS on: ${LISTEN[*]}  (mode: $MODE)"
    if [ "$DOH_PROXY" -eq 1 ]; then
        echo "  DoH backend:    http://127.0.0.1:8053/dns-query  (nginx example: /usr/local/share/doc/dnsnova)"
    fi
    if [ -n "$DOMAIN" ]; then
        echo "  DNS over TLS:   $DOMAIN:853"
        echo "  DNS over QUIC:  quic://$DOMAIN"
        echo "  DNS over HTTPS: https://$DOMAIN/dns-query  (HTTP/2 and HTTP/3)"
        echo "  The certificate is being requested now. It needs $DOMAIN to point to this"
        echo "  server and port 443 reachable from the internet; follow it with:"
        echo "    journalctl -u dnsnova -f | grep tls"
    elif [ -n "$CERT_FILE" ]; then
        echo "  DNS over TLS and QUIC: port 853, certificate $CERT_FILE"
        echo "  dnsnova must be able to read the key: e.g. setfacl -m u:dnsnova:r $KEY_FILE"
    fi
    local open="53 (UDP and TCP)"
    [ ${#DOT_LISTEN[@]} -eq 0 ] || open="$open, 853 (TCP and UDP)"
    [ ${#HTTPS_LISTEN[@]} -eq 0 ] || open="$open, 443 (TCP and UDP)"
    if [ "$ADMIN" = public ] && { [ "$MODE" = private ] || has_cert; }; then open="$open, $ADMIN_PORT (TCP)"; fi
    echo "  Remember to open port $open in your firewall."
    admin_summary
}

setup_code() { # waits for the service to write the code
    local i
    for i in $(seq 1 20); do
        if [ -r "$VAR/secrets/setup-code" ]; then tr -d '[:space:]' < "$VAR/secrets/setup-code"; return; fi
        [ "$SKIP_SYSTEMD" = "1" ] && return
        sleep 0.5
    done
}

# tunnel_hint prints the SSH command that brings the web interface to the
# computer the installer is used from.
tunnel_hint() {
    local host
    host="$(primary_ip)"
    printf 'ssh -L %s:127.0.0.1:%s %s@%s' "$ADMIN_PORT" "$ADMIN_PORT" "${SUDO_USER:-root}" "${host:-<this server>}"
}

# has_cert: a certificate is configured, so other machines can use HTTPS
has_cert() { [ -n "$DOMAIN" ] || [ -n "$CERT_FILE" ]; }

# lan_urls prints http://ADDR:PORT for this host's private addresses.
lan_urls() {
    local a
    while read -r a; do
        case "$a" in
            10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) echo "http://$a:$ADMIN_PORT" ;;
            fc*|fd*) echo "http://[$a]:$ADMIN_PORT" ;;
        esac
    done < <(public_addrs) | awk '!seen[$0]++'
}

summary_simple() {
    echo
    echo "${B}DNSNova is installed and running.${N}"
    if [ "$LAN" -eq 1 ] && [ "$ADMIN" = public ]; then
        echo "Open one of these addresses from a device on your network and follow the setup wizard:"
        { lan_urls; echo "http://127.0.0.1:$ADMIN_PORT"; } | sed 's/^/  /'
        echo "If a firewall is on, open TCP port $ADMIN_PORT to your network."
    else
        echo "The web interface is not encrypted yet, so it opens only on this server."
        echo "On your computer, open a tunnel:"
        echo "  $(tunnel_hint)"
        echo "then open http://127.0.0.1:$ADMIN_PORT/ and follow the setup wizard."
        if [ "$ADMIN" = public ]; then
            echo "Once a domain is set up there, other machines can also open it over HTTPS on"
            echo "port $ADMIN_PORT (open TCP $ADMIN_PORT in the firewall)."
        fi
        if [ "$LAN" -eq 0 ] && [ -n "$(lan_urls)" ] && [ "$(public_addrs | sort -u | wc -l)" -eq "$(lan_urls | wc -l)" ]; then
            echo
            echo "This server has only private addresses. For a home or office network, install"
            echo "with --lan instead, and the web interface opens directly from that network:"
            echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh -s -- -u --purge"
            echo "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh -s -- --lan"
        fi
    fi
    echo
    echo "Control the service: systemctl start|stop|restart|status dnsnova"
    echo "Uninstall:           curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh -s -- -u"
    echo "Forgot the password: dnsnova -reset-admin"
}

admin_summary() {
    [ "$ADMIN" = off ] && return 0
    local code="" i
    for i in $(seq 1 10); do # the service writes the code when it starts
        if [ -r "$VAR/secrets/setup-code" ]; then code="$(tr -d '[:space:]' < "$VAR/secrets/setup-code")"; break; fi
        [ "$SKIP_SYSTEMD" = "1" ] && break
        sleep 0.5
    done
    echo
    echo "${B}Admin interface${N}"
    if [ "$ADMIN" = public ] && [ "$MODE" = private ]; then
        echo "  From the allowed networks (no setup code needed there):"
        { lan_urls; echo "http://127.0.0.1:$ADMIN_PORT"; } | sed 's/^/    /'
        return 0
    fi
    echo "  On this server, or from your computer through a tunnel:"
    echo "    $(tunnel_hint)"
    echo "    then http://127.0.0.1:$ADMIN_PORT/ (no setup code needed)"
    if [ "$ADMIN" = public ]; then
        if [ -n "$DOMAIN" ]; then
            echo "  From other machines, once the certificate is issued: https://$DOMAIN:$ADMIN_PORT/"
        elif [ -n "$CERT_FILE" ]; then
            echo "  From other machines: https://<a name on $CERT_FILE>:$ADMIN_PORT/"
        else
            warn "no certificate: other machines are refused until one is set up (plain HTTP is answered only on this server)"
        fi
        if has_cert && [ -n "$code" ]; then
            echo "  Setup from another machine asks for this code: $code"
        fi
    fi
}

if [ "$UNINSTALL" -eq 1 ]; then
    uninstall
elif [ -x "$BIN" ] && [ -f "$CONF" ]; then
    upgrade
else
    fresh_install
fi
