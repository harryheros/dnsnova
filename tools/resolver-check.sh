#!/usr/bin/env bash
# Checks a DNS server from the outside: popular domains, DNSSEC, minimal
# names (RFC 9156), NXDOMAIN, TCP, IPv6 records and response times, next to
# a reference resolver. Meant for a new DNSNova server, recursive or not.
#
#   bash resolver-check.sh [server] [reference]
#
# server defaults to 127.0.0.1, reference to 1.1.1.1. For another port than
# 53, write address#port, such as 127.0.0.1#5353. Needs dig
# (Debian, Ubuntu: apt install dnsutils; Fedora, RHEL: dnf install bind-utils).

S=${1:-127.0.0.1}
R=${2:-1.1.1.1}

if ! command -v dig >/dev/null 2>&1; then
	echo "dig is not installed: apt install dnsutils (or dnf install bind-utils)" >&2
	exit 2
fi

pass=0 fail=0 warn=0
ok()   { pass=$((pass + 1)); printf '  \033[32mok\033[0m    %s\n' "$*"; }
bad()  { fail=$((fail + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
note() { warn=$((warn + 1)); printf '  \033[33mnote\033[0m  %s\n' "$*"; }

# ask SERVER ARGS...: sets out, status, flags, ms, answers
ask() {
	local srv=${1%%#*} port=53
	case "$1" in *#*) port=${1##*#} ;; esac
	shift
	out=$(dig @"$srv" -p "$port" +time=5 +tries=1 +noall +comments +answer +stats "$@" 2>&1)
	status=$(printf '%s\n' "$out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
	flags=$(printf '%s\n' "$out" | sed -n 's/^;; flags: \([a-z ]*\).*/\1/p' | head -1)
	ms=$(printf '%s\n' "$out" | sed -n 's/^;; Query time: \([0-9]*\) msec.*/\1/p' | head -1)
	answers=$(printf '%s\n' "$out" | grep -cv '^;\|^$')
	[ -n "$status" ] || status=TIMEOUT
	[ -n "$ms" ] || ms=0
}
has_flag() { case " $flags " in *" $1 "*) return 0 ;; esac; return 1; }

echo "Checking $S (reference: $R)"
ask "$S" example.com
if [ "$status" = TIMEOUT ]; then
	echo "No answer from $S. Is the server running, and is the port right (address#port)?" >&2
	exit 1
fi

echo
echo "Popular domains"
domains="google.com youtube.com facebook.com wikipedia.org apple.com microsoft.com
github.com netflix.com yahoo.co.jp naver.com gov.tw bbc.co.uk"
cold=0 warm=0 ref=0 n=0
for d in $domains; do
	ask "$S" "$d"
	s1=$status c=$ms a=$answers
	ask "$S" "$d"
	w=$ms
	ask "$R" "$d"
	rs=$status r=$ms
	n=$((n + 1)) cold=$((cold + c)) warm=$((warm + w)) ref=$((ref + r))
	if [ "$s1" = NOERROR ] && [ "$a" -gt 0 ]; then
		ok "$d  ${c} ms, then ${w} ms (reference ${r} ms)"
	elif [ "$s1" = "$rs" ]; then
		note "$d: $s1, the reference says the same"
	else
		bad "$d: $s1 ($a records), the reference says $rs"
	fi
done
echo "  average: first ask $((cold / n)) ms, from the cache $((warm / n)) ms, reference $((ref / n)) ms"

echo
echo "DNSSEC"
for d in isc.org cloudflare.com internetsociety.org; do
	ask "$S" +dnssec "$d"
	if [ "$status" = NOERROR ] && has_flag ad; then
		ok "$d is signed and the answer is marked validated (AD)"
	elif [ "$status" = NOERROR ]; then
		note "$d answered without AD: DNSSEC is not validated here (fine when forwarding to an upstream that does not pass it on)"
	else
		bad "$d: $status"
	fi
done
ask "$S" +dnssec dnssec-failed.org
if [ "$status" = SERVFAIL ]; then
	ask "$S" +dnssec +cd dnssec-failed.org
	if [ "$status" = NOERROR ]; then
		ok "dnssec-failed.org (deliberately broken) is refused, and answered with checking disabled (CD)"
	else
		ok "dnssec-failed.org (deliberately broken) is refused"
	fi
else
	bad "dnssec-failed.org has a broken signature but was answered: $status"
fi
ask "$S" +dnssec "no-such-name-$RANDOM.isc.org"
if [ "$status" = NXDOMAIN ] && has_flag ad; then
	ok "a name that does not exist is proven so (NXDOMAIN with AD)"
elif [ "$status" = NXDOMAIN ]; then
	note "NXDOMAIN without AD"
else
	bad "a name that does not exist: $status"
fi

echo
echo "Privacy"
ask "$S" +short TXT qnamemintest.internet.nl
if printf '%s' "$out" | grep -q HOORAY; then
	ok "minimal names (RFC 9156): each server only sees the part of the name it needs"
else
	note "minimal names not seen (expected when forwarding: the upstream decides)"
fi

echo
echo "Protocols"
ask "$S" +tcp google.com
[ "$status" = NOERROR ] && ok "TCP" || bad "TCP: $status"
ask "$S" AAAA google.com
[ "$status" = NOERROR ] && [ "$answers" -gt 0 ] && ok "IPv6 addresses (AAAA)" || bad "AAAA google.com: $status"
ask "$S" +dnssec +bufsize=1232 DNSKEY org
[ "$status" = NOERROR ] && ok "large answer (DNSKEY org)" || bad "DNSKEY org: $status"
# Some DNS hosts answer NOERROR for names that do not exist (wildcards,
# "black lies"), so compare with the reference.
nx="no-such-name-$RANDOM.wikipedia.org"
ask "$S" "$nx"
s1=$status
ask "$R" "$nx"
if [ "$s1" = NXDOMAIN ]; then
	ok "NXDOMAIN"
elif [ "$s1" = "$status" ]; then
	note "a name that does not exist: $s1, the reference says the same"
else
	bad "a name that does not exist: $s1, the reference says $status"
fi

echo
printf '%d passed, %d failed, %d notes\n' "$pass" "$fail" "$warn"
[ "$fail" -eq 0 ]
