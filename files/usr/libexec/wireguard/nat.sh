#!/bin/sh
# NAT for the clients of a WireGuard tunnel: lets them reach the internet and the LAN through
# this host, as wg-easy and PiVPN do. Without it a client's packets leave the host with its
# tunnel address as the source, and the router has no route back (forum report, 2026-11-23).
# Called from the lines the tile writes into a server config:
#   PostUp = /bin/sh /usr/libexec/wireguard/nat.sh up %i
#   PostDown = /bin/sh /usr/libexec/wireguard/nat.sh down %i
#   nat.sh status <iface>   prints the number of rules this script set for <iface>
# IPv4 only (the tile gives clients IPv4 addresses). Every rule carries the comment
# wgzima-nat-<iface>; "down" removes exactly those, so it also works after wg-quick has
# deleted the interface (PostDown runs after that).
set -eu
act=${1:-}; dev=${2:-}
case "$dev" in ''|*[!A-Za-z0-9_=+.-]*) echo "nat.sh: usage: nat.sh up|down|status <interface>" >&2; exit 2 ;; esac
tag="wgzima-nat-$dev"

# Docker's backend, as ZFW picks it: on ZimaOS 1.8 iptables-nft holds Docker's FORWARD jumps,
# iptables-legacy has tables too (measured 2026-11-23).
IPT=
for c in iptables-nft iptables-legacy; do
	command -v "$c" >/dev/null 2>&1 || continue
	if "$c" -S FORWARD 2>/dev/null | grep -qE 'DOCKER-USER|DOCKER-FORWARD'; then IPT=$(command -v "$c"); break; fi
done
[ -n "$IPT" ] || IPT=$(command -v iptables) || { echo "nat.sh: no iptables" >&2; exit 1; }

# our rules as "-A ..." lines, table by table
ours() { "$IPT" -w -t "$1" -S 2>/dev/null | grep -F -- "--comment $tag " || true; }

remove() {
	for t in filter nat; do
		ours "$t" | while read -r rule; do
			# shellcheck disable=SC2086 # the rule is iptables' own -S output, no quotes inside (tag has no spaces)
			set -- $rule; shift; "$IPT" -w -t "$t" -D "$@"
		done
	done
}

count() { echo $(( $(ours filter | grep -c . || true) + $(ours nat | grep -c . || true) )); }

case "$act" in
up)
	remove
	nets=$(ip -4 -o route show dev "$dev" proto kernel scope link | awk '{print $1}')
	[ -n "$nets" ] || { echo "nat.sh: $dev has no IPv4 address" >&2; exit 1; }
	echo 1 > /proc/sys/net/ipv4/ip_forward
	"$IPT" -w -I FORWARD 1 -o "$dev" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$tag" -j ACCEPT
	"$IPT" -w -I FORWARD 1 -i "$dev" -m comment --comment "$tag" -j ACCEPT
	for n in $nets; do
		"$IPT" -w -t nat -I POSTROUTING 1 -s "$n" ! -o "$dev" -m comment --comment "$tag" -j MASQUERADE
	done
	echo "nat.sh: $dev: NAT for $(printf '%s' "$nets" | tr '\n' ' ') on ($(basename "$IPT"), $(count) rules)"
	;;
down)
	remove
	echo "nat.sh: $dev: NAT off ($(count) rules left)"
	;;
status) count ;;
*) echo "nat.sh: usage: nat.sh up|down|status <interface>" >&2; exit 2 ;;
esac
