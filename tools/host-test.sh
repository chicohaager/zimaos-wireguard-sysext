#!/bin/sh
# Run on a ZimaOS host as root after `zpkg install /tmp/wireguard.raw`.
# Builds a real tunnel: the peer lives in its own network namespace behind a veth pair,
# so the packets cross the WireGuard interface and need a handshake.
#   sudo sh host-test.sh          set up, test, leave the tunnel running (for a reboot test)
#   sudo sh host-test.sh cleanup  remove everything this test created
# Test names: interface wgt0, namespaces wgtpeer and wgtout, veth vwgt0/vwgt1 and vwgt2/vwgt3,
# 10.231.0.0/30, 10.232.0.0/24 and 10.233.0.0/30.
set -u
D=/DATA/AppData/wireguard; N=wgt0; NS=wgtpeer
# pass/fail and the cleanup after a failure or abort: lintux-modkit tools/hosttest-lib.sh, copied next to this file
. "$(dirname "$0")/hosttest-lib.sh"
HT_LIST=/etc/lintux-hosttest/wireguard.list

# TCP probe with python3 (ZimaOS' ping is a BusyBox applet that exits 1 without output, even
# for --help, measured 1.8.0). The host answers "pong"; the client connects from the namespace.
probe() { # <ns> <ip> <port> [<listener ns>] -> 0 when "pong" came back
  ${4:+ip netns exec "$4"} python3 -c 'import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(1); s.settimeout(8)
try:
    c,_=s.accept(); c.sendall(b"pong\n")
except OSError: pass' "$3" &
  lp=$!; sleep 0.5
  r=$(ip netns exec "$1" python3 -c 'import socket,sys
try:
    c=socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3); print(c.recv(10).decode().strip())
except OSError as e: print("no:", e)' "$2" "$3")
  kill "$lp" 2>/dev/null; wait "$lp" 2>/dev/null
  [ "$r" = pong ]
}
# ZFW (if installed) drops what it does not know: open the test paths for the duration of the test,
# marked with a comment so cleanup removes exactly these. zfw.service restores its own rules at boot.
zfw_open() { iptables -S ZFW-IN >/dev/null 2>&1 || return 0
  for spec in "$@"; do eval "iptables -I ZFW-IN 1 $spec -m comment --comment module-host-test -j ACCEPT"; done; }
zfw_close() { iptables -S ZFW-IN 2>/dev/null | grep -- '--comment module-host-test' | sed 's/^-A /-D /' | while read -r r; do eval "iptables $r"; done; }

wireguard_cleanup() {
  zfw_close
  wireguard-zima disable "$N"
  ip netns del "$NS" 2>/dev/null; ip link del vwgt0 2>/dev/null
  ip netns del wgtout 2>/dev/null; ip link del vwgt2 2>/dev/null
  echo "cleanup: $(sh /usr/libexec/wireguard/nat.sh status "$N") NAT rules left for $N"
  rm -f "$D/$N.conf" "$D/.wgtpeer.key"
  rmdir "$D" 2>/dev/null
  echo "cleanup done: $(ip -o link show | grep -c 'wgt0\|vwgt0') test interfaces left"
}
if [ "${1:-}" = cleanup ]; then
  wireguard_cleanup
  rm -f "$HT_LIST"
  exit 0
fi

echo "zfw: $(systemctl is-active zfw.service 2>/dev/null || true), chain ZFW-IN: $(iptables -S ZFW-IN >/dev/null 2>&1 && echo present || echo absent)"
for b in wg wg-quick wireguard-zima /bin/bash ip; do command -v "$b" >/dev/null || fail "missing $b"; done

ht_init "$HT_LIST"; ht_made call wireguard_cleanup   # from here on a failure or abort runs wireguard_cleanup
umask 077; mkdir -p "$D"
HPRIV=$(wg genkey); HPUB=$(printf '%s' "$HPRIV" | wg pubkey)
PPRIV=$(wg genkey); PPUB=$(printf '%s' "$PPRIV" | wg pubkey)
printf '%s\n' "$PPRIV" > "$D/.wgtpeer.key"
cat > "$D/$N.conf" <<EOF
[Interface]
PrivateKey = $HPRIV
Address = 10.232.0.1/24
ListenPort = 51831
# NAT for clients (WireGuard tile): they reach the internet and the LAN through this host
PostUp = /bin/sh /usr/libexec/wireguard/nat.sh up %i
PostDown = /bin/sh /usr/libexec/wireguard/nat.sh down %i

[Peer]
PublicKey = $PPUB
AllowedIPs = 10.232.0.2/32
EOF

ip netns add "$NS"
ip link add vwgt0 type veth peer name vwgt1
ip link set vwgt1 netns "$NS"
ip addr add 10.231.0.1/30 dev vwgt0; ip link set vwgt0 up
ip -n "$NS" addr add 10.231.0.2/30 dev vwgt1; ip -n "$NS" link set vwgt1 up; ip -n "$NS" link set lo up
ip -n "$NS" link add wgp type wireguard
ip netns exec "$NS" wg set wgp private-key "$D/.wgtpeer.key" listen-port 51832 \
  peer "$HPUB" endpoint 10.231.0.1:51831 allowed-ips 10.232.0.1/32,10.233.0.0/30 persistent-keepalive 1
ip -n "$NS" addr add 10.232.0.2/24 dev wgp; ip -n "$NS" link set wgp up
ip -n "$NS" route add 10.233.0.0/30 dev wgp
# "Outside" (a stand-in for the internet): its own namespace behind a second veth pair, with no
# route back to the tunnel's 10.232.0.0/24, so only NAT on the host brings an answer back.
ip netns add wgtout
ip link add vwgt2 type veth peer name vwgt3
ip link set vwgt3 netns wgtout
ip addr add 10.233.0.1/30 dev vwgt2; ip link set vwgt2 up
ip -n wgtout addr add 10.233.0.2/30 dev vwgt3; ip -n wgtout link set vwgt3 up; ip -n wgtout link set lo up

zfw_open "-i vwgt0 -p udp --dport 51831" "-i wgt0 -p tcp --dport 7831"
# Negative control: without the host side the tunnel must not answer.
if probe "$NS" 10.232.0.1 7831; then fail "answer before the tunnel was up"; else pass "no answer before enable"; fi

if wireguard-zima enable "$N"; then pass "wireguard-zima enable $N"; else fail "wireguard-zima enable $N"; fi
[ "$(systemctl is-active "wireguard@$N.service")" = active ] && pass "wireguard@$N active" || fail "wireguard@$N: $(systemctl is-active "wireguard@$N.service")"
[ -f /etc/systemd/system/wireguard-$N-watchdog.timer ] && [ "$(systemctl is-enabled wireguard-$N-watchdog.timer)" = enabled ] \
  && pass "watchdog timer enabled" || fail "watchdog timer missing or not enabled"
# The peer's first handshake went out before wgt0 existed; its next attempt came 3.6-4.1 s after
# enable (6 runs on the second test NAS, 2026-10-26), longer than one probe waits (0.5 s + 3 s): wait for the
# handshake (up to 15 s), then probe up to three times, as the Nebula test does.
for _ in $(seq 1 30); do [ "$(wg show "$N" latest-handshakes | awk '{print $2}')" -gt 0 ] 2>/dev/null && break; sleep 0.5; done
ok_tcp=0; for _ in 1 2 3; do probe "$NS" 10.232.0.1 7831 && { ok_tcp=1; break; }; sleep 1; done
[ "$ok_tcp" = 1 ] && pass "TCP through the tunnel" || fail "no TCP through the tunnel"
hs=$(wg show "$N" latest-handshakes | awk '{print $2}')
[ "${hs:-0}" -gt 0 ] && pass "handshake at $hs" || fail "no handshake"
# NAT for clients (forum report 2026-11-23: clients connected, no internet). PostUp set the rules.
outside() { for _ in 1 2 3; do probe "$NS" 10.233.0.2 7832 wgtout && return 0; sleep 1; done; return 1; }
nr=$(sh /usr/libexec/wireguard/nat.sh status "$N"); [ "$nr" = 3 ] && pass "PostUp set 3 NAT rules" || fail "NAT rules after enable: $nr"
outside && pass "client reaches an address behind the host (NAT)" || fail "client does not reach the address behind the host"
sh /usr/libexec/wireguard/nat.sh down "$N"
# Negative control: without NAT the outside cannot answer (no route back to the tunnel).
if outside; then fail "answer from behind the host without NAT: the test does not test NAT"; else pass "no answer from behind the host without NAT"; fi
sh /usr/libexec/wireguard/nat.sh up "$N"
outside && pass "NAT on again: client reaches the address behind the host" || fail "NAT on again: no answer"
perm=$(stat -c %a "$D/$N.conf"); [ "$perm" = 600 ] && pass "config mode 600" || fail "config mode $perm"
if systemctl reload "wireguard@$N.service"; then pass "reload (wg syncconf)"; else fail "reload"; fi
# A restart runs PostDown then PostUp: the rules are there once, not twice.
systemctl restart "wireguard@$N.service"
nr=$(sh /usr/libexec/wireguard/nat.sh status "$N"); [ "$nr" = 3 ] && pass "after restart 3 NAT rules" || fail "NAT rules after restart: $nr"
wireguard-zima status "$N" | head -n 1
echo "wireguard host-test: $ok OK, $bad FAIL"
ht_done
