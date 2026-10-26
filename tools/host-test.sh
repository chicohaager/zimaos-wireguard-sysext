#!/bin/sh
# Run on a ZimaOS host as root after `zpkg install /tmp/wireguard.raw`.
# Builds a real tunnel: the peer lives in its own network namespace behind a veth pair,
# so the packets cross the WireGuard interface and need a handshake.
#   sudo sh host-test.sh          set up, test, leave the tunnel running (for a reboot test)
#   sudo sh host-test.sh cleanup  remove everything this test created
# Test names: interface wgt0, namespace wgtpeer, veth vwgt0/vwgt1, 10.231.0.0/30 and 10.232.0.0/24.
set -u
D=/DATA/AppData/wireguard; N=wgt0; NS=wgtpeer
ok=0; bad=0
pass() { ok=$((ok + 1)); echo "OK   $1"; }
fail() { bad=$((bad + 1)); echo "FAIL $1"; }

# TCP probe with python3 (ZimaOS' ping is a BusyBox applet that exits 1 without output, even
# for --help, measured 1.8.0). The host answers "pong"; the client connects from the namespace.
probe() { # <ns> <ip> <port> -> 0 when "pong" came back
  python3 -c 'import socket,sys
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

if [ "${1:-}" = cleanup ]; then
  zfw_close
  wireguard-zima disable "$N"
  ip netns del "$NS" 2>/dev/null; ip link del vwgt0 2>/dev/null
  rm -f "$D/$N.conf" "$D/.wgtpeer.key"
  rmdir "$D" 2>/dev/null
  echo "cleanup done: $(ip -o link show | grep -c 'wgt0\|vwgt0') test interfaces left"
  exit 0
fi

echo "zfw: $(systemctl is-active zfw.service 2>/dev/null || true), chain ZFW-IN: $(iptables -S ZFW-IN >/dev/null 2>&1 && echo present || echo absent)"
for b in wg wg-quick wireguard-zima /bin/bash ip; do command -v "$b" >/dev/null || fail "missing $b"; done

umask 077; mkdir -p "$D"
HPRIV=$(wg genkey); HPUB=$(printf '%s' "$HPRIV" | wg pubkey)
PPRIV=$(wg genkey); PPUB=$(printf '%s' "$PPRIV" | wg pubkey)
printf '%s\n' "$PPRIV" > "$D/.wgtpeer.key"
cat > "$D/$N.conf" <<EOF
[Interface]
PrivateKey = $HPRIV
Address = 10.232.0.1/24
ListenPort = 51831

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
  peer "$HPUB" endpoint 10.231.0.1:51831 allowed-ips 10.232.0.1/32 persistent-keepalive 1
ip -n "$NS" addr add 10.232.0.2/24 dev wgp; ip -n "$NS" link set wgp up

zfw_open "-i vwgt0 -p udp --dport 51831" "-i wgt0 -p tcp --dport 7831"
# Negative control: without the host side the tunnel must not answer.
if probe "$NS" 10.232.0.1 7831; then fail "answer before the tunnel was up"; else pass "no answer before enable"; fi

if wireguard-zima enable "$N"; then pass "wireguard-zima enable $N"; else fail "wireguard-zima enable $N"; fi
[ "$(systemctl is-active "wireguard@$N.service")" = active ] && pass "wireguard@$N active" || fail "wireguard@$N: $(systemctl is-active "wireguard@$N.service")"
[ -f /etc/systemd/system/wireguard-$N-watchdog.timer ] && [ "$(systemctl is-enabled wireguard-$N-watchdog.timer)" = enabled ] \
  && pass "watchdog timer enabled" || fail "watchdog timer missing or not enabled"
# The peer's first handshake went out before wgt0 existed; its next attempt came 3.6-4.1 s after
# enable (6 runs on .184, 2026-10-26), longer than one probe waits (0.5 s + 3 s): wait for the
# handshake (up to 15 s), then probe up to three times, as the Nebula test does.
for _ in $(seq 1 30); do [ "$(wg show "$N" latest-handshakes | awk '{print $2}')" -gt 0 ] 2>/dev/null && break; sleep 0.5; done
ok_tcp=0; for _ in 1 2 3; do probe "$NS" 10.232.0.1 7831 && { ok_tcp=1; break; }; sleep 1; done
[ "$ok_tcp" = 1 ] && pass "TCP through the tunnel" || fail "no TCP through the tunnel"
hs=$(wg show "$N" latest-handshakes | awk '{print $2}')
[ "${hs:-0}" -gt 0 ] && pass "handshake at $hs" || fail "no handshake"
perm=$(stat -c %a "$D/$N.conf"); [ "$perm" = 600 ] && pass "config mode 600" || fail "config mode $perm"
if systemctl reload "wireguard@$N.service"; then pass "reload (wg syncconf)"; else fail "reload"; fi
wireguard-zima status "$N" | head -n 1
echo "wireguard host-test: $ok OK, $bad FAIL"
[ "$bad" -eq 0 ]
