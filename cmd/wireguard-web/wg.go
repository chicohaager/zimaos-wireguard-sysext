package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ---------- keys ----------

// newKey returns a WireGuard private key (Curve25519, clamped as `wg genkey` does).
func newKey() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// publicKey derives the public key from a base64 private key (`wg pubkey`).
func publicKey(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid private key")
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// validKey reports whether s is a base64 WireGuard key.
func validKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

// ---------- names ----------

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

// validName: a wg-quick config's file name is the interface name (at most 15
// characters, the same set wireguard-zima accepts).
func validName(n string) bool { return nameRe.MatchString(n) && n != "." && n != ".." }

// peerNameRe keeps peer names to one safe line inside the config file.
var peerNameRe = regexp.MustCompile(`^[\p{L}\p{N} _.@()+-]{1,40}$`)

// ---------- config files ----------

// Peer is one [Peer] section of a wg-quick config.
type Peer struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	AllowedIPs string `json:"allowed_ips"`
	Endpoint   string `json:"endpoint,omitempty"`
}

// Conf is what the tile needs from a wg-quick config.
type Conf struct {
	PrivateKey string
	Address    string
	ListenPort int
	NAT        bool // the tile's NAT lines (natLines) are in [Interface]
	Peers      []Peer
}

// parseConf reads the keys the tile shows; everything else stays untouched in
// the file. A peer's name is a "# Name = …" line inside its section.
func parseConf(text string) Conf {
	var c Conf
	var cur *Peer
	section := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case strings.EqualFold(l, "[Interface]"):
			section, cur = "interface", nil
			continue
		case strings.EqualFold(l, "[Peer]"):
			c.Peers = append(c.Peers, Peer{})
			cur = &c.Peers[len(c.Peers)-1]
			section = "peer"
			continue
		}
		if strings.HasPrefix(l, "#") {
			if cur != nil {
				if k, v, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(l, "#")), "="); ok && strings.EqualFold(strings.TrimSpace(k), "Name") {
					cur.Name = strings.TrimSpace(v)
				}
			}
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case section == "interface" && strings.EqualFold(k, "PrivateKey"):
			c.PrivateKey = v
		case section == "interface" && strings.EqualFold(k, "Address"):
			c.Address = v
		case section == "interface" && strings.EqualFold(k, "ListenPort"):
			c.ListenPort, _ = strconv.Atoi(v)
		case section == "interface" && l == natLines[1]:
			c.NAT = true
		case section == "peer" && strings.EqualFold(k, "PublicKey"):
			cur.PublicKey = v
		case section == "peer" && strings.EqualFold(k, "AllowedIPs"):
			cur.AllowedIPs = v
		case section == "peer" && strings.EqualFold(k, "Endpoint"):
			cur.Endpoint = v
		}
	}
	return c
}

// ---------- NAT for clients ----------

// natScript sets MASQUERADE and FORWARD rules for a tunnel's clients (files/usr/libexec/wireguard/nat.sh).
const natScript = "/usr/libexec/wireguard/nat.sh"

// natLines are what the tile writes into [Interface] so clients reach the internet and the LAN
// through this host (wg-easy and PiVPN write the same kind of PostUp/PostDown rules). Without
// them a client's packets leave with its tunnel address and the router has no way back.
var natLines = []string{
	"# NAT for clients (WireGuard tile): they reach the internet and the LAN through this host",
	"PostUp = /bin/sh " + natScript + " up %i",
	"PostDown = /bin/sh " + natScript + " down %i",
}

func isNATLine(l string) bool {
	l = strings.TrimSpace(l)
	for _, n := range natLines {
		if l == n {
			return true
		}
	}
	return false
}

// setNAT returns text with the tile's NAT lines at the end of the [Interface] section (on) or
// without them (off). Other lines, also PostUp lines of one's own, stay as they are.
func setNAT(text string, on bool) (string, error) {
	var kept []string
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if !isNATLine(l) {
			kept = append(kept, l)
		}
	}
	if on {
		start, end := -1, len(kept)
		for i, l := range kept {
			t := strings.TrimSpace(l)
			if start < 0 && strings.EqualFold(t, "[Interface]") {
				start = i
			} else if start >= 0 && strings.HasPrefix(t, "[") {
				end = i
				break
			}
		}
		if start < 0 {
			return "", errors.New("the config has no [Interface] section")
		}
		at := end
		for at > start+1 && strings.TrimSpace(kept[at-1]) == "" {
			at--
		}
		out := append([]string{}, kept[:at]...)
		out = append(out, natLines...)
		kept = append(out, kept[at:]...)
	}
	return strings.Join(kept, "\n") + "\n", nil
}

// removePeer drops the [Peer] section with the given public key. It returns
// false when no section matched.
func removePeer(text, pub string) (string, bool) {
	lines := strings.SplitAfter(text, "\n")
	type block struct{ start, end int }
	var blocks []block
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			if len(blocks) > 0 && blocks[len(blocks)-1].end < 0 {
				blocks[len(blocks)-1].end = i
			}
			if strings.EqualFold(t, "[Peer]") {
				blocks = append(blocks, block{i, -1})
			}
		}
	}
	if len(blocks) > 0 && blocks[len(blocks)-1].end < 0 {
		blocks[len(blocks)-1].end = len(lines)
	}
	for _, b := range blocks {
		p := parseConf("[Peer]\n" + strings.Join(lines[b.start+1:b.end], ""))
		if len(p.Peers) == 1 && p.Peers[0].PublicKey == pub {
			out := strings.Join(lines[:b.start], "") + strings.Join(lines[b.end:], "")
			return strings.TrimRight(out, "\n") + "\n", true
		}
	}
	return text, false
}

// nextFreeIP returns the first host address in the interface's network that
// neither the interface nor a peer uses.
func nextFreeIP(c Conf) (netip.Addr, netip.Prefix, error) {
	var ifPrefix netip.Prefix
	used := map[netip.Addr]bool{}
	for _, a := range strings.Split(c.Address, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil || !p.Addr().Is4() {
			continue
		}
		if !ifPrefix.IsValid() {
			ifPrefix = p
		}
		used[p.Addr()] = true
	}
	if !ifPrefix.IsValid() {
		return netip.Addr{}, netip.Prefix{}, errors.New("the tunnel has no IPv4 Address to take client addresses from")
	}
	for _, p := range c.Peers {
		for _, a := range strings.Split(p.AllowedIPs, ",") {
			if q, err := netip.ParsePrefix(strings.TrimSpace(a)); err == nil {
				used[q.Addr()] = true
			}
		}
	}
	net := ifPrefix.Masked()
	broadcast := lastAddr(net)
	for a := net.Addr().Next(); net.Contains(a) && a != broadcast; a = a.Next() {
		if !used[a] {
			return a, net, nil
		}
	}
	return netip.Addr{}, netip.Prefix{}, fmt.Errorf("no free address left in %s", net)
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	bits := p.Bits()
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 1 << (7 - j)
			}
		}
	}
	return netip.AddrFrom4(b)
}

// writeFile replaces path atomically with mode 0600 (configs hold private keys).
func writeFile(path, text string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
