package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// RFC 7748 §6.1: Alice's private and public X25519 key.
func TestPublicKeyMatchesRFC7748(t *testing.T) {
	priv, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	want, _ := hex.DecodeString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	got, err := publicKey(base64.StdEncoding.EncodeToString(priv))
	if err != nil || got != base64.StdEncoding.EncodeToString(want) {
		t.Fatalf("publicKey = %q, %v", got, err)
	}
}

func TestNewKeyIsClampedAndUsable(t *testing.T) {
	k, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(k)
	if len(raw) != 32 || raw[0]&7 != 0 || raw[31]&128 != 0 || raw[31]&64 == 0 {
		t.Fatalf("key not clamped like wg genkey: %x", raw)
	}
	if _, err := publicKey(k); err != nil {
		t.Fatal(err)
	}
}

const sample = `# Created by the WireGuard tile.
[Interface]
PrivateKey = d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c=
Address = 10.8.0.1/24
ListenPort = 51820

[Peer]
# Name = Laptop
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 10.8.0.2/32

[Peer]
# Name = Phone
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
AllowedIPs = 10.8.0.3/32
Endpoint = 203.0.113.9:4000
`

func TestParseConf(t *testing.T) {
	c := parseConf(sample)
	if c.Address != "10.8.0.1/24" || c.ListenPort != 51820 || len(c.Peers) != 2 {
		t.Fatalf("parsed %+v", c)
	}
	if c.Peers[1].Name != "Phone" || c.Peers[1].Endpoint != "203.0.113.9:4000" || c.Peers[0].AllowedIPs != "10.8.0.2/32" {
		t.Fatalf("peers %+v", c.Peers)
	}
}

func TestRemovePeerKeepsTheRest(t *testing.T) {
	out, ok := removePeer(sample, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if !ok {
		t.Fatal("peer not found")
	}
	c := parseConf(out)
	if len(c.Peers) != 1 || c.Peers[0].Name != "Phone" || c.ListenPort != 51820 || !strings.Contains(out, "# Created by") {
		t.Fatalf("after removal:\n%s", out)
	}
	if _, ok := removePeer(sample, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="); ok {
		t.Fatal("removed a peer that is not there")
	}
}

func TestNextFreeIPSkipsUsedAndEdges(t *testing.T) {
	a, net, err := nextFreeIP(parseConf(sample))
	if err != nil || a.String() != "10.8.0.4" || net.String() != "10.8.0.0/24" {
		t.Fatalf("next = %v %v %v", a, net, err)
	}
	full := Conf{Address: "10.9.0.1/30", Peers: []Peer{{AllowedIPs: "10.9.0.2/32"}}}
	if _, _, err := nextFreeIP(full); err == nil {
		t.Fatal("a /30 with both hosts used has no free address")
	}
}

func TestValidEndpoint(t *testing.T) {
	for _, s := range []string{"vpn.example.org:51820", "203.0.113.5:51820", "[2001:db8::1]:51820"} {
		if !validEndpoint(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", "host", "host:0", "host:70000", "a b:1", "x\nPostUp=rm:1", "h#x:1"} {
		if validEndpoint(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// ---------- handlers ----------

type fakeRun struct {
	mu     sync.Mutex
	cmds   []string
	active map[string]bool
}

func (f *fakeRun) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	if name == "systemctl" && args[0] == "is-active" {
		if f.active[args[1]] {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), nil
	}
	return nil, nil
}

func setup(t *testing.T) *fakeRun {
	t.Helper()
	confDir = t.TempDir()
	unitDir = t.TempDir()
	f := &fakeRun{active: map[string]bool{}}
	run = f.run
	return f
}

func call(t *testing.T, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	w := httptest.NewRecorder()
	api(func(h http.Handler) http.Handler { return h }).ServeHTTP(w, httptest.NewRequest(method, path, &buf))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func TestCreateTunnelWritesA0600Config(t *testing.T) {
	setup(t)
	w, _ := call(t, "POST", "/wireguard/tunnels", map[string]any{"name": "wg0", "address": "10.8.0.1/24", "listen_port": 51820})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	fi, err := os.Stat(filepath.Join(confDir, "wg0.conf"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v, %v", fi, err)
	}
	b, _ := os.ReadFile(filepath.Join(confDir, "wg0.conf"))
	c := parseConf(string(b))
	if c.Address != "10.8.0.1/24" || c.ListenPort != 51820 || !validKey(c.PrivateKey) {
		t.Fatalf("config %+v", c)
	}
	if w, _ := call(t, "POST", "/wireguard/tunnels", map[string]any{"name": "wg0", "address": "10.8.0.1/24", "listen_port": 51820}); w.Code != http.StatusConflict {
		t.Fatalf("second create: %d", w.Code)
	}
}

func TestCreateTunnelRejectsBadInput(t *testing.T) {
	setup(t)
	for _, in := range []map[string]any{
		{"name": "../x", "address": "10.8.0.1/24", "listen_port": 51820},
		{"name": "averyveryverylongname", "address": "10.8.0.1/24", "listen_port": 51820},
		{"name": "wg0", "address": "10.8.0.0/24", "listen_port": 51820}, // network address, not a host
		{"name": "wg0", "address": "fd00::1/64", "listen_port": 51820},
		{"name": "wg0", "address": "10.8.0.1/24", "listen_port": 0},
		{"name": "home", "address": "10.8.0.1/24", "listen_port": 51820}, // ZFW only trusts wg* interfaces
	} {
		if w, _ := call(t, "POST", "/wireguard/tunnels", in); w.Code != http.StatusBadRequest {
			t.Errorf("%v: %d", in, w.Code)
		}
	}
	if files, _ := filepath.Glob(filepath.Join(confDir, "*")); len(files) != 0 {
		t.Fatalf("files written: %v", files)
	}
}

func TestAddClientReturnsAWorkingConfigAndReloads(t *testing.T) {
	f := setup(t)
	call(t, "POST", "/wireguard/tunnels", map[string]any{"name": "wg0", "address": "10.8.0.1/24", "listen_port": 51820})
	f.active["wireguard@wg0.service"] = true
	w, out := call(t, "POST", "/wireguard/peers", map[string]any{"tunnel": "wg0", "name": "Laptop", "endpoint": "vpn.example.org:51820", "dns": "10.8.0.1"})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	cfg := out["client_config"].(string)
	client := parseConf(cfg)
	pub, _ := publicKey(client.PrivateKey)
	if pub != out["public_key"] || client.Address != "10.8.0.2/32" || !strings.Contains(cfg, "DNS = 10.8.0.1") ||
		!strings.Contains(cfg, "Endpoint = vpn.example.org:51820") || !strings.Contains(cfg, "AllowedIPs = 10.8.0.0/24") {
		t.Fatalf("client config:\n%s", cfg)
	}
	b, _ := os.ReadFile(filepath.Join(confDir, "wg0.conf"))
	server := parseConf(string(b))
	if len(server.Peers) != 1 || server.Peers[0].PublicKey != pub || server.Peers[0].Name != "Laptop" || server.Peers[0].AllowedIPs != "10.8.0.2/32" {
		t.Fatalf("server config:\n%s", b)
	}
	if strings.Contains(string(b), client.PrivateKey) {
		t.Fatal("the client's private key was stored on the server")
	}
	serverPub, _ := publicKey(server.PrivateKey)
	if client.Peers[0].PublicKey != serverPub {
		t.Fatal("client config does not name the server's public key")
	}
	if !strings.Contains(strings.Join(f.cmds, "|"), "systemctl reload wireguard@wg0.service") {
		t.Fatalf("running tunnel not reloaded: %v", f.cmds)
	}
	// the next client gets the next address
	_, out = call(t, "POST", "/wireguard/peers", map[string]any{"tunnel": "wg0", "name": "Phone", "endpoint": "vpn.example.org:51820", "full_tunnel": true})
	if out["address"] != "10.8.0.3" || !strings.Contains(out["client_config"].(string), "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Fatalf("second client: %v", out)
	}
}

func TestAddPeerRejectsInjection(t *testing.T) {
	setup(t)
	call(t, "POST", "/wireguard/tunnels", map[string]any{"name": "wg0", "address": "10.8.0.1/24", "listen_port": 51820})
	for _, in := range []map[string]any{
		{"tunnel": "wg0", "name": "x\nPostUp = rm -rf /", "endpoint": "h:1"},
		{"tunnel": "wg0", "name": "ok", "endpoint": "h:1\nPostUp = id"},
		{"tunnel": "wg0", "name": "ok", "public_key": "not-a-key"},
		{"tunnel": "wg0", "name": "ok", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "allowed_ips": "10.8.0.9/32\nPostUp = id"},
		{"tunnel": "wg0", "name": "ok", "endpoint": "h:1", "dns": "1.1.1.1\nPostUp = id"},
	} {
		if w, _ := call(t, "POST", "/wireguard/peers", in); w.Code != http.StatusBadRequest {
			t.Errorf("%q: %d", in, w.Code)
		}
	}
	b, _ := os.ReadFile(filepath.Join(confDir, "wg0.conf"))
	if strings.Contains(string(b), "PostUp") || len(parseConf(string(b)).Peers) != 0 {
		t.Fatalf("config changed:\n%s", b)
	}
}

func TestDeleteTunnelKeepsTheConfigAside(t *testing.T) {
	f := setup(t)
	call(t, "POST", "/wireguard/tunnels", map[string]any{"name": "wg0", "address": "10.8.0.1/24", "listen_port": 51820})
	w, out := call(t, "POST", "/wireguard/tunnels/delete", map[string]any{"name": "wg0"})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if _, err := os.Stat(filepath.Join(confDir, "wg0.conf")); !os.IsNotExist(err) {
		t.Fatal("config still active")
	}
	if fi, err := os.Stat(out["kept_as"].(string)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup %v %v", fi, err)
	}
	if !strings.Contains(strings.Join(f.cmds, "|"), "wireguard-zima disable wg0") {
		t.Fatalf("tunnel not disabled first: %v", f.cmds)
	}
}

func TestListShowsLiveData(t *testing.T) {
	f := setup(t)
	call(t, "POST", "/wireguard/tunnels", map[string]any{"name": "wg0", "address": "10.8.0.1/24", "listen_port": 51820})
	_, out := call(t, "POST", "/wireguard/peers", map[string]any{"tunnel": "wg0", "name": "Laptop", "endpoint": "h:51820"})
	pub := out["public_key"].(string)
	f.active["wireguard@wg0.service"] = true
	must(t, os.WriteFile(filepath.Join(unitDir, "wireguard-wg0-watchdog.timer"), nil, 0o644))
	run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "wg" {
			return []byte("priv\tpub\t51820\toff\n" + pub + "\t(none)\t198.51.100.7:40000\t10.8.0.2/32\t1792740000\t1024\t2048\t25\n"), nil
		}
		return f.run(ctx, name, args...)
	}
	_, out = call(t, "GET", "/wireguard/tunnels", nil)
	tun := out["tunnels"].([]any)[0].(map[string]any)
	p := tun["peers"].([]any)[0].(map[string]any)
	if tun["active"] != "active" || tun["boot"] != true || p["live_endpoint"] != "198.51.100.7:40000" || p["latest_handshake"] != float64(1792740000) || p["rx_bytes"] != float64(1024) {
		t.Fatalf("tunnel %v", tun)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
