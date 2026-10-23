// Command wireguard-web serves the WireGuard tile: tunnels in
// /DATA/AppData/wireguard/<name>.conf, their live state (`wg show <name> dump`),
// clients with a generated config, and switching a tunnel on, off and on at boot
// (wireguard-zima). The ZFW rule for a listen port is set by the page itself.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chicohaager/lintux-modkit/httpx"
	"github.com/chicohaager/lintux-modkit/webmod"
)

// version is set at build time from VERSION (-ldflags -X main.version=...).
var version = "dev"

// Paths and commands; tests point them elsewhere.
var (
	confDir = "/DATA/AppData/wireguard"
	unitDir = "/etc/systemd/system"
	run     = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
)

// mu serialises every change to the config files.
var mu sync.Mutex

func main() {
	webmod.Run(webmod.Options{
		Name: "wireguard", Service: "wireguard-web", Binary: "/usr/bin/wireguard-web",
		Route: "/wireguard", Version: version, API: api,
	})
}

func api(verify func(http.Handler) http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/wireguard/tunnels", verify(http.HandlerFunc(tunnelsHandler)))
	mux.Handle("/wireguard/tunnels/delete", verify(post(deleteTunnel)))
	mux.Handle("/wireguard/tunnels/action", verify(post(tunnelAction)))
	mux.Handle("/wireguard/peers", verify(post(addPeer)))
	mux.Handle("/wireguard/peers/delete", verify(post(deletePeer)))
	return mux
}

func post(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httpx.MethodNotAllowed(w)
			return
		}
		h(w, r)
	})
}

func ctxShort(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 60*time.Second)
}

func confPath(name string) string { return filepath.Join(confDir, name+".conf") }

// ---------- list ----------

// LivePeer is a peer as the tile shows it: config plus `wg show` data.
type LivePeer struct {
	Peer
	LiveEndpoint    string `json:"live_endpoint,omitempty"`
	LatestHandshake int64  `json:"latest_handshake"`
	RxBytes         int64  `json:"rx_bytes"`
	TxBytes         int64  `json:"tx_bytes"`
}

// Tunnel is one config file.
type Tunnel struct {
	Name       string     `json:"name"`
	Address    string     `json:"address"`
	ListenPort int        `json:"listen_port"`
	PublicKey  string     `json:"public_key"`
	Active     string     `json:"active"`
	Boot       bool       `json:"boot"`
	Peers      []LivePeer `json:"peers"`
	Error      string     `json:"error,omitempty"`
}

func tunnelsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		listTunnels(w, r)
	case http.MethodPost:
		createTunnel(w, r)
	default:
		httpx.MethodNotAllowed(w)
	}
}

func listTunnels(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxShort(r)
	defer cancel()
	files, _ := filepath.Glob(filepath.Join(confDir, "*.conf"))
	sort.Strings(files)
	out := []Tunnel{}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".conf")
		if !validName(name) {
			continue
		}
		out = append(out, readTunnel(ctx, name))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tunnels": out, "conf_dir": confDir})
}

func readTunnel(ctx context.Context, name string) Tunnel {
	t := Tunnel{Name: name, Peers: []LivePeer{}}
	b, err := os.ReadFile(confPath(name))
	if err != nil {
		t.Error = err.Error()
		return t
	}
	c := parseConf(string(b))
	t.Address, t.ListenPort = c.Address, c.ListenPort
	if pub, err := publicKey(c.PrivateKey); err == nil {
		t.PublicKey = pub
	} else {
		t.Error = "PrivateKey: " + err.Error()
	}
	a, _ := run(ctx, "systemctl", "is-active", "wireguard@"+name+".service")
	t.Active = strings.TrimSpace(string(a))
	_, err = os.Stat(filepath.Join(unitDir, "wireguard-"+name+"-watchdog.timer"))
	t.Boot = err == nil
	live := map[string]LivePeer{}
	if t.Active == "active" {
		if dump, err := run(ctx, "wg", "show", name, "dump"); err == nil {
			for i, l := range strings.Split(strings.TrimSpace(string(dump)), "\n") {
				f := strings.Split(l, "\t")
				if i == 0 || len(f) < 8 {
					continue // the first line is the interface itself
				}
				hs, _ := strconv.ParseInt(f[4], 10, 64)
				rx, _ := strconv.ParseInt(f[5], 10, 64)
				tx, _ := strconv.ParseInt(f[6], 10, 64)
				ep := f[2]
				if ep == "(none)" {
					ep = ""
				}
				live[f[0]] = LivePeer{LiveEndpoint: ep, LatestHandshake: hs, RxBytes: rx, TxBytes: tx}
			}
		}
	}
	for _, p := range c.Peers {
		lp := live[p.PublicKey]
		lp.Peer = p
		t.Peers = append(t.Peers, lp)
	}
	return t
}

// ---------- tunnels ----------

func createTunnel(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name       string `json:"name"`
		Address    string `json:"address"`
		ListenPort int    `json:"listen_port"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if !validName(in.Name) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_name", "name: 1–15 characters, letters, digits and _=+.- (it becomes the interface name)")
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(in.Address))
	if err != nil || !p.Addr().Is4() || p.Bits() < 8 || p.Bits() > 30 || p.Addr() == p.Masked().Addr() {
		httpx.WriteError(w, http.StatusBadRequest, "bad_address", "address: this host's IPv4 address in the tunnel with its prefix, e.g. 10.8.0.1/24")
		return
	}
	if in.ListenPort < 1 || in.ListenPort > 65535 {
		httpx.WriteError(w, http.StatusBadRequest, "bad_port", "listen port: 1–65535 (51820 is WireGuard's usual one)")
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if _, err := os.Stat(confPath(in.Name)); err == nil {
		httpx.WriteError(w, http.StatusConflict, "exists", "a tunnel named "+in.Name+" exists already")
		return
	}
	priv, err := newKey()
	if err != nil {
		httpx.WriteErr(w, err)
		return
	}
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		httpx.WriteErr(w, err)
		return
	}
	text := fmt.Sprintf("# Created by the WireGuard tile.\n[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n", priv, p, in.ListenPort)
	if err := writeFile(confPath(in.Name), text); err != nil {
		httpx.WriteErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "created", "name": in.Name})
}

func deleteTunnel(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if !validName(in.Name) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_name", "invalid tunnel name")
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if _, err := os.Stat(confPath(in.Name)); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "unknown", "no tunnel named "+in.Name)
		return
	}
	ctx, cancel := ctxShort(r)
	defer cancel()
	if out, err := run(ctx, "wireguard-zima", "disable", in.Name); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "disable_failed", strings.TrimSpace(string(out)))
		return
	}
	// The config holds the tunnel's private key: it is moved aside, not deleted.
	bak := filepath.Join(confDir, ".deleted")
	if err := os.MkdirAll(bak, 0o700); err != nil {
		httpx.WriteErr(w, err)
		return
	}
	dst := filepath.Join(bak, in.Name+"-"+time.Now().UTC().Format("20060102T150405Z")+".conf")
	if err := os.Rename(confPath(in.Name), dst); err != nil {
		httpx.WriteErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted", "kept_as": dst})
}

func tunnelAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if !validName(in.Name) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_name", "invalid tunnel name")
		return
	}
	if _, err := os.Stat(confPath(in.Name)); err != nil {
		httpx.WriteError(w, http.StatusNotFound, "unknown", "no tunnel named "+in.Name)
		return
	}
	var cmd []string
	switch in.Action {
	case "enable": // start now and at every boot
		cmd = []string{"wireguard-zima", "enable", in.Name}
	case "disable": // stop, not at boot
		cmd = []string{"wireguard-zima", "disable", in.Name}
	case "restart":
		cmd = []string{"systemctl", "restart", "wireguard@" + in.Name + ".service"}
	default:
		httpx.WriteError(w, http.StatusBadRequest, "bad_action", "action: enable, disable or restart")
		return
	}
	mu.Lock()
	defer mu.Unlock()
	ctx, cancel := ctxShort(r)
	defer cancel()
	if out, err := run(ctx, cmd[0], cmd[1:]...); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "failed", strings.TrimSpace(string(out)))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- peers ----------

// reloadIfActive applies a changed peer list to a running tunnel without dropping it.
func reloadIfActive(ctx context.Context, name string) error {
	a, _ := run(ctx, "systemctl", "is-active", "wireguard@"+name+".service")
	if strings.TrimSpace(string(a)) != "active" {
		return nil
	}
	if out, err := run(ctx, "systemctl", "reload", "wireguard@"+name+".service"); err != nil {
		return fmt.Errorf("reload: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func addPeer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tunnel    string `json:"tunnel"`
		Name      string `json:"name"`
		PublicKey string `json:"public_key"` // empty: generate a client and return its config
		AllowedIP string `json:"allowed_ips"`
		Endpoint  string `json:"endpoint"`    // this server as the client reaches it, host:port
		DNS       string `json:"dns"`         // optional, for the client config
		FullRoute bool   `json:"full_tunnel"` // client sends all traffic through the tunnel
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if !validName(in.Tunnel) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_name", "invalid tunnel name")
		return
	}
	if !peerNameRe.MatchString(in.Name) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_peer_name", "name: 1–40 letters, digits, spaces and _.@()+-")
		return
	}
	if in.PublicKey != "" && !validKey(in.PublicKey) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_key", "public key: 44 characters of base64, as `wg pubkey` prints it")
		return
	}
	if in.DNS != "" {
		if _, err := netip.ParseAddr(in.DNS); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "bad_dns", "DNS: one IP address, or empty")
			return
		}
	}
	mu.Lock()
	defer mu.Unlock()
	b, err := os.ReadFile(confPath(in.Tunnel))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "unknown", "no tunnel named "+in.Tunnel)
		return
	}
	c := parseConf(string(b))
	serverPub, err := publicKey(c.PrivateKey)
	if err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "bad_conf", "the tunnel's PrivateKey is unreadable")
		return
	}
	for _, p := range c.Peers {
		if in.PublicKey != "" && p.PublicKey == in.PublicKey {
			httpx.WriteError(w, http.StatusConflict, "exists", "this public key is a peer already")
			return
		}
	}

	var clientPriv, allowed string
	var addr netip.Addr
	var subnet netip.Prefix
	if in.PublicKey == "" {
		if in.Endpoint == "" || !validEndpoint(in.Endpoint) {
			httpx.WriteError(w, http.StatusBadRequest, "bad_endpoint", "endpoint: how the client reaches this server, host:port (public address or DynDNS name, and the forwarded port)")
			return
		}
		addr, subnet, err = nextFreeIP(c)
		if err != nil {
			httpx.WriteError(w, http.StatusConflict, "no_address", err.Error())
			return
		}
		if clientPriv, err = newKey(); err != nil {
			httpx.WriteErr(w, err)
			return
		}
		if in.PublicKey, err = publicKey(clientPriv); err != nil {
			httpx.WriteErr(w, err)
			return
		}
		allowed = addr.String() + "/32"
	} else {
		allowed = strings.TrimSpace(in.AllowedIP)
		for _, a := range strings.Split(allowed, ",") {
			if _, err := netip.ParsePrefix(strings.TrimSpace(a)); err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "bad_allowed_ips", "allowed IPs: comma-separated prefixes, e.g. 10.8.0.5/32")
				return
			}
		}
	}

	block := fmt.Sprintf("\n[Peer]\n# Name = %s\nPublicKey = %s\nAllowedIPs = %s\n", in.Name, in.PublicKey, allowed)
	if err := writeFile(confPath(in.Tunnel), strings.TrimRight(string(b), "\n")+"\n"+block); err != nil {
		httpx.WriteErr(w, err)
		return
	}
	ctx, cancel := ctxShort(r)
	defer cancel()
	reloadErr := reloadIfActive(ctx, in.Tunnel)

	resp := map[string]any{"status": "added", "public_key": in.PublicKey}
	if reloadErr != nil {
		resp["warning"] = reloadErr.Error()
	}
	if clientPriv != "" {
		routes := subnet.String()
		if in.FullRoute {
			routes = "0.0.0.0/0, ::/0"
		}
		cfg := fmt.Sprintf("# %s — WireGuard client for tunnel %s\n[Interface]\nPrivateKey = %s\nAddress = %s/32\n", in.Name, in.Tunnel, clientPriv, addr)
		if in.DNS != "" {
			cfg += "DNS = " + in.DNS + "\n"
		}
		cfg += fmt.Sprintf("\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", serverPub, in.Endpoint, routes)
		resp["client_config"] = cfg
		resp["address"] = addr.String()
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// validEndpoint accepts host:port and [v6]:port — one line, nothing that could
// end the value inside the client config.
func validEndpoint(s string) bool {
	host, port, ok := strings.Cut(s, ":")
	if strings.HasPrefix(s, "[") { // [v6]:port
		i := strings.LastIndex(s, "]:")
		if i < 0 {
			return false
		}
		host, port, ok = s[1:i], s[i+2:], true
	}
	n, err := strconv.Atoi(port)
	return ok && host != "" && err == nil && n >= 1 && n <= 65535 && !strings.ContainsAny(host, " \t\n#=")
}

func deletePeer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tunnel    string `json:"tunnel"`
		PublicKey string `json:"public_key"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if !validName(in.Tunnel) || !validKey(in.PublicKey) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "tunnel and public key required")
		return
	}
	mu.Lock()
	defer mu.Unlock()
	b, err := os.ReadFile(confPath(in.Tunnel))
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "unknown", "no tunnel named "+in.Tunnel)
		return
	}
	text, ok := removePeer(string(b), in.PublicKey)
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "unknown_peer", "no peer with this public key")
		return
	}
	if err := writeFile(confPath(in.Tunnel), text); err != nil {
		httpx.WriteErr(w, err)
		return
	}
	ctx, cancel := ctxShort(r)
	defer cancel()
	resp := map[string]any{"status": "deleted"}
	if err := reloadIfActive(ctx, in.Tunnel); err != nil {
		resp["warning"] = err.Error()
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
