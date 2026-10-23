'use strict';
// WireGuard tile. Helpers (api, esc, $, setStatus, describe, initTheme, download, zfw) come from common.js.

const API = '/wireguard';
let zfwPresent = false;

function ago(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 90) return `${s} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

function bytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}

// Delete buttons ask a second time instead of a blocking confirm() dialog.
function armed(btn) {
  if (btn.dataset.armed) return true;
  btn.dataset.armed = '1';
  const label = btn.textContent;
  btn.textContent = 'Click again';
  setTimeout(() => { delete btn.dataset.armed; btn.textContent = label; }, 4000);
  return false;
}

function tunnelHTML(t) {
  const on = t.active === 'active';
  const state = on ? '<span class="pill pill-ok">running</span>' : `<span class="pill pill-off">${esc(t.active || 'stopped')}</span>`;
  const boot = t.boot ? '<span class="pill pill-accent">starts at boot</span>' : '';
  const peers = t.peers.length ? `
    <div class="table-wrap"><table>
      <thead><tr><th>Peer</th><th>Allowed IPs</th><th>Last handshake</th><th>Endpoint</th><th>Received / sent</th><th></th></tr></thead>
      <tbody>${t.peers.map((p) => `
        <tr>
          <td><b>${esc(p.name || '—')}</b><div class="muted mono" style="font-size:11px">${esc(p.public_key)}</div></td>
          <td class="mono">${esc(p.allowed_ips)}</td>
          <td>${on ? esc(ago(p.latest_handshake)) : '<span class="muted">tunnel off</span>'}</td>
          <td class="mono">${esc(p.live_endpoint || p.endpoint || '')}</td>
          <td>${on ? `${bytes(p.rx_bytes)} / ${bytes(p.tx_bytes)}` : ''}</td>
          <td><button class="btn-danger btn-small" data-act="del-peer" data-tunnel="${esc(t.name)}" data-key="${esc(p.public_key)}">Remove</button></td>
        </tr>`).join('')}</tbody>
    </table></div>` : '<p class="empty">No peers yet — add a client below.</p>';
  return `
  <section class="card" data-tunnel="${esc(t.name)}">
    <div class="tunnel-head">
      <h3 class="mono">${esc(t.name)}</h3>${state}${boot}
      <div class="app-actions">
        ${on || t.boot ? `<button class="btn-secondary" data-act="disable">Turn off</button>` : `<button class="btn-primary" data-act="enable">Turn on</button>`}
        ${on ? '<button class="btn-secondary" data-act="restart">Restart</button>' : ''}
        <button class="btn-danger" data-act="delete">Delete</button>
      </div>
    </div>
    ${t.error ? `<p class="app-err">${esc(t.error)}</p>` : ''}
    <dl class="kv">
      <dt>Address</dt><dd class="mono">${esc(t.address)}</dd>
      <dt>Listen port</dt><dd class="mono">${esc(t.listen_port || '—')}/udp</dd>
      <dt>Public key</dt><dd class="mono">${esc(t.public_key)}</dd>
    </dl>
    <div class="zfw-line" data-port="${esc(t.listen_port)}"></div>
    <h4 class="section-title" style="margin-top:14px">Peers</h4>
    ${peers}
    <details style="margin-top:12px">
      <summary><b>Add a client</b> (phone, laptop) — generates its keys and config</summary>
      <form class="add-client" style="margin-top:10px" autocomplete="off">
        <div class="form-grid">
          <label>Name<input type="text" name="name" placeholder="Laptop" maxlength="40" required></label>
          <label>This server as the client reaches it<input type="text" name="endpoint" placeholder="vpn.example.org:${esc(t.listen_port || 51820)}" required></label>
          <label>DNS for the client (optional)<input type="text" name="dns" placeholder="e.g. 192.168.1.1"></label>
        </div>
        <label class="row" style="margin:8px 0;font-size:13px"><input type="checkbox" name="full_tunnel"> send all of the client's traffic through the tunnel</label>
        <button class="btn-primary" type="submit">Add client</button>
      </form>
    </details>
    <details style="margin-top:8px">
      <summary>Add a peer with its own key (another server, site-to-site)</summary>
      <form class="add-peer" style="margin-top:10px" autocomplete="off">
        <div class="form-grid">
          <label>Name<input type="text" name="name" maxlength="40" required></label>
          <label>Public key<input type="text" name="public_key" required></label>
          <label>Allowed IPs<input type="text" name="allowed_ips" placeholder="10.8.0.20/32, 192.168.50.0/24" required></label>
        </div>
        <button class="btn-secondary" type="submit" style="margin-top:8px">Add peer</button>
      </form>
    </details>
  </section>`;
}

async function zfwLines() {
  if (!zfwPresent) return;
  for (const el of document.querySelectorAll('.zfw-line')) {
    const port = Number(el.dataset.port);
    if (!port) continue;
    try {
      const ok = await zfw.allowsUdp(port);
      el.innerHTML = ok
        ? `<span class="pill pill-ok">ZFW</span> UDP ${port} is open in the ZFW firewall.`
        : `<span class="pill pill-warn">ZFW</span> The ZFW firewall drops UDP ${port}: clients cannot connect. <button class="btn-small btn-primary" data-act="zfw-open" data-port="${port}">Open UDP ${port} in ZFW</button>`;
    } catch (e) {
      el.innerHTML = `<span class="pill pill-off">ZFW</span> <span class="muted">Could not read the ZFW rules: ${esc(describe(e))}</span>`;
    }
  }
}

async function load() {
  const d = await api(`${API}/tunnels`);
  $('#conf-dir').textContent = d.conf_dir;
  $('#tunnels').innerHTML = d.tunnels.length ? d.tunnels.map(tunnelHTML).join('')
    : '<section class="card"><p class="empty">No tunnel yet. Create one below.</p></section>';
  const saved = safeGet('wireguard.endpoint');
  if (saved) document.querySelectorAll('.add-client input[name=endpoint]').forEach((i) => { i.value = saved; });
  await zfwLines();
}

async function refresh() {
  try {
    await load();
    setStatus('');
  } catch (e) {
    $('#tunnels').innerHTML = `<section class="card"><p class="app-err">${esc(describe(e))}</p></section>`;
    setStatus(describe(e), 'err');
  }
}

async function act(label, fn) {
  setStatus(`${label} …`);
  try {
    const r = await fn();
    setStatus(r && r.warning ? `${label}: done, but ${r.warning}` : `${label}: done.`, r && r.warning ? 'err' : 'ok');
    await load();
    return r;
  } catch (e) {
    setStatus(`${label}: ${describe(e)}`, 'err');
    return null;
  }
}

function showClientConfig(name, cfg) {
  const node = $('#client-dialog').content.firstElementChild.cloneNode(true);
  node.querySelector('pre').textContent = cfg;
  node.addEventListener('click', async (e) => {
    const a = e.target.dataset.act;
    if (a === 'copy') { await navigator.clipboard.writeText(cfg).catch(() => {}); e.target.textContent = 'Copied'; }
    if (a === 'download') download(`${name.replace(/[^A-Za-z0-9_.-]+/g, '_')}.conf`, cfg);
    if (a === 'close') node.remove();
  });
  document.body.appendChild(node);
}

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn || btn.closest('.modal')) return;
  const card = btn.closest('[data-tunnel]');
  const name = card && card.dataset.tunnel;
  switch (btn.dataset.act) {
    case 'enable': await act(`Turning ${name} on`, () => api(`${API}/tunnels/action`, { method: 'POST', body: { name, action: 'enable' } })); break;
    case 'disable': await act(`Turning ${name} off`, () => api(`${API}/tunnels/action`, { method: 'POST', body: { name, action: 'disable' } })); break;
    case 'restart': await act(`Restarting ${name}`, () => api(`${API}/tunnels/action`, { method: 'POST', body: { name, action: 'restart' } })); break;
    case 'delete':
      if (!armed(btn)) return;
      await act(`Deleting ${name} (the config is kept in .deleted)`, () => api(`${API}/tunnels/delete`, { method: 'POST', body: { name } }));
      break;
    case 'del-peer':
      if (!armed(btn)) return;
      await act('Removing the peer', () => api(`${API}/peers/delete`, { method: 'POST', body: { tunnel: btn.dataset.tunnel, public_key: btn.dataset.key } }));
      break;
    case 'zfw-open': {
      const port = Number(btn.dataset.port);
      await act(`Opening UDP ${port} in ZFW`, () => zfw.openUdp(port, `WireGuard ${port}/udp`, 'Added by the WireGuard tile'));
      break;
    }
    default:
  }
});

document.addEventListener('submit', async (e) => {
  const f = e.target;
  e.preventDefault();
  const v = Object.fromEntries(new FormData(f).entries());
  if (f.id === 'new-tunnel') {
    await act(`Creating ${v.name}`, () => api(`${API}/tunnels`, { method: 'POST', body: { name: v.name, address: v.address, listen_port: Number(v.listen_port) } }));
    return;
  }
  const tunnel = f.closest('[data-tunnel]').dataset.tunnel;
  if (f.classList.contains('add-client')) {
    safeSet('wireguard.endpoint', v.endpoint);
    const r = await act(`Adding ${v.name}`, () => api(`${API}/peers`, { method: 'POST',
      body: { tunnel, name: v.name, endpoint: v.endpoint, dns: v.dns || '', full_tunnel: !!v.full_tunnel } }));
    if (r && r.client_config) showClientConfig(v.name, r.client_config);
  } else if (f.classList.contains('add-peer')) {
    await act(`Adding ${v.name}`, () => api(`${API}/peers`, { method: 'POST',
      body: { tunnel, name: v.name, public_key: v.public_key.trim(), allowed_ips: v.allowed_ips } }));
  }
});

initTheme('wireguard.theme');
$('#refresh-btn').addEventListener('click', refresh);
(async () => { zfwPresent = await zfw.present(); refresh(); })();
