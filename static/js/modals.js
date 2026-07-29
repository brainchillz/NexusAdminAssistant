'use strict';
// Modals: Add/Edit Host, Users, LLM Settings, Audit, Change Password, alert.

function modal(html, wide) {
  $('modal-root').innerHTML =
    `<div class="modal" onclick="if(event.target===this)closeModal()">
       <div class="modal-card ${wide ? 'wide' : ''}">${html}</div></div>`;
}
function closeModal() { $('modal-root').innerHTML = ''; }
function alertModal(title, body) {
  modal(`<h2>${esc(title)}</h2><p style="white-space:pre-wrap" class="mono small">${esc(body)}</p>
    <div class="row end"><button onclick="closeModal()">Close</button></div>`);
}

// ─── Add / Edit Host ──────────────────────────────────────────────────
async function openHost(id) {
  const h = id ? state.hosts.find(x => x.id === id) : null;
  const t = (h && h.tags || []).join(', ');
  let creds = [];
  try { creds = (await API.get('/api/credentials')).credentials; } catch (e) { }
  state.creds = creds;
  const copts = `<option value="">— none —</option>` + creds.map(c =>
    `<option value="${c.id}" ${h && h.credential_id === c.id ? 'selected' : ''}>${esc(c.name)}${c.username ? ` (${esc(c.username)})` : ''}</option>`).join('');
  modal(`<h2>${h ? 'Edit' : 'Add'} host</h2>
    <div class="grid2">
      <div><label>Friendly name</label><input id="h-name" value="${esc(h ? h.name : '')}"></div>
      <div><label>Address (IP / hostname)</label><input id="h-addr" value="${esc(h ? h.address : '')}"></div>
      <div><label>Port</label><input id="h-port" type="number" value="${h ? h.port : 22}"></div>
      <div><label>Login username</label><input id="h-user" value="${esc(h ? h.username : '')}"></div>
    </div>
    <label>SSH private key ${h && h.has_ssh_key ? '<span class="ok-txt small">(stored — leave blank to keep)</span>' : ''}</label>
    <textarea id="h-key" rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY----- …"></textarea>
    <div class="grid2">
      <div><label>Shared credential <span class="muted small">(used when no per-host key)</span></label>
        <select id="h-cred">${copts}</select></div>
      <div style="align-self:end">${h ? `<button class="ghost" onclick="deployCred('${h.id}')" title="push the selected credential's PUBLIC key to the host's authorized_keys over its current creds, verify, and switch the host to it">Deploy credential key</button>` : ''}</div>
    </div>
    <div class="grid2">
      <div><label>Password ${h && h.has_password ? '<span class="ok-txt small">(stored)</span>' : ''}</label><input id="h-pass" type="password" placeholder="${h && h.has_password ? '•••• keep' : ''}"></div>
      <div><label>Sudo password ${h && h.has_sudo_password ? '<span class="ok-txt small">(stored)</span>' : ''}</label><input id="h-sudo" type="password" placeholder="${h && h.has_sudo_password ? '•••• keep' : 'blank if passwordless'}"></div>
    </div>
    <div class="grid2">
      <div><label>API token ${h && h.has_token ? '<span class="ok-txt small">(stored)</span>' : ''}</label><input id="h-token" type="password"></div>
      <div><label>Autonomy level</label><select id="h-level">
        <option value="lab" ${h && h.autonomy_level === 'lab' ? 'selected' : ''}>lab — free rein</option>
        <option value="default" ${!h || h.autonomy_level === 'default' ? 'selected' : ''}>default — confirm risky</option>
        <option value="prod" ${h && h.autonomy_level === 'prod' ? 'selected' : ''}>prod — confirm every change</option>
      </select></div>
    </div>
    <label>Tags (comma-separated)</label><input id="h-tags" value="${esc(t)}">
    <label>Notes</label><input id="h-notes" value="${esc(h ? h.notes : '')}">
    <div class="err" id="h-err"></div>
    <div class="row">
      <button class="ghost" onclick="testUnsaved(${h ? `'${h.id}'` : 'null'})">Test connection</button>
      ${h ? `<button class="ghost" onclick="provisionKey('${h.id}')" title="generate a key, deploy it, switch to key auth">Provision SSH key</button>` : ''}
      <span class="spacer" style="flex:1"></span>
      ${h ? `<button class="danger" onclick="delHost('${h.id}')">Delete</button>` : ''}
      <button class="ghost" onclick="closeModal()">Cancel</button>
      <button onclick="saveHost(${h ? `'${h.id}'` : 'null'})">Save</button>
    </div>`, true);
}
async function provisionKey(id) {
  if (!confirm('Generate a fresh SSH key, deploy it to this host using its current credentials, and switch the host to key auth?')) return;
  const nopw = confirm('Also set up passwordless sudo for this login user? (Requires current sudo access. Cancel to skip.)');
  $('h-err').textContent = 'Provisioning key…';
  try {
    const j = await API.post(`/api/hosts/${id}/provision-key`, { nopasswd_sudo: nopw });
    const r = j.result;
    $('h-err').innerHTML = `<span class="ok-txt">Key deployed — host now uses key auth${r.nopasswd_sudo ? ' + passwordless sudo' : ''}. OS: ${esc(r.os || '')}</span>`;
    loadHosts();
  } catch (e) { $('h-err').textContent = e.message; }
}
function hostForm() {
  const d = {
    name: $('h-name').value.trim(), address: $('h-addr').value.trim(),
    port: parseInt($('h-port').value) || 22, username: $('h-user').value.trim(),
    autonomy_level: $('h-level').value, notes: $('h-notes').value,
    tags: $('h-tags').value.split(',').map(s => s.trim()).filter(Boolean),
  };
  d.credential_id = $('h-cred') ? $('h-cred').value : '';
  if ($('h-key').value.trim()) d.ssh_key = $('h-key').value;
  if ($('h-pass').value) d.password = $('h-pass').value;
  if ($('h-sudo').value) d.sudo_password = $('h-sudo').value;
  if ($('h-token').value) d.token = $('h-token').value;
  return d;
}
async function saveHost(id) {
  const d = hostForm();
  if (!d.name || !d.address) { $('h-err').textContent = 'name and address required'; return; }
  try {
    if (id) await API.put(`/api/hosts/${id}`, d); else await API.post('/api/hosts', d);
    closeModal(); await loadHosts();
  } catch (e) { $('h-err').textContent = e.message; }
}
async function delHost(id) {
  if (!confirm('Delete this host and its stored credentials?')) return;
  try { await API.del(`/api/hosts/${id}`); closeModal(); if (state.activeHost && state.activeHost.id === id) state.activeHost = null; await loadHosts(); }
  catch (e) { $('h-err').textContent = e.message; }
}
async function testUnsaved(id) {
  $('h-err').textContent = 'Testing…';
  const d = hostForm();
  if (id) d.id = id;   // saved host: blank secret fields fall back to stored secrets
  try {
    const j = await API.post('/api/hosts/test', d);
    const r = j.result;
    $('h-err').innerHTML = r.ok ? `<span class="ok-txt">OK — ${esc(r.os || 'reached host')}</span>` : `<span class="err">${esc(r.error)}</span>`;
  } catch (e) { $('h-err').textContent = e.message; }
}

// ─── LLM Settings ─────────────────────────────────────────────────────
const LLM_PRESETS = {
  ollama: { provider: 'openai_compat', base_url: 'http://localhost:11434/v1', model: 'llama3.1' },
  vllm: { provider: 'openai_compat', base_url: 'http://localhost:8000/v1', model: '' },
  lmstudio: { provider: 'openai_compat', base_url: 'http://localhost:1234/v1', model: '' },
  llamacpp: { provider: 'openai_compat', base_url: 'http://localhost:8080/v1', model: '' },
  openai: { provider: 'openai_compat', base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
  anthropic: { provider: 'anthropic', base_url: '', model: 'claude-sonnet-5' },
};
async function openSettings() {
  let cfg = { provider: 'openai_compat', base_url: '', model: '', has_key: false, temperature: 0.2, max_tokens: 2048 };
  try { const j = await API.get('/api/settings/llm'); cfg = j.llm; } catch (e) { }
  modal(`<h2>LLM endpoint</h2>
    <label>Preset</label>
    <select id="s-preset" onchange="applyPreset()">
      <option value="">— choose a preset —</option>
      <option value="ollama">Ollama</option><option value="vllm">vLLM</option>
      <option value="lmstudio">LM Studio</option><option value="llamacpp">llama.cpp server</option>
      <option value="anthropic">Anthropic (Claude)</option><option value="openai">OpenAI</option>
    </select>
    <div class="grid2">
      <div><label>Provider</label><select id="s-provider">
        <option value="openai_compat" ${cfg.provider === 'openai_compat' ? 'selected' : ''}>OpenAI-compatible</option>
        <option value="anthropic" ${cfg.provider === 'anthropic' ? 'selected' : ''}>Anthropic</option>
      </select></div>
      <div><label>Model</label><input id="s-model" value="${esc(cfg.model)}"></div>
    </div>
    <label>Base URL <span class="muted small">(blank for Anthropic)</span></label>
    <input id="s-url" value="${esc(cfg.base_url)}" placeholder="http://host:11434/v1">
    <label>API key ${cfg.has_key ? '<span class="ok-txt small">(stored — blank to keep)</span>' : ''}</label>
    <input id="s-key" type="password" placeholder="${cfg.has_key ? '•••• keep' : 'optional for local'}">
    <div class="grid2">
      <div><label>Temperature</label><input id="s-temp" type="number" step="0.1" value="${cfg.temperature}"></div>
      <div><label>Max tokens</label><input id="s-max" type="number" value="${cfg.max_tokens}"></div>
    </div>
    <div class="err" id="s-err"></div>
    <h2 style="font-size:15px;margin-top:18px">Web search</h2>
    <label>SearXNG base URL <span class="muted small">(enables the web_search tool)</span></label>
    <input id="s-searx" placeholder="http://searxng-host:8888">
    <h2 style="font-size:15px;margin-top:18px">Notifications</h2>
    <label>Webhook URL <span class="muted small">(monitoring alerts + job reports; Slack/Discord/gchat-style {text})</span></label>
    <input id="s-notify" placeholder="https://hooks.example/...">
    <div class="err" id="s-serr"></div>
    <div class="row">
      <button class="ghost" onclick="testLlm()">Test LLM</button>
      <span class="spacer" style="flex:1"></span>
      <button class="ghost" onclick="closeModal()">Cancel</button>
      <button onclick="saveLlm()">Save all</button>
    </div>
    <h2 style="font-size:15px;margin-top:18px">Backup &amp; restore</h2>
    <p class="muted small">Export ALL state (hosts + credentials, memory, skills, jobs, users, and config) as one passphrase-encrypted file — the clean way to snapshot an instance, especially in Docker. Restore replaces everything and restarts the service.</p>
    <div class="row">
      <button class="ghost" onclick="exportState()">Export state…</button>
      <button class="ghost" onclick="restoreState()">Restore state…</button>
      <span class="spacer" style="flex:1"></span>
    </div>
    <div class="err" id="bk-err"></div>
    <h2 style="font-size:15px;margin-top:18px">Telegram bot</h2>
    <p class="muted small">Command the agent + approve actions from your phone. Only ONE running instance should own the bot token. Message your bot once, then add the ID it replies with.</p>
    <label class="check"><input type="checkbox" id="tg-enabled"> Enabled</label>
    <label>Bot token ${''}<span class="muted small">(from @BotFather; leave blank to keep)</span></label>
    <input id="tg-token" type="password" placeholder="123456:AA…">
    <div class="grid2">
      <div><label>Authorized Telegram user IDs (comma-sep)</label><input id="tg-wl" placeholder="123456789"></div>
      <div><label>Bot acts as app user</label><select id="tg-actas"></select></div>
    </div>
    <div class="err" id="tg-err"></div>
    <div class="row"><span class="spacer" style="flex:1"></span><button onclick="saveTelegram()">Save Telegram</button></div>
    <h2 style="font-size:15px;margin-top:18px">TLS certificate</h2>
    <p class="muted small">The certificate this app serves HTTPS with. Paste your own PEM (e.g. from Let's Encrypt or your internal CA) or regenerate a self-signed one. Applying restarts the service briefly to load it.</p>
    <div id="tls-current" class="muted small" style="margin:6px 0 10px">Loading…</div>
    <label>Certificate (PEM) <span class="muted small">full chain if you have intermediates</span></label>
    <textarea id="tls-cert" rows="4" placeholder="-----BEGIN CERTIFICATE-----" style="width:100%;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px"></textarea>
    <label>Private key (PEM) <span class="muted small">unencrypted; must match the cert</span></label>
    <textarea id="tls-key" rows="4" placeholder="-----BEGIN PRIVATE KEY-----" style="width:100%;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px"></textarea>
    <div class="err" id="tls-err"></div>
    <div class="row">
      <button class="ghost" onclick="regenTls()">Regenerate self-signed</button>
      <button class="ghost" onclick="applyTls()">Apply (restart)</button>
      <span class="spacer" style="flex:1"></span>
      <button onclick="saveTlsCert()">Install certificate</button>
    </div>`);
  try { const sj = await API.get('/api/settings/search'); $('s-searx').value = sj.search.base_url || ''; } catch (e) { }
  try { const nj = await API.get('/api/settings/notify'); $('s-notify').value = nj.notify.url || ''; } catch (e) { }
  try {
    const tj = await API.get('/api/settings/telegram');
    $('tg-enabled').checked = !!tj.telegram.enabled;
    $('tg-wl').value = (tj.telegram.whitelist || []).join(', ');
    $('tg-token').placeholder = tj.telegram.has_token ? '•••• stored — blank to keep' : '123456:AA…';
    $('tg-actas').innerHTML = (tj.users || []).map(u => `<option ${u === tj.telegram.act_as ? 'selected' : ''}>${esc(u)}</option>`).join('');
  } catch (e) { }
  loadTls();
}
async function loadTls() {
  const el = $('tls-current'); if (!el) return;
  try {
    const j = await API.get('/api/settings/tls');
    const scheme = j.tls_enabled ? 'currently serving HTTPS' : 'installed but TLS is OFF (set NAA_TLS=1 and restart)';
    if (!j.present) { el.innerHTML = `<span class="muted">No certificate yet — ${esc(scheme)}.</span>`; return; }
    if (j.error) { el.innerHTML = `<span class="err-txt">${esc(j.error)}</span>`; return; }
    const warn = j.days_left < 0 ? 'err-txt' : (j.days_left < 30 ? 'warn-txt' : 'ok-txt');
    const expiry = j.days_left < 0 ? `EXPIRED ${-j.days_left}d ago` : `${j.days_left}d left`;
    el.innerHTML = `<b>${j.self_signed ? 'Self-signed' : 'CA-issued'}</b> · ${esc(scheme)}<br>`
      + `Subject: ${esc(j.subject)}<br>Expires: ${esc(j.expires)} <span class="${warn}">(${expiry})</span><br>`
      + `SHA-256: <span style="font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10px">${esc(j.fingerprint_sha256)}</span>`;
  } catch (e) { el.innerHTML = `<span class="muted">Admin only — cert info unavailable.</span>`; }
}
async function saveTlsCert() {
  const cert = $('tls-cert').value.trim(), key = $('tls-key').value.trim();
  if (!cert || !key) { $('tls-err').textContent = 'Paste both the certificate and its private key.'; return; }
  $('tls-err').textContent = 'Validating…';
  try {
    const j = await API.post('/api/tls/cert', { cert, key });
    $('tls-err').innerHTML = `<span class="ok-txt">${esc(j.note || 'Installed.')}</span>`;
    $('tls-cert').value = ''; $('tls-key').value = ''; loadTls();
  } catch (e) { $('tls-err').textContent = e.message; }
}
async function regenTls() {
  if (!confirm('Generate a NEW self-signed certificate, replacing the current one? Browsers will show a "not trusted" warning until you install a CA-issued cert.')) return;
  $('tls-err').textContent = 'Generating…';
  try {
    const j = await API.post('/api/tls/regenerate', {});
    $('tls-err').innerHTML = `<span class="ok-txt">${esc(j.note || 'Generated.')}</span>`;
    loadTls();
  } catch (e) { $('tls-err').textContent = e.message; }
}
async function applyTls() {
  if (!confirm('Restart the service now to load the current certificate? Active sessions blip for a second.')) return;
  $('tls-err').textContent = 'Restarting…';
  try {
    const j = await API.post('/api/tls/apply', {});
    $('tls-err').innerHTML = `<span class="ok-txt">${esc(j.note || 'Restarting…')}</span>`;
    setTimeout(() => location.reload(), 5000);
  } catch (e) { $('tls-err').textContent = e.message; }
}
async function saveTelegram() {
  const d = {
    enabled: $('tg-enabled').checked,
    whitelist: $('tg-wl').value.split(',').map(s => s.trim()).filter(Boolean),
    act_as: $('tg-actas').value,
  };
  if ($('tg-token').value.trim()) d.token = $('tg-token').value.trim();
  try { await API.put('/api/settings/telegram', d); $('tg-err').innerHTML = '<span class="ok-txt">Telegram settings saved.</span>'; }
  catch (e) { $('tg-err').textContent = e.message; }
}
async function exportState() {
  const pw = prompt('Set a passphrase to encrypt this backup (min 8 chars). You will NEED it to restore — store it safely:');
  if (!pw) return;
  $('bk-err').textContent = 'Creating backup…';
  try {
    const r = await fetch('/api/backup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase: pw }) });
    if (!r.ok) { const j = await r.json().catch(() => ({})); $('bk-err').textContent = j.error || 'backup failed'; return; }
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `nexus-admin-assistant-${new Date().toISOString().slice(0, 10)}.naabk`;
    a.click(); URL.revokeObjectURL(a.href);
    $('bk-err').innerHTML = '<span class="ok-txt">Backup downloaded.</span>';
  } catch (e) { $('bk-err').textContent = e.message; }
}
function restoreState() {
  const inp = document.createElement('input');
  inp.type = 'file'; inp.accept = '.naabk';
  inp.onchange = async () => {
    const file = inp.files[0]; if (!file) return;
    const pw = prompt('Passphrase for this backup:'); if (!pw) return;
    if (!confirm('Restore will REPLACE all current state (hosts, users, memory, skills, everything) and restart the service. This cannot be undone. Continue?')) return;
    $('bk-err').textContent = 'Restoring…';
    const fd = new FormData(); fd.append('file', file); fd.append('passphrase', pw);
    try {
      const r = await fetch('/api/restore', { method: 'POST', body: fd });
      const j = await r.json().catch(() => ({}));
      if (!j.success) { $('bk-err').textContent = j.error || 'restore failed'; return; }
      alertModal('Restored', 'State restored. The service is restarting — this page will reload shortly.');
      setTimeout(() => location.reload(), 6000);
    } catch (e) { $('bk-err').textContent = e.message; }
  };
  inp.click();
}
function applyPreset() {
  const p = LLM_PRESETS[$('s-preset').value]; if (!p) return;
  $('s-provider').value = p.provider; $('s-url').value = p.base_url; $('s-model').value = p.model;
}
function llmForm() {
  const d = { provider: $('s-provider').value, base_url: $('s-url').value.trim(), model: $('s-model').value.trim(),
    temperature: parseFloat($('s-temp').value), max_tokens: parseInt($('s-max').value) };
  if ($('s-key').value) d.api_key = $('s-key').value;
  return d;
}
async function saveLlm() {
  try {
    await API.put('/api/settings/llm', llmForm());
    await API.put('/api/settings/search', { provider: 'searxng', base_url: $('s-searx').value.trim() });
    await API.put('/api/settings/notify', { url: $('s-notify').value.trim() });
    closeModal(); loadLlmBadge();
  } catch (e) { $('s-err').textContent = e.message; }
}
async function testLlm() {
  $('s-err').textContent = 'Testing…';
  try {
    const j = await API.post('/api/settings/llm/test', llmForm());
    const r = j.result;
    $('s-err').innerHTML = r.ok ? `<span class="ok-txt">OK — model replied: ${esc(r.detail)}</span>` : `<span class="err">${esc(r.detail)}</span>`;
    loadLlmBadge();
  } catch (e) { $('s-err').textContent = e.message; }
}

// ─── Users ────────────────────────────────────────────────────────────
async function openUsers() {
  const j = await API.get('/api/users');
  const rows = j.users.map(u => `<tr>
    <td>${esc(u.username)}</td><td>${esc(u.role)}</td>
    <td>${(u.scope_tags || []).map(t => `<span class="chip">${esc(t)}</span>`).join('') || '<span class="muted small">all</span>'}</td>
    <td><button class="ghost sm" onclick="resetPw('${u.id}')">Reset pw</button>
        ${u.id !== state.me.id ? `<button class="danger sm" onclick="delUser('${u.id}')">×</button>` : ''}</td></tr>`).join('');
  modal(`<h2>Users</h2>
    <table class="tbl"><tr><th>User</th><th>Role</th><th>Scope tags</th><th></th></tr>${rows}</table>
    <h2 style="font-size:15px;margin-top:16px">Add user</h2>
    <div class="grid2">
      <div><label>Username</label><input id="u-name"></div>
      <div><label>Password</label><input id="u-pass" type="password"></div>
      <div><label>Role</label><select id="u-role"><option>operator</option><option>admin</option><option>viewer</option></select></div>
      <div><label>Scope tags (comma-sep, blank=all)</label><input id="u-tags"></div>
    </div>
    <div class="err" id="u-err"></div>
    <div class="row end"><button class="ghost" onclick="closeModal()">Close</button><button onclick="addUser()">Add user</button></div>`, true);
}
async function addUser() {
  try {
    await API.post('/api/users', { username: $('u-name').value.trim(), password: $('u-pass').value,
      role: $('u-role').value, tags: $('u-tags').value.split(',').map(s => s.trim()).filter(Boolean) });
    openUsers();
  } catch (e) { $('u-err').textContent = e.message; }
}
async function delUser(id) { if (confirm('Delete user?')) { try { await API.del(`/api/users/${id}`); openUsers(); } catch (e) { alertModal('Error', e.message); } } }
async function resetPw(id) { const p = prompt('New password (user must change on next login):'); if (p) { try { await API.put(`/api/users/${id}`, { password: p }); alertModal('Done', 'Password reset.'); } catch (e) { alertModal('Error', e.message); } } }

// ─── Shared credentials ───────────────────────────────────────────────
async function openCreds() {
  let creds = [];
  try { creds = (await API.get('/api/credentials')).credentials; } catch (e) { alertModal('Error', e.message); return; }
  state.creds = creds;
  const rows = creds.map(c => `<tr>
    <td>${esc(c.name)}</td><td>${esc(c.username) || '<span class="muted small">—</span>'}</td>
    <td class="mono small" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(c.public_key)}">${esc(c.public_key)}</td>
    <td>${c.hosts_using}</td>
    <td><button class="ghost sm" onclick="showCredPub('${c.id}')">Pubkey</button>
        <button class="danger sm" onclick="delCred('${c.id}')">×</button></td></tr>`).join('');
  modal(`<h2>Shared credentials</h2>
    <p class="muted small">A private key stored once, reusable by any host (Fernet-encrypted; never shown again).
    Assign it in the host editor — "Deploy credential key" pushes its <b>public</b> key to the host's
    <span class="mono">authorized_keys</span> using the host's current credentials.</p>
    <table class="tbl"><tr><th>Name</th><th>Login user</th><th>Public key</th><th>Hosts</th><th></th></tr>
    ${rows || '<tr><td colspan="5" class="muted small">none yet</td></tr>'}</table>
    <h2 style="font-size:15px;margin-top:16px">Add credential</h2>
    <div class="grid2">
      <div><label>Name</label><input id="c-name" placeholder="e.g. fleet-admin"></div>
      <div><label>Default login user <span class="muted small">(optional)</span></label><input id="c-user"></div>
    </div>
    <label>SSH private key</label>
    <textarea id="c-key" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY----- …"></textarea>
    <div class="err" id="c-err"></div>
    <div class="row end"><button class="ghost" onclick="closeModal()">Close</button><button onclick="addCred()">Add credential</button></div>`, true);
}
async function addCred() {
  const name = $('c-name').value.trim();
  try {
    await API.post('/api/credentials', { name, username: $('c-user').value.trim(), ssh_key: $('c-key').value });
    openCreds();
  } catch (e) { $('c-err').textContent = e.message; }
}
function showCredPub(id) {
  const c = (state.creds || []).find(x => x.id === id);
  if (c) alertModal(`Public key — ${c.name}`, c.public_key + '\n\nAdd this line to authorized_keys on any host (or use "Deploy credential key" in the host editor).');
}
async function delCred(id) {
  if (!confirm('Delete this shared credential? Hosts using it will fall back to their own stored secrets.')) return;
  try { await API.del(`/api/credentials/${id}`); openCreds(); } catch (e) { alertModal('Error', e.message); }
}
async function deployCred(id) {
  const cid = $('h-cred').value;
  if (!cid) { $('h-err').textContent = 'pick a shared credential first'; return; }
  if (!confirm("Push this credential's public key to the host's authorized_keys (using the host's current credentials), verify key auth, and switch the host to it?")) return;
  $('h-err').textContent = 'Deploying credential key…';
  try {
    const j = await API.post(`/api/hosts/${id}/deploy-credential`, { credential_id: cid });
    $('h-err').innerHTML = `<span class="ok-txt">Credential deployed — key auth verified. OS: ${esc(j.result.os || '')}</span>`;
    loadHosts();
  } catch (e) { $('h-err').textContent = e.message; }
}

// ─── Memory ───────────────────────────────────────────────────────────
async function openMemory() {
  const hid = state.activeHost ? state.activeHost.id : null;
  const j = await API.get('/api/memories' + (hid ? `?host_id=${hid}` : ''));
  const mission = j.mission ? j.mission.body : '';
  const memList = (arr, scope) => (arr && arr.length ? arr.map(m => `
    <tr><td><span class="chip">${esc(m.kind)}</span></td>
      <td><b>${esc(m.title)}</b><div class="muted small">${esc(m.body)}</div></td>
      <td class="gs-acts"><button class="ghost sm" onclick="editMem(${m.id},'${scope}',${hid ? `'${hid}'` : 'null'})">✎</button>
        <button class="danger sm" onclick="delMem(${m.id},'${scope}',${hid ? `'${hid}'` : 'null'})">×</button></td></tr>`).join('')
    : `<tr><td colspan="3" class="muted small">nothing yet</td></tr>`);
  const hostSec = hid ? `
    <h2 style="font-size:15px;margin-top:16px">Memory for ${esc(state.activeHost.name)}</h2>
    <table class="tbl">${memList(j.host, 'host')}</table>
    ${addMemForm('host', hid)}` : '<p class="muted small" style="margin-top:14px">Select a host to see its memory.</p>';
  modal(`<h2>Memory</h2>
    <label>Mission <span class="muted small">(who the assistant is — injected into every conversation)</span></label>
    <textarea id="mem-mission" rows="4">${esc(mission)}</textarea>
    <div class="row"><span class="spacer" style="flex:1"></span><button class="ghost sm" onclick="saveMission()">Save mission</button></div>
    <h2 style="font-size:15px;margin-top:16px">Estate-wide knowledge <span class="muted small">(shared services, cross-host facts)</span></h2>
    <table class="tbl">${memList(j.global, 'global')}</table>
    ${addMemForm('global', null)}
    ${hostSec}
    <div class="err" id="mem-err"></div>
    <div class="row end"><button onclick="closeModal()">Close</button></div>`, true);
}
function addMemForm(scope, hid) {
  const p = scope === 'global' ? 'g' : 'h';
  return `<div class="row" style="margin-top:6px;gap:6px">
    <select id="mem-${p}-kind" style="width:auto">
      ${['service', 'decision', 'fact', 'state', 'changelog'].map(k => `<option>${k}</option>`).join('')}
    </select>
    <input id="mem-${p}-title" placeholder="title" style="width:auto;flex:1">
    <input id="mem-${p}-body" placeholder="details" style="flex:2">
    <button class="sm" onclick="addMem('${scope}',${hid ? `'${hid}'` : 'null'})">Add</button></div>`;
}
async function addMem(scope, hid) {
  const p = scope === 'global' ? 'g' : 'h';
  const title = $(`mem-${p}-title`).value.trim();
  if (!title) { $('mem-err').textContent = 'title required'; return; }
  try {
    await API.post('/api/memories', { scope, host_id: hid, kind: $(`mem-${p}-kind`).value,
      title, body: $(`mem-${p}-body`).value });
    openMemory();
  } catch (e) { $('mem-err').textContent = e.message; }
}
async function editMem(id) {
  const title = prompt('Title:'); if (title === null) return;
  const body = prompt('Details:'); if (body === null) return;
  try { await API.put(`/api/memories/${id}`, { title, body }); openMemory(); }
  catch (e) { $('mem-err').textContent = e.message; }
}
async function delMem(id) {
  if (!confirm('Delete this memory?')) return;
  try { await API.del(`/api/memories/${id}`); openMemory(); } catch (e) { $('mem-err').textContent = e.message; }
}
async function saveMission() {
  try { await API.put('/api/memories/mission', { body: $('mem-mission').value }); $('mem-err').innerHTML = '<span class="ok-txt">Mission saved.</span>'; }
  catch (e) { $('mem-err').textContent = e.message; }
}

// ─── Skills / playbooks ───────────────────────────────────────────────
async function openSkills() {
  const j = await API.get('/api/skills');
  const rows = (j.skills || []).map(s => {
    const warns = s.warnings || [];
    const warnRow = warns.length ? `<tr><td colspan="3" style="padding-top:0">
      <div class="err small" style="white-space:normal">⚠ May hang on replay: ${warns.map(w => esc(w)).join('<br>⚠ ')}</div></td></tr>` : '';
    return `<tr>
    <td><b>${esc(s.name)}</b>${warns.length ? ' <span class="chip" style="border-color:var(--bad);color:var(--bad)">⚠ blocking steps</span>' : ''}<div class="muted small">${esc(s.description)}</div></td>
    <td>${s.approved ? '<span class="chip" style="border-color:var(--ok);color:var(--ok)">approved</span>' : '<span class="chip" style="border-color:var(--warn);color:var(--warn)">draft</span>'}</td>
    <td class="gs-acts">
      <button class="ghost sm" onclick='viewSkill(${JSON.stringify(s.id)})'>View</button>
      <button class="${s.approved ? 'ghost' : 'ok'} sm" onclick="approveSkill(${s.id},${!s.approved})">${s.approved ? 'Unapprove' : 'Approve'}</button>
      <button class="danger sm" onclick="delSkill(${s.id})">×</button></td></tr>${warnRow}`;
  }).join('')
    || '<tr><td colspan="3" class="muted small">No playbooks yet. The assistant saves them as it learns tasks.</td></tr>';
  window._skills = j.skills || [];
  modal(`<h2>Skills / playbooks</h2>
    <p class="muted small">Reusable procedures the assistant authored. Approved ones are offered to it as known-good playbooks; drafts wait for your review.</p>
    <table class="tbl"><tr><th>Skill</th><th>Status</th><th></th></tr>${rows}</table>
    <h2 style="font-size:15px;margin-top:16px">Add a playbook</h2>
    <div class="grid2"><div><label>Name (kebab-case)</label><input id="sk-name"></div>
      <div><label>Description</label><input id="sk-desc"></div></div>
    <label>Steps / body</label><textarea id="sk-body" rows="5"></textarea>
    <label class="check"><input type="checkbox" id="sk-appr"> Approve immediately</label>
    <div class="err" id="sk-err"></div>
    <div class="row end"><button class="ghost" onclick="closeModal()">Close</button><button onclick="addSkill()">Add</button></div>`, true);
}
function viewSkill(id) {
  const s = (window._skills || []).find(x => x.id === id); if (!s) return;
  const warns = s.warnings || [];
  const banner = warns.length ? `<div class="err" style="white-space:normal;margin-bottom:8px">
    <b>⚠ This playbook has steps that would block an unattended run:</b><br>• ${warns.map(w => esc(w)).join('<br>• ')}
    <br><span class="small">Fix the body before approving, or it will hang when the agent replays it.</span></div>` : '';
  modal(`<h2>${esc(s.name)} ${s.approved ? '' : '<span class="muted small">(draft)</span>'}</h2>
    <p class="muted">${esc(s.description)}</p>${banner}
    <label>Name</label><input id="ske-name" value="${esc(s.name)}">
    <label>Description</label><input id="ske-desc" value="${esc(s.description)}">
    <label>Steps / body</label><textarea id="ske-body" rows="10">${esc(s.body)}</textarea>
    <div class="err" id="ske-err"></div>
    <div class="row"><button class="ghost" onclick="openSkills()">Back</button><span class="spacer" style="flex:1"></span>
      <button onclick="saveSkill(${s.id})">Save changes</button></div>`, true);
}
async function saveSkill(id) {
  try { await API.put(`/api/skills/${id}`, { name: $('ske-name').value.trim(), description: $('ske-desc').value, body: $('ske-body').value }); openSkills(); }
  catch (e) { $('ske-err').textContent = e.message; }
}
async function approveSkill(id, approved) { try { await API.put(`/api/skills/${id}`, { approved }); openSkills(); } catch (e) { alertModal('Error', e.message); } }
async function delSkill(id) { if (confirm('Delete this playbook?')) { try { await API.del(`/api/skills/${id}`); openSkills(); } catch (e) { alertModal('Error', e.message); } } }
async function addSkill() {
  const name = $('sk-name').value.trim();
  if (!name) { $('sk-err').textContent = 'name required'; return; }
  try { await API.post('/api/skills', { name, description: $('sk-desc').value, body: $('sk-body').value, approved: $('sk-appr').checked }); openSkills(); }
  catch (e) { $('sk-err').textContent = e.message; }
}

// ─── Scheduled jobs + deferred approvals ──────────────────────────────
async function openJobs() {
  const [jj, dj] = await Promise.all([API.get('/api/jobs'), API.get('/api/deferred')]);
  window._jobs = jj.jobs || [];
  const hostName = (id) => { const h = state.hosts.find(x => x.id === id); return h ? h.name : (id ? '(host)' : '—'); };
  const jobRows = (jj.jobs || []).map(j => `<tr>
    <td><b>${esc(j.name)}</b><div class="muted small mono">${esc(j.kind === 'once' ? '@ ' + j.schedule : j.schedule)} · ${esc(j.tz)}</div></td>
    <td>${esc(hostName(j.host_id))}</td>
    <td><span class="chip" ${j.ceiling === 'critical' ? 'style="border-color:var(--bad);color:var(--bad)"' : (j.ceiling === 'risky' ? 'style="border-color:var(--warn);color:var(--warn)"' : '')}>${esc(j.ceiling)}</span></td>
    <td class="small">${j.enabled ? (esc((j.next_run || '').slice(0, 16)) || 'enabled') : '<span class="muted">disabled</span>'}<div class="muted small">${j.last_status ? 'last: ' + esc(j.last_status) : ''}</div></td>
    <td class="gs-acts">
      <button class="ghost sm" onclick="runJobNow('${j.id}')">Run</button>
      ${j.last_report ? `<button class="ghost sm" onclick='viewReport(${JSON.stringify(j.id)})'>Report</button>` : ''}
      <button class="ghost sm" onclick='editJob(${JSON.stringify(j.id)})'>Edit</button>
      <button class="danger sm" onclick="delJob('${j.id}')">×</button></td></tr>`).join('')
    || '<tr><td colspan="5" class="muted small">No scheduled jobs.</td></tr>';
  const defRows = (dj.deferred || []).map(a => `<tr>
    <td class="mono small">${esc(a.command || a.tool)}</td>
    <td><span class="chip" style="border-color:var(--warn);color:var(--warn)">${esc(a.risk)}</span></td>
    <td class="gs-acts">
      <button class="ok sm" onclick="approveDeferred(${a.id},false)">Approve once</button>
      <button class="ghost sm" onclick="approveDeferred(${a.id},true)">Approve + allow</button>
      <button class="danger sm" onclick="denyDeferred(${a.id})">Deny</button></td></tr>`).join('')
    || '<tr><td colspan="3" class="muted small">Nothing waiting for approval.</td></tr>';
  modal(`<h2>Scheduled jobs</h2>
    <table class="tbl"><tr><th>Job</th><th>Host</th><th>Ceiling</th><th>Next / status</th><th></th></tr>${jobRows}</table>
    ${(dj.deferred || []).length ? '<h2 style="font-size:15px;margin-top:16px;color:var(--warn)">⚠ Waiting for your approval</h2>' : '<h2 style="font-size:15px;margin-top:16px">Deferred approvals</h2>'}
    <p class="muted small">Actions a job wanted to take that fell outside its pre-approved envelope. Approving runs it now; "Approve + allow" also pre-approves it for that job's future runs.</p>
    <table class="tbl"><tr><th>Action</th><th>Risk</th><th></th></tr>${defRows}</table>
    <div class="row end" style="margin-top:14px"><button onclick="closeModal()">Close</button><button onclick="editJob(null)">+ New job</button></div>`, true);
}
function jobHostOptions(sel) {
  return '<option value="">— no host (general) —</option>' +
    state.hosts.map(h => `<option value="${h.id}" ${sel === h.id ? 'selected' : ''}>${esc(h.name)}</option>`).join('');
}
function editJob(id) {
  const j = id ? (window._jobs || []).find(x => x.id === id) : null;
  const once = j && j.kind === 'once';
  modal(`<h2>${j ? 'Edit' : 'New'} scheduled job</h2>
    <div class="grid2">
      <div><label>Name</label><input id="j-name" value="${esc(j ? j.name : '')}"></div>
      <div><label>Host</label><select id="j-host">${jobHostOptions(j ? j.host_id : (state.activeHost ? state.activeHost.id : ''))}</select></div>
    </div>
    <label>Instruction (what the agent should do)</label>
    <textarea id="j-inst" rows="3">${esc(j ? j.instruction : '')}</textarea>
    <div class="grid2">
      <div><label>Schedule type</label><select id="j-kind" onchange="jobKindHint()"><option value="cron" ${!once ? 'selected' : ''}>recurring (cron)</option><option value="once" ${once ? 'selected' : ''}>one-off (at)</option></select></div>
      <div><label>Timezone</label><input id="j-tz" value="${esc(j ? j.tz : 'UTC')}" placeholder="America/New_York"></div>
    </div>
    <label id="j-sched-l">Cron (min hour dom mon dow) — e.g. "0 22 * * *" = 22:00 daily</label>
    <input id="j-sched" value="${esc(j ? j.schedule : '0 22 * * *')}">
    <label>Unattended ceiling</label>
    <select id="j-ceil" onchange="ceilWarn()">
      ${['safe', 'caution', 'risky', 'critical'].map(c => `<option ${(j ? j.ceiling : 'caution') === c ? 'selected' : ''}>${c}</option>`).join('')}
    </select>
    <div id="j-ceilwarn" class="small"></div>
    <label>Pre-approved actions (one substring per line — runs even above the ceiling)</label>
    <textarea id="j-allow" rows="2" placeholder="docker image prune&#10;systemctl restart docker">${esc(j ? (j.allow || []).join('\n') : '')}</textarea>
    <div class="grid2">
      <div><label>Notify webhook URL (optional)</label><input id="j-notify" value="${esc(j ? j.notify_url : '')}"></div>
      <div><label class="check"><input type="checkbox" id="j-enabled" ${!j || j.enabled ? 'checked' : ''}> Enabled</label></div>
    </div>
    <div class="err" id="j-err"></div>
    <div class="row"><button class="ghost" onclick="openJobs()">Back</button><span class="spacer" style="flex:1"></span><button onclick="saveJob(${j ? `'${j.id}'` : 'null'})">Save</button></div>`, true);
  ceilWarn(); jobKindHint();
}
function jobKindHint() {
  const once = $('j-kind').value === 'once';
  $('j-sched-l').textContent = once ? 'Run at (ISO datetime) — e.g. 2026-07-25T22:00:00' : 'Cron (min hour dom mon dow) — e.g. "0 22 * * *" = 22:00 daily';
}
function ceilWarn() {
  const c = $('j-ceil').value; const el = $('j-ceilwarn');
  const notes = { safe: 'Auto-runs read-only actions; everything else is deferred for you.',
    caution: 'Auto-runs reads + installs/config; defers restarts, deletes, firewall/user changes, reboots.',
    risky: 'Auto-runs up to service restarts and deletes unattended. Defers only critical.',
    critical: '⚠ Auto-runs ANYTHING unattended — including reboots, disk formatting, mass deletes — with no human. Use only for hosts you fully trust to automate.' };
  el.innerHTML = `<span class="${c === 'critical' ? 'bad' : (c === 'risky' ? 'warn-txt' : 'muted')}">${notes[c]}</span>`;
}
async function saveJob(id) {
  const d = { name: $('j-name').value.trim(), host_id: $('j-host').value || null,
    instruction: $('j-inst').value.trim(), kind: $('j-kind').value, schedule: $('j-sched').value.trim(),
    tz: $('j-tz').value.trim() || 'UTC', ceiling: $('j-ceil').value,
    allow: $('j-allow').value.split('\n').map(s => s.trim()).filter(Boolean),
    notify_url: $('j-notify').value.trim(), enabled: $('j-enabled').checked };
  if (!d.name || !d.instruction) { $('j-err').textContent = 'name and instruction required'; return; }
  try { if (id) await API.put(`/api/jobs/${id}`, d); else await API.post('/api/jobs', d); openJobs(); }
  catch (e) { $('j-err').textContent = e.message; }
}
async function runJobNow(id) { try { await API.post(`/api/jobs/${id}/run`, {}); alertModal('Started', 'Job is running now. Reopen Jobs in a moment to see its report.'); } catch (e) { alertModal('Error', e.message); } }
async function delJob(id) { if (confirm('Delete this job?')) { try { await API.del(`/api/jobs/${id}`); openJobs(); } catch (e) { alertModal('Error', e.message); } } }
function viewReport(id) {
  const j = (window._jobs || []).find(x => x.id === id); if (!j) return;
  alertModal(`Report — ${j.name}`, j.last_report || '(no report yet)');
}
async function approveDeferred(did, addAllow) {
  try { const r = await API.post(`/api/deferred/${did}/approve`, { add_to_allow: addAllow }); openJobs(); }
  catch (e) { alertModal('Error', e.message); }
}
async function denyDeferred(did) { try { await API.post(`/api/deferred/${did}/deny`, {}); openJobs(); } catch (e) { alertModal('Error', e.message); } }

// ─── Host documentation ───────────────────────────────────────────────
const DOC_PROMPT = 'Inspect this host thoroughly and write clear, well-organized documentation for it — OS and version, CPU/memory/disk, the services and software installed and their roles, important configuration and file locations, and what this host is used for. Then save it using the write_host_doc tool.';
async function openHostDoc(hid) {
  const j = await API.get(`/api/hosts/${hid}/doc`);
  window._hostDoc = j.doc || '';
  const name = (state.hosts.find(h => h.id === hid) || {}).name || '';
  const body = j.doc
    ? `<div class="muted small" style="margin-bottom:8px">Updated ${esc((j.doc_updated || '').slice(0, 16).replace('T', ' '))}</div>
       <div class="md" style="background:var(--well);border:1px solid var(--line);border-radius:8px;padding:14px;max-height:55vh;overflow:auto">${renderMarkdown(j.doc)}</div>`
    : '<p class="muted">No documentation yet. Generate it and the assistant will inspect the host and write it up.</p>';
  modal(`<h2>Docs — ${esc(name)}</h2>${body}
    <div class="row">
      <button onclick="generateDoc('${hid}')">${j.doc ? 'Regenerate' : 'Generate documentation'}</button>
      ${j.doc ? '<button class="ghost" onclick="copyDoc()">Copy markdown</button>' : ''}
      <span class="spacer" style="flex:1"></span>
      <button class="ghost" onclick="closeModal()">Close</button>
    </div>`, true);
}
function copyDoc() {
  try { navigator.clipboard.writeText(window._hostDoc || ''); alertModal('Copied', 'Documentation markdown copied to clipboard.'); }
  catch (e) { alertModal('Copy failed', 'Select and copy manually.'); }
}
function generateDoc(hid) {
  closeModal();
  if (!state.activeHost || state.activeHost.id !== hid) { selectHost(hid); }
  $('composer').value = DOC_PROMPT;
  autogrow($('composer'));
  send();
}

// ─── Changes / rollback ───────────────────────────────────────────────
async function openChanges(hid) {
  const j = await API.get(`/api/hosts/${hid}/changes`);
  const rows = (j.changes || []).map(c => {
    const when = (c.ts || '').slice(0, 19).replace('T', ' ');
    let act = '';
    if (c.reverted) act = '<span class="muted small">reverted</span>';
    else if (c.reversible) act = `<button class="ghost sm" onclick="revertChange(${c.id},'${hid}')">Revert</button>`;
    else act = '<span class="muted small">—</span>';
    const label = c.kind === 'write_file'
      ? `<span class="mono small">wrote ${esc(c.path)}${c.had_before ? '' : ' (new)'}${c.used_sudo ? ' [sudo]' : ''}</span>`
      : `<span class="mono small">${esc(c.summary)}</span>`;
    return `<tr><td class="small">${esc(when)}</td><td>${label}</td>
      <td class="small">${esc(c.username || '')}</td><td class="gs-acts">${act}</td></tr>`;
  }).join('') || '<tr><td colspan="4" class="muted small">No recorded changes on this host yet.</td></tr>';
  modal(`<h2>Changes — ${esc((state.hosts.find(h => h.id === hid) || {}).name || '')}</h2>
    <p class="muted small">File writes are reversible (the previous content is stored encrypted); risky commands are logged for visibility.</p>
    <table class="tbl"><tr><th>When</th><th>Change</th><th>By</th><th></th></tr>${rows}</table>
    <div class="err" id="ch-err"></div>
    <div class="row end"><button onclick="closeModal()">Close</button></div>`, true);
}
async function revertChange(cid, hid) {
  if (!confirm('Revert this file change — restore the previous content on the host?')) return;
  try { await API.post(`/api/changes/${cid}/revert`, {}); openChanges(hid); }
  catch (e) { $('ch-err').textContent = e.message; }
}

// ─── Audit ────────────────────────────────────────────────────────────
async function openAudit() {
  const j = await API.get('/api/audit');
  const rows = j.audit.map(a => `<tr><td class="mono small">${esc(a.ts.slice(0, 19))}</td><td>${esc(a.username)}</td>
    <td>${esc(a.action)}</td><td class="mono small">${esc((a.detail || '').slice(0, 80))}</td>
    <td><span class="chip">${esc(a.decision || '')}</span></td></tr>`).join('');
  modal(`<h2>Audit log</h2><table class="tbl"><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>Decision</th></tr>${rows || '<tr><td colspan=5 class="muted">No entries yet.</td></tr>'}</table>
    <div class="row end"><button onclick="closeModal()">Close</button></div>`, true);
}

// ─── Change password (forced first-run) ───────────────────────────────
function openChangePw(forced) {
  modal(`<h2>${forced ? 'Set a new password' : 'Change password'}</h2>
    ${forced ? '<p class="muted small">First login — please change the default password.</p>' : ''}
    <label>Current password</label><input id="cp-old" type="password">
    <label>New password</label><input id="cp-new" type="password">
    <div class="err" id="cp-err"></div>
    <div class="row end">${forced ? '' : '<button class="ghost" onclick="closeModal()">Cancel</button>'}<button onclick="changePw()">Save</button></div>`);
}
async function changePw() {
  try { await API.post('/api/change-password', { old_password: $('cp-old').value, new_password: $('cp-new').value });
    closeModal(); state.me.must_change = false; }
  catch (e) { $('cp-err').textContent = e.message; }
}

// ─── Application & service checks ─────────────────────────────────────
// Two distinct facts per check: the TARGET we probe (a URL/VIP/floating IP —
// "is it up?") and the HOST it's pinned to ("where do I go to fix it?"). They
// differ whenever a proxy or VIP is involved, and only the host is actionable.
const CHECK_KINDS = {
  https: { label: 'HTTPS (web page/API)', ph: 'https://shop.lan/health' },
  http: { label: 'HTTP (web page/API)', ph: 'http://intranet.lan/' },
  tcp: { label: 'TCP port open', ph: '10.0.0.20:5432' },
  dns: { label: 'DNS resolver', ph: '10.0.0.53' },
  smb: { label: 'SMB / Windows file share', ph: '10.0.0.30' },
  ssh: { label: 'SSH', ph: '10.0.0.10:22' },
  ping: { label: 'Host reachable', ph: '10.0.0.42' },
  cert: { label: 'TLS certificate expiry', ph: 'shop.lan:443' },
};
const CHECK_DOT = { ok: 'var(--ok)', warn: 'var(--warn)', down: 'var(--bad)', unknown: 'var(--muted)' };

async function openChecks() {
  const j = await API.get('/api/checks');
  window._checks = j.checks || [];
  const hostName = (id) => { const h = state.hosts.find(x => x.id === id); return h ? h.name : (id ? '(host)' : ''); };
  const rows = window._checks.map(c => {
    const age = c.last_check ? esc(c.last_check.slice(11, 16)) : '—';
    const pin = c.host_id
      ? esc(hostName(c.host_id))
      : '<span class="muted">not pinned</span>';
    return `<tr>
      <td><span style="color:${CHECK_DOT[c.status] || CHECK_DOT.unknown}">●</span> <b>${esc(c.name)}</b>
        <div class="muted small mono">${esc(CHECK_KINDS[c.kind] ? c.kind : c.kind)} · ${esc(c.target)}${c.port ? ':' + c.port : ''}</div></td>
      <td>${pin}${c.auto_fix ? '<div class="small" style="color:var(--accent-hov)">🛠 auto-fix</div>' : ''}</td>
      <td class="small">${c.enabled ? esc(c.status) : '<span class="muted">paused</span>'}
        <div class="muted small">${c.status === 'ok' ? c.latency_ms + 'ms' : esc((c.last_error || '').slice(0, 60))}</div></td>
      <td class="small muted">${age}</td>
      <td class="gs-acts">
        <button class="ghost sm" onclick="runCheckNow('${c.id}')">Test</button>
        <button class="ghost sm" onclick='editCheck(${JSON.stringify(c.id)})'>Edit</button>
        <button class="danger sm" onclick="delCheck('${c.id}')">×</button></td></tr>`;
  }).join('') || '<tr><td colspan="5" class="muted small">No checks yet. Add one to watch a website, share, resolver or port.</td></tr>';
  const down = window._checks.filter(c => c.status === 'down' && c.enabled);
  modal(`<h2>Application &amp; service checks</h2>
    <p class="muted small">Watches the things people actually use — a website, a file share, a resolver, a port —
      from here. Each check is <b>pinned to the host it runs on</b>, which may be different from the address you
      probe (a proxy, VIP or floating IP). The pinned host is where troubleshooting happens.</p>
    ${down.length ? `<div class="err" style="margin-bottom:10px">🔴 ${down.length} service${down.length > 1 ? 's are' : ' is'} down: ${down.map(c => esc(c.name)).join(', ')}</div>` : ''}
    <table class="tbl"><tr><th>Check</th><th>Runs on</th><th>State</th><th>Last</th><th></th></tr>${rows}</table>
    <div class="row end" style="margin-top:14px"><button onclick="closeModal()">Close</button><button onclick="editCheck(null)">+ New check</button></div>`, true);
}

function checkHostOptions(sel) {
  return '<option value="">— not pinned —</option>' +
    state.hosts.map(h => `<option value="${h.id}" ${sel === h.id ? 'selected' : ''}>${esc(h.name)}</option>`).join('');
}

function editCheck(id) {
  const c = id ? (window._checks || []).find(x => x.id === id) : null;
  const kind = c ? c.kind : 'https';
  // checkKindHint() re-renders the per-kind fields on every change, so it needs
  // the saved options to prefill them the first time
  window._editingCheckOpts = (c && c.options) || {};
  modal(`<h2>${c ? 'Edit' : 'New'} service check</h2>
    <div class="grid2">
      <div><label>Name</label><input id="c-name" value="${esc(c ? c.name : '')}" placeholder="Shop website"></div>
      <div><label>What to check</label><select id="c-kind" onchange="checkKindHint()">
        ${Object.entries(CHECK_KINDS).map(([k, v]) => `<option value="${k}" ${kind === k ? 'selected' : ''}>${esc(v.label)}</option>`).join('')}
      </select></div>
    </div>
    <label>Address to probe <span class="muted">— where the service answers</span></label>
    <input id="c-target" value="${esc(c ? c.target : '')}" placeholder="">
    <div class="grid2">
      <div><label>Port <span class="muted">(0 = default)</span></label><input id="c-port" type="number" value="${c ? c.port : 0}"></div>
      <div><label>Check every (seconds)</label><input id="c-interval" type="number" value="${c ? c.interval_s : 120}"></div>
    </div>
    <div id="c-kindopts"></div>
    <label>Host it runs on <span class="muted">— where you'd go to fix it</span></label>
    <select id="c-host">${checkHostOptions(c ? c.host_id : (state.activeHost ? state.activeHost.id : ''))}</select>
    <p class="muted small">Pin this to the machine the service actually lives on, whatever address you probe above.
      A check on <span class="mono">https://shop.lan</span> may answer through a reverse proxy while the app runs on a different box.</p>
    <div class="grid2">
      <div><label>Timeout (s)</label><input id="c-timeout" type="number" value="${c ? c.timeout_s : 10}"></div>
      <div><label>Failures before "down"</label><input id="c-fails" type="number" value="${c ? c.fail_threshold : 2}"></div>
    </div>
    <hr style="border:0;border-top:1px solid var(--line);margin:14px 0">
    <label class="check"><input type="checkbox" id="c-autofix" ${c && c.auto_fix ? 'checked' : ''} onchange="autoFixHint()">
      <b>Troubleshoot this automatically when it goes down</b></label>
    <div id="c-autofix-box" style="display:none">
      <p class="muted small">When the check goes red, the assistant starts an unattended run <b>on the pinned host</b>:
        it inspects the service, reads logs and config, and repairs what it safely can within the ceiling below.
        Anything beyond the ceiling is held for your approval instead of being done. You get a report either way.</p>
      <label>How much it may do on its own</label>
      <select id="c-ceil" onchange="autoFixHint()">
        ${['safe', 'caution', 'risky', 'critical'].map(k => `<option value="${k}" ${(c ? c.auto_fix_ceiling : 'caution') === k ? 'selected' : ''}>${k}</option>`).join('')}
      </select>
      <div id="c-ceilwarn" class="small"></div>
      <label>Pre-approved actions (one per line — allowed even above the ceiling)</label>
      <textarea id="c-allow" rows="2" placeholder="systemctl restart nginx">${esc(c ? (c.auto_fix_allow || []).join('\n') : '')}</textarea>
      <label>Custom instructions (optional — leave blank for the standard troubleshooting brief)</label>
      <textarea id="c-inst" rows="2" placeholder="Check the container first: docker compose ps in /srv/shop">${esc(c ? c.auto_fix_instruction : '')}</textarea>
      <label>Wait at least this long between repair attempts (seconds)</label>
      <input id="c-cooldown" type="number" value="${c ? c.auto_fix_cooldown_s : 1800}">
    </div>
    <label class="check" style="margin-top:10px"><input type="checkbox" id="c-enabled" ${!c || c.enabled ? 'checked' : ''}> Enabled</label>
    <div class="err" id="c-err"></div>
    <div id="c-testout" class="small muted"></div>
    <div class="row"><button class="ghost" onclick="openChecks()">Back</button>
      <span class="spacer" style="flex:1"></span>
      <button class="ghost" onclick="testCheckDraft()">Test now</button>
      <button onclick="saveCheck(${c ? `'${c.id}'` : 'null'})">Save</button></div>`, true);
  checkKindHint(); autoFixHint();
}

function checkKindHint() {
  const k = $('c-kind').value;
  const t = $('c-target');
  t.placeholder = (CHECK_KINDS[k] || {}).ph || '';
  const opts = window._editingCheckOpts || {};
  const box = $('c-kindopts');
  if (k === 'dns') {
    box.innerHTML = `<div class="grid2">
      <div><label>Name to look up</label><input id="o-dnsq" value="${esc(opts.dns_query || '')}" placeholder="shop.lan"></div>
      <div><label>Expected answer (optional)</label><input id="o-dnsexp" value="${esc(opts.dns_expect || '')}" placeholder="10.0.0.20"></div></div>`;
  } else if (k === 'http' || k === 'https') {
    box.innerHTML = `<div class="grid2">
      <div><label>Expected status (blank = any non-error)</label><input id="o-status" value="${esc(opts.expect_status || '')}" placeholder="200"></div>
      <div><label>Page must contain (optional)</label><input id="o-body" value="${esc(opts.expect_body || '')}" placeholder="Welcome"></div></div>
      <label class="check"><input type="checkbox" id="o-verify" ${opts.verify_tls === false ? '' : 'checked'}> Verify the TLS certificate</label>`;
  } else if (k === 'cert') {
    box.innerHTML = `<label>Warn this many days before it expires</label>
      <input id="o-certdays" type="number" value="${opts.cert_warn_days || 21}">`;
  } else {
    box.innerHTML = '';
  }
}

function autoFixHint() {
  const on = $('c-autofix').checked;
  $('c-autofix-box').style.display = on ? '' : 'none';
  if (!on) return;
  const c = $('c-ceil').value;
  const notes = {
    safe: 'It will only look — read logs, check status — and report. Any fix waits for you.',
    caution: 'It can install packages and write configuration, and will hold restarts and deletions for you.',
    risky: 'It can also restart services, change the firewall, and delete files on its own. Usually what you want for "just fix the website".',
    critical: '⚠ It can do ANYTHING unattended, including rebooting the machine and formatting disks, with nobody watching.',
  };
  $('c-ceilwarn').innerHTML = `<span class="${c === 'critical' ? 'bad' : (c === 'risky' ? 'warn-txt' : 'muted')}">${notes[c]}</span>`;
}

function checkDraft() {
  const k = $('c-kind').value;
  const options = {};
  if (k === 'dns') { options.dns_query = ($('o-dnsq') || {}).value || ''; options.dns_expect = ($('o-dnsexp') || {}).value || ''; }
  if (k === 'http' || k === 'https') {
    if (($('o-status') || {}).value) options.expect_status = $('o-status').value.trim();
    if (($('o-body') || {}).value) options.expect_body = $('o-body').value.trim();
    options.verify_tls = ($('o-verify') || {}).checked !== false;
  }
  if (k === 'cert') options.cert_warn_days = parseInt(($('o-certdays') || {}).value || 21, 10);
  return {
    name: $('c-name').value.trim(), kind: k, target: $('c-target').value.trim(),
    port: parseInt($('c-port').value || 0, 10), host_id: $('c-host').value || '',
    interval_s: parseInt($('c-interval').value || 120, 10),
    timeout_s: parseInt($('c-timeout').value || 10, 10),
    fail_threshold: parseInt($('c-fails').value || 2, 10),
    options, enabled: $('c-enabled').checked,
    auto_fix: $('c-autofix').checked,
    auto_fix_ceiling: ($('c-ceil') || {}).value || 'caution',
    auto_fix_allow: (($('c-allow') || {}).value || '').split('\n').map(s => s.trim()).filter(Boolean),
    auto_fix_instruction: (($('c-inst') || {}).value || '').trim(),
    auto_fix_cooldown_s: parseInt(($('c-cooldown') || {}).value || 1800, 10),
  };
}

async function testCheckDraft() {
  const d = checkDraft();
  $('c-testout').textContent = 'testing…';
  try {
    const j = await API.post('/api/checks/probe', { kind: d.kind, target: d.target, port: d.port, timeout_s: d.timeout_s, options: d.options });
    const r = j.result;
    $('c-testout').innerHTML = `<span style="color:${CHECK_DOT[r.status]}">●</span> ${esc(r.status)} · ${r.latency_ms}ms ${r.error ? '— ' + esc(r.error) : ''}`;
  } catch (e) { $('c-testout').textContent = e.message; }
}

async function saveCheck(id) {
  const d = checkDraft();
  if (!d.name || !d.target) { $('c-err').textContent = 'name and address are required'; return; }
  if (d.auto_fix && !d.host_id) { $('c-err').textContent = 'pick the host it runs on — automatic troubleshooting needs somewhere to work'; return; }
  try { if (id) await API.put(`/api/checks/${id}`, d); else await API.post('/api/checks', d); openChecks(); }
  catch (e) { $('c-err').textContent = e.message; }
}

async function runCheckNow(id) {
  try { await API.post(`/api/checks/${id}/run`, {}); openChecks(); }
  catch (e) { alertModal('Error', e.message); }
}
async function delCheck(id) {
  if (confirm('Delete this check?')) {
    try { await API.del(`/api/checks/${id}`); openChecks(); } catch (e) { alertModal('Error', e.message); }
  }
}
