'use strict';
// Nexus Admin Assistant SPA — vanilla JS, no build step.

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const state = {
  me: null, hosts: [], activeHost: null, convo: null, convos: [],
  tagFilter: new Set(), runId: null, es: null, streaming: false,
  toolCards: {}, // call_id -> {out element}
  csrf: null,    // issued at login / /api/me; sent on every mutating request
};

// ─── API ──────────────────────────────────────────────────────────────
const API = {
  async req(method, path, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    if (state.csrf && method !== 'GET') opt.headers['X-CSRF-Token'] = state.csrf;
    const r = await fetch(path, opt);
    if (r.status === 401) { showLogin(); throw new Error('auth'); }
    const j = await r.json().catch(() => ({ success: false, error: 'bad response' }));
    if (!j.success) throw new Error(j.error || 'error');
    return j;
  },
  get(p) { return this.req('GET', p); },
  post(p, b) { return this.req('POST', p, b || {}); },
  put(p, b) { return this.req('PUT', p, b || {}); },
  del(p) { return this.req('DELETE', p); },
};

// ─── boot ─────────────────────────────────────────────────────────────
async function boot() {
  try {
    const j = await API.get('/api/me');
    state.me = j.user; state.csrf = j.csrf;
    showApp();
  } catch (e) { showLogin(); }
}
function showLogin() { $('login').style.display = 'flex'; $('app').style.display = 'none'; }
async function showApp() {
  $('login').style.display = 'none'; $('app').style.display = 'flex';
  $('whoami').textContent = `${state.me.username} · ${state.me.role}`;
  const admin = state.me.role === 'admin';
  $('btn-creds').style.display = (admin || state.me.role === 'operator') ? '' : 'none';
  $('btn-users').style.display = admin ? '' : 'none';
  $('btn-settings').style.display = admin ? '' : 'none';
  $('btn-audit').style.display = admin ? '' : 'none';
  if (state.me.must_change) openChangePw(true);
  await loadHosts();
  await loadLlmBadge();
  if (!state._healthTimer) state._healthTimer = setInterval(() => { loadHosts().catch(() => { }); }, 45000);
}

async function doLogin() {
  $('lg-err').textContent = '';
  try {
    const j = await API.post('/api/login', { username: $('lg-user').value, password: $('lg-pass').value });
    state.me = j.user; state.csrf = j.csrf; showApp();
  } catch (e) { $('lg-err').textContent = e.message; }
}
async function doLogout() { await API.post('/api/logout'); location.reload(); }

async function loadLlmBadge() {
  if (state.me.role !== 'admin') { $('llm-badge').style.display = 'none'; return; }
  try {
    const j = await API.get('/api/settings/llm');
    $('llm-model').textContent = j.llm.model ? `${j.llm.model}` : 'not set';
  } catch (e) { }
}

// ─── hosts sidebar ────────────────────────────────────────────────────
async function loadHosts() {
  const j = await API.get('/api/hosts');
  state.hosts = j.hosts;
  if (state.activeHost) {
    const cur = state.hosts.find(h => h.id === state.activeHost.id);
    if (cur) { state.activeHost = cur; updateCtxHealth(); }
  }
  renderTagbar(); renderHosts();
}
function updateCtxHealth() {
  const el = $('ctx-health'); const h = state.activeHost;
  if (!el || !h) return;
  if (h.status === 'bad' && (!h.metrics || !Object.keys(h.metrics).length)) { el.innerHTML = '<span class="bad">● unreachable</span>'; return; }
  if (!h.metrics || !Object.keys(h.metrics).length) { el.textContent = ''; return; }
  const m = h.metrics; const c = h.status === 'bad' ? 'bad' : h.status === 'warn' ? 'warn-txt' : 'ok-txt';
  el.innerHTML = `<span class="${c}">●</span> <span class="muted">disk ${m.disk || 0}% · mem ${m.mem || 0}% · up ${Math.floor((m.uptime || 0) / 86400)}d</span>`;
}
function allTags() {
  const s = new Set(); state.hosts.forEach(h => h.tags.forEach(t => s.add(t))); return [...s].sort();
}
function renderTagbar() {
  const tags = allTags();
  $('tagbar').innerHTML = tags.map(t =>
    `<span class="tagf ${state.tagFilter.has(t) ? 'on' : ''}" onclick="toggleTag('${esc(t)}')">${esc(t)}</span>`).join('');
}
function toggleTag(t) { state.tagFilter.has(t) ? state.tagFilter.delete(t) : state.tagFilter.add(t); renderTagbar(); renderHosts(); }
function renderHosts() {
  const q = $('hostq').value.toLowerCase();
  let hs = state.hosts.filter(h => !q || h.name.toLowerCase().includes(q) || h.address.includes(q));
  if (state.tagFilter.size) hs = hs.filter(h => h.tags.some(t => state.tagFilter.has(t)));
  $('hostlist').innerHTML = hs.map(h => {
    const lvl = h.autonomy_level;
    const dotc = ['ok', 'warn', 'bad'].includes(h.status) ? h.status : '';
    const tip = h.issues && h.issues.length ? h.issues.join('; ') : (h.status === 'unknown' || !h.status ? 'no health data yet' : 'healthy');
    return `<div class="host ${state.activeHost && state.activeHost.id === h.id ? 'on' : ''}" onclick="selectHost('${h.id}')">
      <span class="dot ${dotc}" title="${esc(tip)}"></span>
      <div class="host-meta"><b>${esc(h.name)}</b><div class="sub">${esc(h.username || '')}@${esc(h.address)}</div></div>
      <span class="lvl ${lvl}">${lvl}</span>
      <button class="ghost sm" onclick="event.stopPropagation();openHost('${h.id}')" title="edit">✎</button>
    </div>`;
  }).join('') || '<div class="convo muted">No hosts yet. Click + Add.</div>';
}

async function selectHost(id) {
  if (state.shellWs) { try { state.shellWs.close(); } catch (e) { } state.shellWs = null; }
  state.activeHost = state.hosts.find(h => h.id === id);
  renderHosts();
  const h = state.activeHost;
  $('chat-ctx').innerHTML = `Working on <b>${esc(h.name)}</b> <span class="muted">${esc(h.username || '')}@${esc(h.address)}:${h.port} · ${esc(h.autonomy_level)}</span>
    <span id="ctx-health"></span>
    <button class="ghost sm" onclick="testHost('${h.id}')">Test connection</button>
    <button class="ghost sm" onclick="openChanges('${h.id}')">Changes</button>
    <button class="ghost sm" onclick="openHostDoc('${h.id}')">Docs</button>`;
  updateCtxHealth();
  $('term-host').textContent = `${h.name}`;

  // If the user is mid-conversation in a general (no-host) chat, ADOPT it onto
  // this host instead of discarding it — so their in-progress request isn't lost.
  if (state.convo && !state.convo.host_id && chatHasContent()) {
    try { await API.put(`/api/conversations/${state.convo.id}`, { host_id: id }); } catch (e) { }
    state.convo.host_id = id;
    await loadConvos(id);
    addSystemNote(`Now working on ${h.name}. Continue below, or resend your request.`);
    return;
  }
  await loadConvos(id);
  await newConversation(id, true);
}
function chatHasContent() { return !!$('chat').querySelector('.msg, .toolcard, .confirm'); }
function addSystemNote(text) {
  clearEmpty();
  const div = document.createElement('div');
  div.className = 'msg';
  div.innerHTML = `<div class="av" style="background:var(--line)">•</div><div class="body"><p class="muted"></p></div>`;
  div.querySelector('p').textContent = text;
  $('chat').appendChild(div); scrollChat();
}

async function testHost(id) {
  $('chat-ctx').querySelector('button').textContent = 'Testing…';
  try {
    const j = await API.post(`/api/hosts/${id}/test`, {});
    const r = j.result;
    alertModal(r.ok ? 'Connection OK' : 'Connection failed',
      r.ok ? `Reached the host.\n\nOS: ${r.os || 'unknown'}\n${r.uname || ''}` : (r.error || 'unknown error'));
    if (r.ok) loadHosts();
  } catch (e) { alertModal('Error', e.message); }
  const b = $('chat-ctx').querySelector('button'); if (b) b.textContent = 'Test connection';
}

// ─── conversations ────────────────────────────────────────────────────
async function loadConvos(hostId) {
  const j = await API.get('/api/conversations' + (hostId ? `?host_id=${hostId}` : ''));
  state.convos = j.conversations;
  $('convolist').innerHTML = state.convos.map(c =>
    `<div class="convo ${state.convo && state.convo.id === c.id ? 'on' : ''}" onclick="openConvo('${c.id}')">
       <span class="convo-t">${esc(c.title)}</span>
       <button class="convo-del" title="delete conversation" onclick="deleteConvo('${c.id}',event)">×</button>
     </div>`
  ).join('') || '<div class="convo muted">No conversations yet.</div>';
  const clr = $('btn-clear-convos'); if (clr) clr.style.display = state.convos.length ? '' : 'none';
}
async function deleteConvo(id, ev) {
  if (ev) ev.stopPropagation();
  if (!confirm('Delete this conversation? Its messages are removed. Memories, skills, and audit are kept.')) return;
  const hostId = state.convo ? state.convo.host_id : (state.activeHost ? state.activeHost.id : null);
  const wasActive = state.convo && state.convo.id === id;
  try { await API.del(`/api/conversations/${id}`); }
  catch (e) { alertModal("Couldn't delete", e.message); return; }
  if (wasActive) await newConversation(hostId, true);   // resets the chat pane + reloads list
  else await loadConvos(hostId);
}
async function clearConvos() {
  if (!state.convos.length) return;
  if (!confirm(`Delete the ${state.convos.length} conversation(s) in this list? Messages are removed; `
    + `memories, skills, and audit are kept. A conversation with a run in progress is skipped.`)) return;
  const hostId = state.activeHost ? state.activeHost.id : null;
  try {
    const j = await API.post('/api/conversations/clear', { host_id: hostId });
    await newConversation(hostId, true);
    if (j.skipped) alertModal('Cleared', `Deleted ${j.deleted}. Skipped ${j.skipped} with a run in progress.`);
  } catch (e) { alertModal('Error', e.message); }
}
async function newConversation(hostId, silent) {
  const j = await API.post('/api/conversations', { host_id: hostId || null });
  state.convo = { id: j.id, host_id: hostId || null, title: 'New conversation' };
  $('chat').innerHTML = emptyChat();
  await loadConvos(hostId);
}
async function openConvo(id) {
  const j = await API.get(`/api/conversations/${id}`);
  state.convo = j.conversation;
  if (j.conversation.host_id) { const h = state.hosts.find(x => x.id === j.conversation.host_id); if (h) { state.activeHost = h; renderHosts(); } }
  renderMessages(j.messages);
  loadConvos(j.conversation.host_id);
}
function emptyChat() {
  return `<div class="chat-empty"><h2>What would you like to get done?</h2>
    <p class="muted">Describe your goal in plain language — I'll figure out the commands and confirm anything risky.</p></div>`;
}
function renderMessages(msgs) {
  const el = $('chat'); el.innerHTML = '';
  if (!msgs.length) { el.innerHTML = emptyChat(); return; }
  msgs.forEach(m => {
    if (m.role === 'user') addMsg('user', m.content);
    else if (m.role === 'assistant' && m.content) addMsg('assistant', m.content);
    else if (m.role === 'tool') addHistoryTool(m.content);
  });
  scrollChat();
}

// ─── chat rendering ───────────────────────────────────────────────────
function clearEmpty() { const e = $('chat').querySelector('.chat-empty'); if (e) e.remove(); }
// Minimal, XSS-safe markdown renderer (escapes HTML first, then formats a subset).
function renderMarkdown(src) {
  const h = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const inline = (t) => t
    .replace(/`([^`]+)`/g, (m, c) => `<code>${c}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  const lines = String(src || '').replace(/\r\n?/g, '\n').split('\n');
  let out = '', i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {                                  // fenced code
      i++; const code = [];
      while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i++; }
      i++; out += `<pre><code>${h(code.join('\n'))}</code></pre>`; continue;
    }
    if (/\|/.test(line) && i + 1 < lines.length && /^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$/.test(lines[i + 1])) {
      const cells = (r) => r.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => inline(h(c.trim())));
      let t = '<table><thead><tr>' + cells(line).map((c) => `<th>${c}</th>`).join('') + '</tr></thead><tbody>';
      i += 2;
      while (i < lines.length && /\|/.test(lines[i]) && lines[i].trim()) {
        t += '<tr>' + cells(lines[i]).map((c) => `<td>${c}</td>`).join('') + '</tr>'; i++;
      }
      out += t + '</tbody></table>'; continue;
    }
    const hm = line.match(/^(#{1,6})\s+(.*)$/);
    if (hm) { const lv = Math.min(hm[1].length + 2, 6); out += `<h${lv}>${inline(h(hm[2]))}</h${lv}>`; i++; continue; }
    if (/^\s*([-*+]|\d+[.)])\s+/.test(line)) {                 // list
      const ordered = /^\s*\d/.test(line); const items = [];
      while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i])) {
        items.push(inline(h(lines[i].replace(/^\s*([-*+]|\d+[.)])\s+/, '')))); i++;
      }
      out += `<${ordered ? 'ol' : 'ul'}>` + items.map((x) => `<li>${x}</li>`).join('') + `</${ordered ? 'ol' : 'ul'}>`;
      continue;
    }
    if (/^\s*>\s?/.test(line)) {                               // blockquote
      const q = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) { q.push(inline(h(lines[i].replace(/^\s*>\s?/, '')))); i++; }
      out += `<blockquote>${q.join('<br>')}</blockquote>`; continue;
    }
    if (/^\s*(---+|\*\*\*+)\s*$/.test(line)) { out += '<hr>'; i++; continue; }
    if (line.trim() === '') { i++; continue; }
    const para = [];                                          // paragraph
    while (i < lines.length && lines[i].trim() && !/^```|^\s*([-*+]|\d+[.)])\s+|^#{1,6}\s|^\s*>/.test(lines[i])) {
      para.push(inline(h(lines[i]))); i++;
    }
    out += `<p>${para.join('<br>')}</p>`;
  }
  return out;
}

function addMsg(role, content) {
  clearEmpty();
  const div = document.createElement('div');
  div.className = `msg ${role}`;
  div.innerHTML = `<div class="av">${role === 'user' ? 'U' : 'N'}</div>
    <div class="body"><div class="who">${role === 'user' ? esc(state.me.username) : 'Nexus'}</div><div class="content md"></div></div>`;
  const c = div.querySelector('.content');
  if (role === 'assistant') { c._raw = content || ''; c.innerHTML = renderMarkdown(c._raw); }
  else { c.textContent = content; }
  $('chat').appendChild(div); scrollChat();
  return c;
}
function addHistoryTool(content) {
  clearEmpty();
  const div = document.createElement('div');
  div.className = 'toolcard';
  div.innerHTML = `<div class="tc-h"><span class="tc-name mono">ssh_exec</span></div><div class="tc-out"></div>`;
  div.querySelector('.tc-out').textContent = content;
  $('chat').appendChild(div);
}
function scrollChat() { const c = $('chat'); c.scrollTop = c.scrollHeight; }

// ─── send + stream ────────────────────────────────────────────────────
function composerKey(e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }
function autogrow(t) { t.style.height = 'auto'; t.style.height = Math.min(t.scrollHeight, 180) + 'px'; }

async function send() {
  if (state.streaming) return;
  const text = $('composer').value.trim();
  if (!text) return;
  if (!state.convo) await newConversation(state.activeHost ? state.activeHost.id : null, true);
  addMsg('user', text);
  $('composer').value = ''; autogrow($('composer'));
  setStreaming(true);
  state.assistantEl = null;
  try {
    const j = await API.post('/api/agent/send', { conversation_id: state.convo.id, message: text });
    state.runId = j.run_id;
    openStream(j.run_id);
  } catch (e) { addMsg('assistant', '[error] ' + e.message); setStreaming(false); }
}

function openStream(runId) {
  if (state.es) state.es.close();
  const es = new EventSource(`/api/agent/stream/${runId}`);
  state.es = es;
  es.onmessage = (ev) => { try { handleEvent(JSON.parse(ev.data)); } catch (e) { } };
  es.onerror = () => { if (state.streaming) { /* keep-alive gaps are normal */ } };
}

function handleEvent(ev) {
  switch (ev.type) {
    case 'token':
      if (!state.assistantEl) state.assistantEl = addMsg('assistant', '');
      state.assistantEl._raw += ev.text;
      state.assistantEl.innerHTML = renderMarkdown(state.assistantEl._raw);
      scrollChat(); break;
    case 'message':
      if (!state.assistantEl) state.assistantEl = addMsg('assistant', ev.content);
      else { state.assistantEl._raw = ev.content; state.assistantEl.innerHTML = renderMarkdown(ev.content); }
      state.assistantEl = null; break;
    case 'tool_call': addToolCard(ev); break;
    case 'tool_output': appendToolOut(ev.call_id, ev.chunk); appendTerm(ev.chunk); break;
    case 'tool_result': finishToolCard(ev); break;
    case 'confirm_request': addConfirm(ev); break;
    case 'plan_request': addPlan(ev); break;
    case 'plan_result': finishPlan(ev); break;
    case 'envelope_run': markEnvelopeRun(ev); break;
    case 'error': addMsg('assistant', '⚠ ' + ev.message); break;
    case 'done': setStreaming(false); if (state.es) { state.es.close(); state.es = null; } refreshConvoTitle(); break;
  }
}

function setStreaming(on) {
  state.streaming = on;
  $('send-btn').style.display = on ? 'none' : '';
  $('stop-btn').style.display = on ? '' : 'none';
}
async function stopRun() { if (state.runId) { try { await API.post('/api/agent/stop', { run_id: state.runId }); } catch (e) { } } }

async function refreshConvoTitle() {
  // the server names a conversation after its first user message; reload the
  // list so the new title shows (works for host and general/no-host chats).
  loadConvos(state.convo ? state.convo.host_id : (state.activeHost ? state.activeHost.id : null));
}

// tool cards
function addToolCard(ev) {
  clearEmpty();
  state.assistantEl = null;
  const div = document.createElement('div');
  div.className = `toolcard ${ev.risk}`;
  div.id = `tc-${ev.call_id}`;
  const cmd = ev.args && ev.args.command ? ev.args.command : JSON.stringify(ev.args || {});
  const sudo = ev.args && ev.args.sudo ? ' <span class="muted">(sudo)</span>' : '';
  // flag when the agent targets a DIFFERENT host than the active one
  const onHost = ev.host && (!state.activeHost || ev.host !== state.activeHost.name)
    ? ` <span class="tc-badge caution">on ${esc(ev.host)}</span>` : '';
  div.innerHTML = `<div class="tc-h" onclick="this.parentNode.querySelector('.tc-out').classList.toggle('collapsed')">
      <span class="tc-name mono">${esc(ev.tool)}</span>${sudo}${onHost}
      <span class="spacer"></span><span class="tc-badge ${ev.risk}">${ev.risk}</span></div>
    <div class="tc-cmd"></div>
    <div class="tc-out"></div>`;
  div.querySelector('.tc-cmd').textContent = cmd;
  $('chat').appendChild(div); scrollChat();
  state.toolCards[ev.call_id] = div;
}
function appendToolOut(callId, chunk) {
  const div = state.toolCards[callId]; if (!div) return;
  div.querySelector('.tc-out').textContent += chunk; scrollChat();
}
function finishToolCard(ev) {
  const div = state.toolCards[ev.call_id]; if (!div) return;
  const s = document.createElement('div');
  s.className = `tc-status ${ev.ok ? 'ok' : 'bad'}`;
  const hasExit = ev.exit_code !== null && ev.exit_code !== undefined;
  s.textContent = ev.ok
    ? (hasExit ? `✓ exit ${ev.exit_code}` : '✓ done')
    : `✗ ${ev.error || (hasExit ? 'exit ' + ev.exit_code : 'failed')}`;
  div.appendChild(s); scrollChat();
}

// confirm cards
function addConfirm(ev) {
  state.assistantEl = null;
  const div = document.createElement('div');
  div.className = `confirm ${ev.risk}`;
  div.id = `cf-${ev.call_id}`;
  div.innerHTML = `<h3>Approval needed — ${esc(ev.risk)} action${ev.host ? ` on <span class="warn-txt">${esc(ev.host)}</span>` : ''}</h3>
    <div class="why">${esc(ev.explanation)}${ev.sudo ? ' Runs as <b>root</b>.' : ''}</div>
    <div class="cmd" id="cf-cmd-${ev.call_id}"></div>
    <textarea id="cf-edit-${ev.call_id}" style="display:none" rows="2"></textarea>
    <div class="acts">
      <button class="ok" onclick="decide('${ev.call_id}','approve')">Approve</button>
      <button class="ghost" onclick="decide('${ev.call_id}','approve_session')">Approve &amp; don't ask again</button>
      <button class="ghost" onclick="editCmd('${ev.call_id}')">Edit</button>
      <button class="danger" onclick="decide('${ev.call_id}','deny')">Deny</button>
    </div>`;
  $('chat').appendChild(div);
  $(`cf-cmd-${ev.call_id}`).textContent = ev.command;
  div.dataset.command = ev.command;
  scrollChat();
}
function editCmd(id) {
  const div = $(`cf-${id}`); const ta = $(`cf-edit-${id}`);
  $(`cf-cmd-${id}`).style.display = 'none';
  ta.style.display = 'block'; ta.value = div.dataset.command; ta.focus();
}
async function decide(id, decision) {
  const div = $(`cf-${id}`); const ta = $(`cf-edit-${id}`);
  const command = ta && ta.style.display !== 'none' ? ta.value : div.dataset.command;
  div.querySelectorAll('button').forEach(b => b.disabled = true);
  div.querySelector('.acts').innerHTML = `<span class="muted">${decision === 'deny' ? 'Denied' : 'Approved'}</span>`;
  try { await API.post('/api/agent/confirm', { run_id: state.runId, call_id: id, decision, command }); }
  catch (e) { }
}

// plan cards — approve the whole task once, instead of every command in it
const CEILING_WORDS = {
  safe: 'only look at things, changing nothing',
  caution: 'install software and write configuration files',
  risky: 'also restart services, change the firewall/users, and delete files',
};
function addPlan(ev) {
  state.assistantEl = null;
  clearEmpty();
  const div = document.createElement('div');
  div.className = `confirm plan ${ev.ceiling}`;
  div.id = `pl-${ev.call_id}`;
  const steps = (ev.steps || []).map(s => `<li>${esc(s)}</li>`).join('');
  const where = (ev.hosts || []).length ? ` on <span class="warn-txt">${esc(ev.hosts.join(', '))}</span>` : '';
  const allow = (ev.allow || []).length
    ? `<div class="why">Also pre-approving by name: ${(ev.allow).map(a => `<code>${esc(a)}</code>`).join(', ')}</div>` : '';
  div.innerHTML = `<h3>Plan — approve once${where}</h3>
    <div class="plan-summary">${esc(ev.summary)}</div>
    ${steps ? `<ol class="plan-steps">${steps}</ol>` : ''}
    ${ev.risk_note ? `<div class="why">⚠ ${esc(ev.risk_note)}</div>` : ''}
    <div class="why">If you approve, it will work without asking again, up to
      <b>${esc(ev.ceiling)}</b> — it may ${esc(CEILING_WORDS[ev.ceiling] || 'act within that level')}.
      Reboots, disk formatting and mass deletion still ask separately.</div>
    ${allow}
    <div class="acts">
      <button class="ok" onclick="decidePlan('${ev.call_id}','approve')">Approve plan</button>
      <button class="danger" onclick="decidePlan('${ev.call_id}','deny')">Not this way</button>
    </div>`;
  $('chat').appendChild(div); scrollChat();
}
async function decidePlan(id, decision) {
  const div = $(`pl-${id}`);
  div.querySelectorAll('button').forEach(b => b.disabled = true);
  div.querySelector('.acts').innerHTML =
    `<span class="muted">${decision === 'deny' ? 'Declined' : 'Approved — working…'}</span>`;
  try { await API.post('/api/agent/confirm', { run_id: state.runId, call_id: id, decision }); }
  catch (e) { }
}
function finishPlan(ev) {
  if (!ev.approved) return;
  state.envelope = ev.ceiling;
  const b = $('envelope-badge');
  if (b) { b.textContent = `plan approved · up to ${ev.ceiling}`; b.style.display = ''; }
}
function markEnvelopeRun(ev) {
  // show WHY a risky step didn't stop to ask — it was inside the approved plan
  const div = state.toolCards[ev.call_id]; if (!div) return;
  const tag = document.createElement('span');
  tag.className = 'tc-badge envelope';
  tag.textContent = 'in plan';
  const h = div.querySelector('.tc-h'); if (h) h.appendChild(tag);
}

// ─── terminal pane (xterm.js) ─────────────────────────────────────────
function ensureTerm() {
  if (state.term) return state.term;
  const term = new Terminal({
    convertEol: true, fontSize: 12, cursorBlink: true,
    fontFamily: 'ui-monospace,Menlo,Consolas,monospace',
    theme: { background: '#0d0e10', foreground: '#cdd0d4' },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit); term.open($('term')); fit.fit();
  term.onData(d => { if (state.shellWs && state.shellWs.readyState === 1) state.shellWs.send(d); });
  window.addEventListener('resize', () => { try { fit.fit(); sendResize(); } catch (e) { } });
  state.term = term; state.fit = fit;
  return term;
}
function fitSoon() { setTimeout(() => { try { state.fit.fit(); sendResize(); } catch (e) { } }, 40); }
function toggleTerm() {
  const col = $('termcol'); col.classList.toggle('hidden');
  if (!col.classList.contains('hidden')) { ensureTerm(); fitSoon(); }
}
function appendTerm(chunk) {
  if ($('termcol').classList.contains('hidden')) return;
  ensureTerm().write(chunk);
}
function sendResize() {
  if (state.shellWs && state.shellWs.readyState === 1 && state.term)
    state.shellWs.send(JSON.stringify({ resize: { cols: state.term.cols, rows: state.term.rows } }));
}
function openShell() {
  if (state.shellWs) { try { state.shellWs.close(); } catch (e) { } state.shellWs = null; return; }
  if (!state.activeHost) { alertModal('No host', 'Pick a host in the sidebar first.'); return; }
  $('termcol').classList.remove('hidden');
  const term = ensureTerm(); fitSoon();
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/api/hosts/${state.activeHost.id}/shell`);
  state.shellWs = ws;
  term.write(`\r\n\x1b[33mconnecting to ${state.activeHost.name}…\x1b[0m\r\n`);
  ws.onopen = () => { $('shell-btn').textContent = 'Close shell'; fitSoon(); };
  ws.onmessage = (e) => term.write(e.data);
  ws.onclose = () => { term.write('\r\n\x1b[31m[session closed]\x1b[0m\r\n'); $('shell-btn').textContent = 'Open shell'; state.shellWs = null; };
  ws.onerror = () => { term.write('\r\n\x1b[31m[connection error]\x1b[0m\r\n'); };
}

boot();
