"""Telegram bridge — command the agent from your phone, from anywhere.

The bot long-polls Telegram's servers (outbound only — nothing on your network is
exposed, no VPN or open port needed). Authorized users send plain-language
instructions; the bot drives the same agent core as the web UI and renders the
risk-approval gate as inline Approve/Deny buttons. Monitoring alerts and job
reports are pushed to the same chat.

Only ONE running instance should own a given bot token (two pollers would steal
each other's updates). Configure it on a single instance.
"""
import secrets as _secrets
import threading
import time

import requests

import logs
from store import db, settings

log = logs.get('telegram')

_started = False
_lock = threading.Lock()
_pending = {}            # short token -> ('run', run_id, call_id) | ('defer', deferred_id)
_chat_host = {}          # chat_id -> host_id (the chat's "selected host", set via /use)
_offset = 0

API = 'https://api.telegram.org/bot{token}/{method}'


def _cfg():
    return settings.get_telegram()


def _post(method, **params):
    c = _cfg()
    if not c.get('token'):
        return None
    try:
        r = requests.post(API.format(token=c['token'], method=method), json=params, timeout=40)
        return r.json()
    except requests.RequestException:
        return None


def send(chat_id, text, reply_markup=None):
    p = {'chat_id': chat_id, 'text': text[:4000], 'parse_mode': 'Markdown',
         'disable_web_page_preview': True}
    if reply_markup:
        p['reply_markup'] = reply_markup
    return _post('sendMessage', **p)


def push(text, reply_markup=None):
    """Send a message to every authorized user (used for alerts + job reports)."""
    c = _cfg()
    if not c.get('enabled') or not c.get('token'):
        return
    for uid in c.get('whitelist', []):
        send(uid, text, reply_markup)


def push_deferred(did, command, risk):
    """Push a scheduled-job deferred action to authorized users with Approve/Deny."""
    c = _cfg()
    if not c.get('enabled') or not c.get('token'):
        return
    for uid in c.get('whitelist', []):
        send(uid, f"⚠ *A scheduled job needs approval* ({risk}):\n`{command}`",
             _approve_kb(_token(('defer', did), uid), session=False))


def _authorized(uid):
    return str(uid) in [str(x) for x in _cfg().get('whitelist', [])]


def _app_user():
    """The app identity the bot acts as (its role/scope govern what it can do)."""
    uname = _cfg().get('act_as') or ''
    rec = db.query_one('SELECT * FROM users WHERE username=?', (uname,)) if uname else None
    if not rec:
        rec = db.query_one('SELECT * FROM users WHERE role="admin" ORDER BY created_at LIMIT 1')
    return dict(rec) if rec else None


TOKEN_TTL = 3600      # an approval button goes stale after an hour
MAX_PENDING = 500     # bound the map — one chat can't grow it without limit


def _token(payload, chat=None):
    """Mint an approval token BOUND to the chat it was sent to.

    Unbound, immortal tokens meant any whitelisted user could approve any run
    (including one started by someone else in the web UI), forever.
    """
    _prune_tokens()
    t = _secrets.token_hex(8)
    _pending[t] = {'payload': payload, 'chat': chat, 'ts': time.time()}
    return t


def _prune_tokens():
    now = time.time()
    for t in [t for t, p in list(_pending.items()) if now - p['ts'] > TOKEN_TTL]:
        _pending.pop(t, None)
    if len(_pending) > MAX_PENDING:
        for t, _ in sorted(_pending.items(), key=lambda kv: kv[1]['ts'])[:len(_pending) - MAX_PENDING]:
            _pending.pop(t, None)


def _take_token(tok, chat):
    """Consume a token, but only from the chat it was issued to."""
    _prune_tokens()
    p = _pending.get(tok)
    if not p:
        return None
    if p['chat'] is not None and str(p['chat']) != str(chat):
        return None
    _pending.pop(tok, None)
    return p['payload']


def _approve_kb(tok, session=True):
    rows = [[{'text': '✅ Approve', 'callback_data': 'a:' + tok},
             {'text': '⛔ Deny', 'callback_data': 'd:' + tok}]]
    if session:
        rows.append([{'text': 'Approve for this task', 'callback_data': 's:' + tok}])
    return {'inline_keyboard': rows}


# ─── polling ──────────────────────────────────────────────────────────
def start_bridge():
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_poll_loop, daemon=True).start()


def _poll_loop():
    global _offset
    while True:
        c = _cfg()
        if not c.get('enabled') or not c.get('token'):
            time.sleep(5)
            continue
        try:
            r = requests.get(API.format(token=c['token'], method='getUpdates'),
                             params={'offset': _offset, 'timeout': 30}, timeout=40).json()
            for u in r.get('result', []):
                _offset = u['update_id'] + 1
                threading.Thread(target=_handle, args=(u,), daemon=True).start()
        except requests.RequestException:
            time.sleep(3)
        except Exception:  # noqa: BLE001 — never let the poll loop die
            time.sleep(3)


def _handle(u):
    try:
        if 'callback_query' in u:
            return _handle_callback(u['callback_query'])
        m = u.get('message') or u.get('edited_message')
        if not m or 'text' not in m:
            return
        uid, chat, text = m['from']['id'], m['chat']['id'], m['text'].strip()
        if not _authorized(uid):
            send(chat, f"Not authorized. Your Telegram ID is `{uid}` — add it in "
                       "the app under Settings → Telegram to grant access.")
            return
        if text.startswith('/'):
            return _command(chat, text)
        _run_agent(chat, text)
    except Exception:  # noqa: BLE001 — one bad update must not kill the bridge
        log.exception('telegram update handler failed')


def _resolve_host(name, user):
    for h in inventory_list(user):
        if h['id'] == name or h['name'].lower() == name.lower():
            from store import db as _db
            return _db.query_one('SELECT * FROM hosts WHERE id=?', (h['id'],))
    return None


def inventory_list(user):
    import inventory
    return inventory.list_for_user(user)


def _command(chat, text):
    import inventory
    cmd = text.split()[0].lower()
    if cmd in ('/start', '/help'):
        send(chat, "*Nexus Sysadmin*\nSend an instruction and I'll act on your hosts, asking "
                   "before anything risky.\nExamples:\n_check disk usage on naa-lamp1_\n_on db01, "
                   "restart nginx_\n\n/use `<host>` — work on a host by default (like the sidebar)\n"
                   "/hosts — your hosts\n/jobs — scheduled jobs\n/approvals — pending approvals\n"
                   "/whoami — your id")
    elif cmd == '/use':
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            cur = _chat_host.get(chat)
            name = None
            if cur:
                rec = _resolve_host(cur, _app_user())
                name = rec['name'] if rec else None
            send(chat, (f"Currently working on *{name}*." if name else "No default host set.") +
                 " Use `/use <host>` to set one, or `/use none` to clear. /hosts to list.")
        elif parts[1].strip().lower() in ('none', 'clear', 'off'):
            _chat_host.pop(chat, None)
            send(chat, "Cleared — no default host. Name a host in your message, e.g. _on web01, …_")
        else:
            rec = _resolve_host(parts[1].strip(), _app_user())
            if rec:
                _chat_host[chat] = rec['id']
                send(chat, f"Now working on *{rec['name']}* ({rec['address']}). Just tell me what to do.")
            else:
                send(chat, f"No host named _{parts[1].strip()}_. /hosts to list them.")
    elif cmd == '/hosts':
        hs = inventory.list_for_user(_app_user())
        cur = _chat_host.get(chat)
        body = '\n'.join((f"{'▸ ' if h['id'] == cur else '• '}*{h['name']}* ({h['address']}) — "
                          f"{h.get('status', '?')}") for h in hs)
        send(chat, "*Hosts* (▸ = current)\n" + (body or "_none_") + "\n\n_/use <name>_ to work on one.")
    elif cmd == '/jobs':
        import schedule
        js = schedule.list_all()
        body = '\n'.join(f"• *{j['name']}* — `{j['schedule']}` — {j['last_status'] or 'never run'}"
                         for j in js)
        send(chat, "*Scheduled jobs*\n" + (body or "_none_"))
    elif cmd == '/approvals':
        import schedule
        pend = schedule.list_deferred('pending')
        if not pend:
            send(chat, "No pending approvals ✅")
            return
        for a in pend[:10]:
            tok = _token(('defer', a['id']), chat)
            send(chat, f"⚠ *Deferred* ({a['risk']}):\n`{a['command']}`",
                 _approve_kb(tok, session=False))
    elif cmd == '/whoami':
        send(chat, "You're authorized. The bot acts as app user "
                   f"*{(_app_user() or {}).get('username', '?')}*.")
    else:
        send(chat, "Unknown command — /help")


def _run_agent(chat, text):
    from agent import core
    import inventory
    user = _app_user()
    if not user:
        send(chat, "No app user configured for the bot.")
        return
    # the chat's default host (set via /use) acts like the web sidebar selection;
    # the agent can still target other hosts by name via multi-host.
    host = secrets = None
    host_id = _chat_host.get(chat)
    if host_id:
        rec = db.query_one('SELECT * FROM hosts WHERE id=?', (host_id,))
        if rec:
            host = dict(rec)
            secrets = inventory.secrets_for(rec)
    cid = _secrets.token_hex(8)
    now = _now()
    db.execute('INSERT INTO conversations(id, host_id, user_id, title, created_at, updated_at)'
               ' VALUES(?,?,?,?,?,?)', (cid, host_id, user['id'], core.derive_title(text), now, now))
    db.execute('INSERT INTO messages(conversation_id, role, content, created_at) VALUES(?,?,?,?)',
               (cid, 'user', text, now))
    run = core.start({'id': cid, 'host_id': host_id}, host, secrets, user)
    send(chat, "…working" + (f" on *{host['name']}*" if host else ''))
    while True:
        try:
            ev = run.q.get(timeout=1200)
        except Exception:  # noqa: BLE001 — timeout
            break
        t = ev['type']
        if t == 'message' and ev.get('content'):
            send(chat, ev['content'])
        elif t == 'tool_call':
            cmd = (ev.get('args') or {}).get('command') or ev['tool']
            on = f" on *{ev['host']}*" if ev.get('host') else ''
            send(chat, f"⚙ `{cmd}`{on}")
        elif t == 'plan_request':
            tok = _token(('run', run.id, ev['call_id']), chat)
            steps = '\n'.join(f"{i}. {s}" for i, s in enumerate(ev.get('steps') or [], 1))
            where = f" on *{', '.join(ev['hosts'])}*" if ev.get('hosts') else ''
            note = f"\n⚠ _{ev['risk_note']}_" if ev.get('risk_note') else ''
            send(chat, f"📋 *Plan*{where}\n{ev.get('summary', '')}\n\n{steps}{note}\n\n"
                       f"_Approve once and I'll work up to *{ev.get('ceiling')}* without asking "
                       "again. Reboots and disk formatting still ask separately._",
                 {'inline_keyboard': [[{'text': '✅ Approve plan', 'callback_data': 'a:' + tok},
                                       {'text': '⛔ Not this way', 'callback_data': 'd:' + tok}]]})
        elif t == 'plan_result':
            if ev.get('approved'):
                send(chat, f"👍 Working — approved up to *{ev.get('ceiling')}*.")
        elif t == 'confirm_request':
            tok = _token(('run', run.id, ev['call_id']), chat)
            on = f" on *{ev['host']}*" if ev.get('host') else ''
            send(chat, f"⚠ *Approval needed* ({ev['risk']}){on}\n`{ev['command']}`\n"
                       f"_{ev.get('explanation', '')}_", _approve_kb(tok))
        elif t == 'error':
            send(chat, "⚠ " + ev['message'])
        elif t == 'done':
            break
    core.cleanup(run.id)


def _handle_callback(cq):
    cqid, chat = cq['id'], cq['message']['chat']['id']
    uid, data = cq['from']['id'], cq.get('data', '')
    if not _authorized(uid):
        _post('answerCallbackQuery', callback_query_id=cqid, text='not authorized')
        return
    action, _, tok = data.partition(':')
    payload = _take_token(tok, chat)
    if not payload:
        _post('answerCallbackQuery', callback_query_id=cqid, text='expired')
        return
    from agent import core
    if payload[0] == 'run':
        _, run_id, call_id = payload
        decision = {'a': 'approve', 'd': 'deny', 's': 'approve_session'}.get(action, 'deny')
        if not core.confirm(run_id, call_id, decision, user=_app_user()):
            _post('answerCallbackQuery', callback_query_id=cqid, text='no longer pending')
            return
        label = '✅ approved' if decision != 'deny' else '⛔ denied'
    else:  # deferred approval
        _, did = payload
        import schedule
        if action == 'd':
            schedule.deny_deferred(did, _app_user())
            label = '⛔ denied'
        else:
            r = schedule.approve_deferred(did, _app_user())
            label = '✅ approved & ran' if r.get('ok') else f"⚠ {r.get('error', 'failed')}"
    _post('answerCallbackQuery', callback_query_id=cqid, text=label)
    _post('editMessageReplyMarkup', chat_id=chat, message_id=cq['message']['message_id'],
          reply_markup={'inline_keyboard': [[{'text': label, 'callback_data': 'x'}]]})


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
