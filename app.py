"""Nexus Admin Assistant — Flask app.

Thin wiring layer: auth, users, inventory, LLM settings, conversations, and the
agent (send / SSE stream / confirm / stop). Logic lives in the tested modules
(auth, inventory, agent/*, store/*).
"""
import json
import os
import queue
import secrets as _secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, g, jsonify, request, send_from_directory, session
from flask_sock import Sock

import auth
import changes
import config
import inventory
import logs
import memory
import monitor
import schedule
import services
import skills
import telegrambot
from agent import core, llm
from agent.tools import ssh as sshtool
from store import db, settings

app = Flask(__name__, static_folder='static', template_folder='templates')
sock = Sock(app)
log = logs.get('web')


def _now():
    return datetime.now(timezone.utc).isoformat()


def err(msg, code=400):
    return jsonify({'success': False, 'error': msg}), code


def ok(**kw):
    return jsonify({'success': True, **kw})


def boot(background=True):
    """Wire up storage + settings; start background workers unless told not to.

    Importing this module must NOT have side effects — it used to call boot() at
    import time, which created a database and an admin user and spawned the
    scheduler, monitor and Telegram pollers merely because something imported
    `app` (that is why the route tests never existed). The entrypoints call this
    explicitly; tests call boot(background=False).
    """
    config.load()
    db.configure(config.DB_FILE)
    auth.ensure_admin()
    memory.ensure_mission()
    app.secret_key = config.secret_key()
    app.permanent_session_lifetime = timedelta(hours=12)
    # session cookie hardening: never readable from JS, never sent cross-site,
    # and TLS-only when we're actually serving HTTPS
    app.config.update(SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Lax',
                      SESSION_COOKIE_SECURE=bool(config.TLS))
    if background:
        _single_instance_guard()
        schedule.start_scheduler()
        monitor.start_monitor()
        services.start_checker()
        telegrambot.start_bridge()
    return app


def _single_instance_guard():
    """SQLite access here assumes ONE process (store.db serializes writes on a
    process-local lock, and the scheduler/monitor/Telegram pollers must be
    singletons). That was documented in comments only; make a second worker fail
    loudly instead of silently double-running every job."""
    import fcntl
    lock_path = os.path.join(config.DATA_DIR, 'naa.lock')
    fh = open(lock_path, 'w')  # noqa: SIM115 — held for the process lifetime
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit(
            f'Another Nexus Admin Assistant process holds {lock_path}.\n'
            'Run a SINGLE worker (gunicorn -w 1 --threads N): the scheduler, '
            'monitor and Telegram poller must not be duplicated.')
    fh.write(str(os.getpid()))
    fh.flush()
    globals()['_instance_lock'] = fh  # keep the fd alive


# ─── CSRF ─────────────────────────────────────────────────────────────
# Every mutating route is a cookie-authenticated JSON call, so a cross-origin
# form post could drive the agent as the logged-in user. Enforce a token that
# only same-origin JS can read (double-submit against the session).
CSRF_HEADER = 'X-CSRF-Token'
_CSRF_EXEMPT = {'api_login'}          # no session yet; nothing to forge with


@app.before_request
def _csrf_protect():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None
    if request.endpoint in _CSRF_EXEMPT:
        return None
    if not session.get('uid'):
        return None                    # unauthenticated: nothing to abuse
    token = session.get('csrf')
    sent = request.headers.get(CSRF_HEADER, '')
    if not token or not _secrets.compare_digest(str(token), str(sent)):
        return err('CSRF token missing or invalid', 403)
    return None


def _same_origin(req):
    """True when a WebSocket handshake came from our own page. flask_sock does
    not check Origin, and the socket hands out a live root PTY — a cross-site
    connection from a logged-in browser would be a full host takeover."""
    origin = req.headers.get('Origin')
    if not origin:
        return True            # non-browser client (no cookie auth to steal)
    host = req.headers.get('Host', '')
    return origin.split('://', 1)[-1].lower() == host.lower()


# ─── static / index ───────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')


# ─── auth ─────────────────────────────────────────────────────────────
# Brute-force damping: failures were neither rate-limited nor recorded, so an
# attempt run was both unimpeded and invisible.
_LOGIN_FAILS = {}          # remote_addr -> [count, first_ts]
LOGIN_MAX_FAILS = 8
LOGIN_WINDOW = 60


def _login_fail(addr, username):
    ent = _LOGIN_FAILS.get(addr)
    now = time.time()
    if not ent or now - ent[1] > LOGIN_WINDOW:
        ent = [0, now]
    ent[0] += 1
    _LOGIN_FAILS[addr] = ent
    log.warning('login failed user=%r from=%s (%d in window)', username, addr, ent[0])


def _login_blocked(addr):
    ent = _LOGIN_FAILS.get(addr)
    if not ent:
        return False
    if time.time() - ent[1] > LOGIN_WINDOW:
        _LOGIN_FAILS.pop(addr, None)
        return False
    return ent[0] >= LOGIN_MAX_FAILS


@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.get_json(force=True, silent=True) or {}
    if _login_blocked(request.remote_addr):
        return err('too many failed attempts — wait a minute and try again', 429)
    rec = auth.authenticate(d.get('username', ''), d.get('password', ''))
    if not rec:
        _login_fail(request.remote_addr, d.get('username', ''))
        return err('invalid credentials', 401)
    log.info('login ok user=%s from=%s', rec['username'], request.remote_addr)
    auth.login_session(rec)
    session['csrf'] = _secrets.token_urlsafe(32)
    _LOGIN_FAILS.pop(request.remote_addr, None)
    return ok(user=auth.public_user(rec), csrf=session['csrf'])


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return ok()


@app.route('/api/me')
def api_me():
    rec = auth.current_user()
    if not rec:
        return err('auth required', 401)
    if not session.get('csrf'):        # session predates CSRF (or was restored)
        session['csrf'] = _secrets.token_urlsafe(32)
    return ok(user=auth.public_user(rec), csrf=session['csrf'])


@app.route('/api/change-password', methods=['POST'])
@auth.require_login
def api_change_password():
    d = request.get_json(force=True, silent=True) or {}
    new = d.get('new_password', '')
    if len(new) < 6:
        return err('password too short (min 6)')
    if not auth.authenticate(g.user['username'], d.get('old_password', '')):
        return err('current password is wrong')
    auth.set_password(g.user['id'], new, must_change=False)
    return ok()


# ─── users (admin) ────────────────────────────────────────────────────
@app.route('/api/users')
@auth.require_admin
def api_users():
    return ok(users=auth.list_users())


@app.route('/api/users', methods=['POST'])
@auth.require_admin
def api_users_create():
    d = request.get_json(force=True, silent=True) or {}
    try:
        auth.create_user(d['username'], d.get('password') or _secrets.token_urlsafe(10),
                         d.get('role', 'operator'), d.get('tags', []))
    except (KeyError, ValueError) as e:
        return err(str(e))
    return ok()


@app.route('/api/users/<uid>', methods=['PUT'])
@auth.require_admin
def api_users_update(uid):
    d = request.get_json(force=True, silent=True) or {}
    try:
        if 'password' in d and d['password']:
            auth.set_password(uid, d['password'], must_change=True)
        auth.update_user(uid, role=d.get('role'), tags=d.get('tags'))
    except ValueError as e:
        return err(str(e))
    return ok()


@app.route('/api/users/<uid>', methods=['DELETE'])
@auth.require_admin
def api_users_delete(uid):
    if uid == g.user['id']:
        return err('cannot delete yourself')
    try:
        auth.delete_user(uid)
    except ValueError as e:
        return err(str(e))
    return ok()


# ─── hosts / inventory ────────────────────────────────────────────────
@app.route('/api/hosts')
@auth.require_login
def api_hosts():
    hosts = inventory.list_for_user(g.user)
    for h in hosts:
        snap = monitor.snapshot(h['id'])
        if snap:
            h['status'] = snap['status']
            h['issues'] = [t for _, t in snap['issues']]
            h['metrics'] = snap['metrics']
        else:
            h['status'] = 'unknown'
            h['issues'] = []
    return ok(hosts=hosts)


@app.route('/api/hosts/<hid>/health')
@auth.require_login
def api_host_health(hid):
    if not inventory.find_for_user(hid, g.user):
        return err('not found', 404)
    snap = monitor.snapshot(hid)
    rows = db.query('SELECT ts, reachable, cpu, mem, disk, load1 FROM host_metrics '
                    'WHERE host_id=? ORDER BY id DESC LIMIT 60', (hid,))
    return ok(snapshot=snap, history=list(reversed(rows)))


@app.route('/api/hosts/<hid>/poll', methods=['POST'])
@auth.require_operator
def api_host_poll(hid):
    rec = inventory.find_for_user(hid, g.user)
    if not rec:
        return err('not found', 404)
    return ok(snapshot=monitor.poll_host(rec))


@app.route('/api/hosts/<hid>/doc')
@auth.require_login
def api_host_doc(hid):
    if not inventory.find_for_user(hid, g.user):
        return err('not found', 404)
    return ok(**inventory.get_doc(hid))


@app.route('/api/hosts/<hid>/doc', methods=['PUT'])
@auth.require_operator
def api_host_doc_set(hid):
    if not inventory.find_for_user(hid, g.user):
        return err('not found', 404)
    inventory.set_doc(hid, (request.get_json(force=True, silent=True) or {}).get('doc', ''))
    return ok()


@app.route('/api/hosts/<hid>/provision-key', methods=['POST'])
@auth.require_operator
def api_provision_key(hid):
    """Generate an Ed25519 keypair, deploy the pubkey over current creds, and
    switch the host to key auth."""
    import provision
    from agent.tools import ssh as sshmod
    rec = inventory.find_for_user(hid, g.user)
    if not rec:
        return err('not found', 404)
    d = request.get_json(force=True, silent=True) or {}
    secrets = inventory.secrets_for(rec)
    if not (secrets.get('password') or secrets.get('ssh_key')):
        return err('the host needs a password or an existing key to deploy a new one')
    priv, pub = provision.gen_ed25519(f"naa-{rec['name']}")
    dep = provision.deploy_pubkey(rec, secrets, pub)
    if 'KEY_INSTALLED' not in (dep.get('output') or ''):
        return err(f"key deploy failed: {dep.get('error') or (dep.get('output') or '')[:200]}")
    test = sshmod.test_connection(rec, {'username': rec['username'], 'ssh_key': priv})
    if not test['ok']:
        return err(f"key deployed but key-auth test failed: {test.get('error')}")
    inventory.update(hid, {'ssh_key': priv})   # switch the host to the new key
    result = {'os': test['os'], 'pub': pub}
    if d.get('nopasswd_sudo'):
        s = provision.setup_nopasswd_sudo(rec, secrets, rec['username'])
        result['nopasswd_sudo'] = 'SUDO_OK' in (s.get('output') or '')
    inventory.touch(hid)
    db.execute('INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
               ' VALUES(?,?,?,?,?,?,?)',
               (_now(), g.user['id'], g.user['username'], hid, 'provision-key',
                rec['name'], 'auto'))
    return ok(result=result)


@app.route('/api/hosts/<hid>/deploy-credential', methods=['POST'])
@auth.require_operator
def api_deploy_credential(hid):
    """Push a shared credential's PUBLIC key to the host's authorized_keys over
    the host's current working creds, verify key auth with the credential's
    private key, then attach the credential to the host."""
    import provision
    from agent.tools import ssh as sshmod
    rec = inventory.find_for_user(hid, g.user)
    if not rec:
        return err('not found', 404)
    d = request.get_json(force=True, silent=True) or {}
    cid = d.get('credential_id') or rec.get('credential_id') or ''
    cred = inventory.cred_get(cid) if cid else None
    if not cred:
        return err('pick a shared credential first')
    secrets = inventory.secrets_for(rec)
    if not (secrets.get('password') or secrets.get('ssh_key')):
        return err('the host needs a working password or key to deploy the credential with')
    dep = provision.deploy_pubkey(rec, secrets, cred['public_key'])
    if 'KEY_INSTALLED' not in (dep.get('output') or ''):
        return err(f"key deploy failed: {dep.get('error') or (dep.get('output') or '')[:200]}")
    username = rec.get('username') or cred.get('username') or ''
    test = sshmod.test_connection(rec, {'username': username,
                                        'ssh_key': inventory.cred_key(cid)})
    if not test['ok']:
        return err(f"key deployed but key-auth test failed: {test.get('error')}")
    inventory.update(hid, {'credential_id': cid})
    inventory.touch(hid)
    db.execute('INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
               ' VALUES(?,?,?,?,?,?,?)',
               (_now(), g.user['id'], g.user['username'], hid, 'deploy-credential',
                f"{cred['name']} -> {rec['name']}", 'auto'))
    return ok(result={'os': test['os']})


# ─── Shared credentials (operator) ────────────────────────────────────
@app.route('/api/credentials')
@auth.require_operator
def api_creds_list():
    return ok(credentials=inventory.cred_list())


@app.route('/api/credentials', methods=['POST'])
@auth.require_operator
def api_creds_create():
    import provision
    d = request.get_json(force=True, silent=True) or {}
    name = (d.get('name') or '').strip()
    key = d.get('ssh_key') or ''
    if not name or not key.strip():
        return err('name and private key are required')
    if any(c['name'] == name for c in inventory.cred_list()):
        return err('a credential with that name already exists')
    try:
        pub = provision.derive_pubkey(key, comment=f'naa-{name}')
    except ValueError as e:
        return err(str(e))
    cid = inventory.cred_create(name, key, (d.get('username') or '').strip(), pub)
    db.execute('INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
               ' VALUES(?,?,?,?,?,?,?)',
               (_now(), g.user['id'], g.user['username'], None, 'credential-create', name, 'auto'))
    return ok(id=cid, public_key=pub)


@app.route('/api/credentials/<cid>', methods=['DELETE'])
@auth.require_operator
def api_creds_delete(cid):
    cred = inventory.cred_get(cid)
    if not cred:
        return err('not found', 404)
    inventory.cred_delete(cid)
    db.execute('INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
               ' VALUES(?,?,?,?,?,?,?)',
               (_now(), g.user['id'], g.user['username'], None, 'credential-delete',
                cred['name'], 'auto'))
    return ok()


@app.route('/api/hosts', methods=['POST'])
@auth.require_operator
def api_hosts_create():
    d = request.get_json(force=True, silent=True) or {}
    if not d.get('name') or not d.get('address'):
        return err('name and address are required')
    hid = inventory.create(d)
    return ok(id=hid)


@app.route('/api/hosts/<hid>', methods=['PUT'])
@auth.require_operator
def api_hosts_update(hid):
    if not inventory.find_for_user(hid, g.user):
        return err('not found', 404)
    inventory.update(hid, request.get_json(force=True, silent=True) or {})
    return ok()


@app.route('/api/hosts/<hid>', methods=['DELETE'])
@auth.require_operator
def api_hosts_delete(hid):
    if not inventory.find_for_user(hid, g.user):
        return err('not found', 404)
    inventory.delete(hid)
    return ok()


@app.route('/api/hosts/<hid>/test', methods=['POST'])
@auth.require_operator
def api_hosts_test(hid):
    rec = inventory.find_for_user(hid, g.user)
    if not rec:
        return err('not found', 404)
    from agent.tools import ssh
    result = ssh.test_connection(rec, inventory.secrets_for(rec))
    if result['ok']:
        inventory.touch(hid)
    return ok(result=result)


@app.route('/api/hosts/test', methods=['POST'])
@auth.require_operator
def api_hosts_test_unsaved():
    """Test connection with the modal's form values. For a saved host (id
    given), blank secret fields fall back to the STORED secrets — mirroring the
    save semantics ("leave blank to keep") — so Test works after save/provision
    even though secrets are never echoed back into the form."""
    d = request.get_json(force=True, silent=True) or {}
    if not d.get('address'):
        return err('address required')
    host = {'address': d['address'], 'port': d.get('port', 22)}
    secrets = {'username': d.get('username', ''), 'password': d.get('password'),
               'ssh_key': d.get('ssh_key'), 'sudo_password': d.get('sudo_password')}
    if d.get('id'):
        rec = inventory.find_for_user(d['id'], g.user)
        if not rec:
            return err('not found', 404)
        stored = inventory.secrets_for(rec)
        for f in ('password', 'ssh_key', 'sudo_password'):
            if not secrets.get(f):
                secrets[f] = stored.get(f)
        if not secrets.get('username'):
            secrets['username'] = stored.get('username', '')
    if not secrets.get('ssh_key') and d.get('credential_id'):
        cred = inventory.cred_get(d['credential_id'])
        if cred:
            secrets['ssh_key'] = inventory.cred_key(cred['id'])
            if not secrets.get('username'):
                secrets['username'] = cred.get('username') or ''
    from agent.tools import ssh
    return ok(result=ssh.test_connection(host, secrets))


# ─── LLM settings (admin) ─────────────────────────────────────────────
@app.route('/api/settings/llm')
@auth.require_admin
def api_llm_get():
    return ok(llm=settings.public_llm())


@app.route('/api/settings/llm', methods=['PUT'])
@auth.require_admin
def api_llm_set():
    settings.set_llm(request.get_json(force=True, silent=True) or {})
    return ok(llm=settings.public_llm())


@app.route('/api/settings/llm/test', methods=['POST'])
@auth.require_admin
def api_llm_test():
    # allow testing posted config without saving first
    d = request.get_json(force=True, silent=True) or {}
    if d.get('base_url') or d.get('model') or d.get('provider'):
        settings.set_llm(d)
    return ok(result=llm.test_connection())


@app.route('/api/settings/search')
@auth.require_admin
def api_search_get():
    return ok(search=settings.public_search())


@app.route('/api/settings/search', methods=['PUT'])
@auth.require_admin
def api_search_set():
    settings.set_search(request.get_json(force=True, silent=True) or {})
    return ok(search=settings.public_search())


@app.route('/api/settings/notify')
@auth.require_admin
def api_notify_get():
    return ok(notify=settings.public_notify())


@app.route('/api/settings/notify', methods=['PUT'])
@auth.require_admin
def api_notify_set():
    settings.set_notify(request.get_json(force=True, silent=True) or {})
    return ok(notify=settings.public_notify())


@app.route('/api/settings/telegram')
@auth.require_admin
def api_telegram_get():
    return ok(telegram=settings.public_telegram(),
              users=[u['username'] for u in auth.list_users()])


@app.route('/api/settings/telegram', methods=['PUT'])
@auth.require_admin
def api_telegram_set():
    d = request.get_json(force=True, silent=True) or {}
    # normalize whitelist to ints where possible
    wl = []
    for x in d.get('whitelist', []):
        x = str(x).strip()
        if x:
            wl.append(int(x) if x.isdigit() else x)
    settings.set_telegram({'enabled': d.get('enabled'), 'token': d.get('token'),
                           'whitelist': wl, 'act_as': d.get('act_as', '')})
    return ok(telegram=settings.public_telegram())


# ─── app-state backup / restore (admin) ───────────────────────────────
@app.route('/api/backup', methods=['POST'])
@auth.require_admin
def api_backup():
    import backup
    passphrase = (request.get_json(force=True, silent=True) or {}).get('passphrase', '')
    try:
        blob = backup.create_backup(passphrase)
    except ValueError as e:
        return err(str(e))
    return Response(blob, mimetype='application/octet-stream',
                    headers={'Content-Disposition': 'attachment; filename=nexus-admin-assistant.naabk'})


@app.route('/api/restore', methods=['POST'])
@auth.require_admin
def api_restore():
    import backup
    f = request.files.get('file')
    passphrase = request.form.get('passphrase', '')
    if not f:
        return err('no backup file uploaded')
    try:
        backup.restore_backup(f.read(), passphrase)
    except ValueError as e:
        return err(str(e))
    # replaced state files are only picked up on a fresh process; exit the worker
    # so the supervisor (gunicorn/docker/systemd) respawns it and re-loads them.
    def _restart():
        time.sleep(1.5)
        os._exit(0)
    threading.Thread(target=_restart, daemon=True).start()
    return ok(note='State restored — the service is restarting. Reload in a few seconds.')


# ─── TLS certificate management (admin) ───────────────────────────────
@app.route('/api/settings/tls')
@auth.require_admin
def api_tls_info():
    import tls
    return ok(**tls.cert_info())


@app.route('/api/tls/cert', methods=['POST'])
@auth.require_admin
def api_tls_upload():
    import tls
    d = request.get_json(force=True, silent=True) or {}
    okd, e = tls.validate_and_install_cert(d.get('cert'), d.get('key'))
    if not okd:
        return err(e)
    return ok(restart_required=True,
              note='Certificate installed. Click Apply to restart and serve it.')


@app.route('/api/tls/regenerate', methods=['POST'])
@auth.require_admin
def api_tls_regenerate():
    import tls
    okd, e = tls.generate_self_signed()
    if not okd:
        return err('Failed to generate certificate: ' + e, 500)
    return ok(restart_required=True,
              note='Self-signed certificate generated. Click Apply to restart and serve it.')


@app.route('/api/tls/apply', methods=['POST'])
@auth.require_admin
def api_tls_apply():
    # gunicorn wraps the listening socket with the SSL context once at worker
    # startup, so bouncing the worker (supervisor respawns it) reloads the cert.
    if not config.TLS:
        return err('TLS is not enabled on this instance — set NAA_TLS=1 and restart '
                   'the service/container to serve HTTPS.')
    def _restart():
        time.sleep(1.0)
        os._exit(0)
    threading.Thread(target=_restart, daemon=True).start()
    return ok(note='Restarting to load the certificate — reload the page in a few seconds.')


# ─── conversations ────────────────────────────────────────────────────
def _can_see_convo(convo):
    """Transcripts hold command output from the hosts they ran against, so the
    host tag-scope has to apply here too — otherwise /api/conversations/<id>
    hands any logged-in user (viewers included) the full output of runs against
    hosts they can't even list. Admins see everything; everyone else sees their
    own conversations, and only while the host is still in their scope."""
    if g.user['role'] == 'admin':
        return True
    if convo.get('user_id') != g.user['id']:
        return False
    hid = convo.get('host_id')
    return not hid or bool(inventory.find_for_user(hid, g.user))


@app.route('/api/conversations')
@auth.require_login
def api_convos():
    host_id = request.args.get('host_id')
    if host_id:
        rows = db.query('SELECT * FROM conversations WHERE host_id=? ORDER BY updated_at DESC',
                        (host_id,))
    else:
        rows = db.query('SELECT * FROM conversations ORDER BY updated_at DESC LIMIT 200')
    visible = [r for r in rows if _can_see_convo(r)][:100]
    return ok(conversations=[_convo_public(r) for r in visible])


@app.route('/api/conversations', methods=['POST'])
@auth.require_login
def api_convo_create():
    d = request.get_json(force=True, silent=True) or {}
    host_id = d.get('host_id')
    if host_id and not inventory.find_for_user(host_id, g.user):
        return err('host not found', 404)
    cid = _secrets.token_hex(8)
    db.execute('INSERT INTO conversations(id, host_id, user_id, title, created_at, updated_at)'
               ' VALUES(?,?,?,?,?,?)',
               (cid, host_id, g.user['id'], d.get('title', core.DEFAULT_TITLE), _now(), _now()))
    return ok(id=cid)


@app.route('/api/conversations/<cid>')
@auth.require_login
def api_convo_get(cid):
    convo = db.query_one('SELECT * FROM conversations WHERE id=?', (cid,))
    if not convo or not _can_see_convo(convo):
        return err('not found', 404)          # invisible, not forbidden
    msgs = db.query('SELECT role, content, tool_calls_json, created_at FROM messages'
                    ' WHERE conversation_id=? ORDER BY id', (cid,))
    return ok(conversation=_convo_public(convo), messages=msgs)


@app.route('/api/conversations/<cid>', methods=['PUT'])
@auth.require_login
def api_convo_update(cid):
    convo = db.query_one('SELECT * FROM conversations WHERE id=?', (cid,))
    if not convo or not _can_see_convo(convo):
        return err('not found', 404)
    d = request.get_json(force=True, silent=True) or {}
    if 'host_id' in d:
        hid = d['host_id']
        if hid and not inventory.find_for_user(hid, g.user):
            return err('host not found', 404)
        db.execute('UPDATE conversations SET host_id=?, updated_at=? WHERE id=?', (hid, _now(), cid))
    if 'title' in d:
        db.execute('UPDATE conversations SET title=? WHERE id=?', (d['title'], cid))
    return ok()


def _owns_convo(convo):
    """A user may delete their own conversations; admins may delete any."""
    return g.user['role'] == 'admin' or convo.get('user_id') == g.user['id']


@app.route('/api/conversations/<cid>', methods=['DELETE'])
@auth.require_login
def api_convo_delete(cid):
    convo = db.query_one('SELECT * FROM conversations WHERE id=?', (cid,))
    if not convo:
        return err('not found', 404)
    if not _owns_convo(convo):
        return err('not found', 404)          # invisible, not forbidden
    # (deletion is deliberately NOT gated on host scope: losing scope to a host
    # shouldn't strand your own conversations.)
    if cid in core.active_conversation_ids():
        return err('that conversation has a run in progress — stop it first', 409)
    db.execute('DELETE FROM conversations WHERE id=?', (cid,))  # messages cascade
    return ok()


@app.route('/api/conversations/clear', methods=['POST'])
@auth.require_login
def api_convos_clear():
    """Delete the caller's conversations, skipping any with a run in progress.
    Scoped to a host when host_id is given (matches the list pane); admins clear
    everyone's, others only their own. Reports counts deleted vs kept."""
    d = request.get_json(force=True, silent=True) or {}
    host_id = d.get('host_id')
    where, params = [], []
    if host_id:
        where.append('host_id=?')
        params.append(host_id)
    if g.user['role'] != 'admin':
        where.append('user_id=?')
        params.append(g.user['id'])
    sql = 'SELECT id FROM conversations'
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    active = core.active_conversation_ids()
    deleted = skipped = 0
    for r in db.query(sql, params):
        if r['id'] in active:
            skipped += 1
            continue
        db.execute('DELETE FROM conversations WHERE id=?', (r['id'],))
        deleted += 1
    return ok(deleted=deleted, skipped=skipped)


def _convo_public(r):
    return {'id': r['id'], 'host_id': r['host_id'], 'title': r['title'],
            'updated_at': r['updated_at']}


# ─── agent ────────────────────────────────────────────────────────────
@app.route('/api/agent/send', methods=['POST'])
@auth.require_operator
def api_agent_send():
    d = request.get_json(force=True, silent=True) or {}
    cid = d.get('conversation_id')
    message = (d.get('message') or '').strip()
    convo = db.query_one('SELECT * FROM conversations WHERE id=?', (cid,))
    if not convo or not _can_see_convo(convo):
        return err('conversation not found', 404)
    if not message:
        return err('empty message')
    host = None
    secrets = None
    if convo['host_id']:
        host = inventory.find_for_user(convo['host_id'], g.user)
        if not host:
            return err('host not found or out of scope', 404)
        secrets = inventory.secrets_for(host)
    # persist the user turn, then start the run
    db.execute('INSERT INTO messages(conversation_id, role, content, created_at)'
               ' VALUES(?,?,?,?)', (cid, 'user', message, _now()))
    # name a still-unnamed conversation after its first user message
    if (convo['title'] or '').strip() in ('', core.DEFAULT_TITLE):
        db.execute('UPDATE conversations SET title=?, updated_at=? WHERE id=?',
                   (core.derive_title(message), _now(), cid))
    else:
        db.execute('UPDATE conversations SET updated_at=? WHERE id=?', (_now(), cid))
    run = core.start(convo, host, secrets, g.user)
    return ok(run_id=run.id)


@app.route('/api/agent/stream/<run_id>')
@auth.require_login
def api_agent_stream(run_id):
    run = core.get(run_id)
    if not run:
        return err('run not found or finished', 404)
    if run.user and run.user['id'] != g.user['id'] and g.user['role'] != 'admin':
        return err('forbidden', 403)

    def gen():
        yield 'retry: 2000\n\n'
        while True:
            try:
                ev = run.q.get(timeout=15)
            except queue.Empty:
                yield ': keepalive\n\n'
                if run.finished:
                    break
                continue
            yield f'data: {json.dumps(ev)}\n\n'
            if ev['type'] == 'done':
                break
        core.cleanup(run_id)
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/api/agent/confirm', methods=['POST'])
@auth.require_operator
def api_agent_confirm():
    d = request.get_json(force=True, silent=True) or {}
    run = core.get(d.get('run_id'))
    if run and not core.may_control(run, g.user):
        return err('forbidden', 403)
    okc = core.confirm(d.get('run_id'), d.get('call_id'), d.get('decision', 'deny'),
                       command=d.get('command'), user=g.user)
    return ok() if okc else err('no pending confirmation', 404)


@app.route('/api/agent/stop', methods=['POST'])
@auth.require_operator
def api_agent_stop():
    d = request.get_json(force=True, silent=True) or {}
    run = core.get(d.get('run_id'))
    if run and not core.may_control(run, g.user):
        return err('forbidden', 403)
    return ok() if core.stop(d.get('run_id'), user=g.user) else err('run not found', 404)


# ─── interactive shell (WebSocket PTY) ────────────────────────────────
@sock.route('/api/hosts/<hid>/shell')
def api_shell(ws, hid):
    """Bridge the browser terminal to a real PTY on the host over SSH.
    Operator+ only; host must be in the caller's scope."""
    if not _same_origin(request):
        log.warning('rejected cross-origin shell handshake origin=%r',
                    request.headers.get('Origin'))
        ws.close()
        return
    user = auth.current_user()
    if not user or user['role'] == 'viewer':
        ws.close()
        return
    rec = inventory.find_for_user(hid, user)
    if not rec:
        ws.close()
        return
    try:
        client = sshtool.connect(rec, inventory.secrets_for(rec))
    except Exception as e:  # noqa: BLE001
        ws.send(f'\r\n\x1b[31mconnect failed: {sshtool._friendly(e)}\x1b[0m\r\n')
        ws.close()
        return
    db.execute('INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
               ' VALUES(?,?,?,?,?,?,?)',
               (_now(), user['id'], user['username'], hid, 'shell:open', rec['name'], 'auto'))
    chan = client.invoke_shell(term='xterm-256color', width=120, height=32)
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                if chan.recv_ready():
                    data = chan.recv(4096)
                    if not data:
                        break
                    ws.send(data.decode(errors='replace'))
                elif chan.closed:
                    break
                else:
                    time.sleep(0.02)
            except Exception:  # noqa: BLE001
                break
        stop.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    try:
        while not stop.is_set():
            msg = ws.receive(timeout=1)
            if msg is None:
                if chan.closed or not t.is_alive():
                    break
                continue
            if msg.startswith('{') and '"resize"' in msg:
                try:
                    r = json.loads(msg)['resize']
                    chan.resize_pty(width=int(r['cols']), height=int(r['rows']))
                    continue
                except Exception:  # noqa: BLE001
                    pass
            chan.send(msg)
    except Exception:  # noqa: BLE001
        pass
    finally:
        stop.set()
        try:
            chan.close()
        except Exception:  # noqa: BLE001
            pass
        client.close()


# ─── change journal / rollback ────────────────────────────────────────
@app.route('/api/hosts/<hid>/changes')
@auth.require_login
def api_changes(hid):
    if not inventory.find_for_user(hid, g.user):
        return err('not found', 404)
    return ok(changes=changes.list_for_host(hid))


@app.route('/api/changes/<int:cid>/revert', methods=['POST'])
@auth.require_operator
def api_change_revert(cid):
    row = changes.get(cid)
    if not row or not row['reversible'] or row['reverted']:
        return err('not revertible', 400)
    rec = inventory.find_for_user(row['host_id'], g.user)
    if not rec:
        return err('host not found', 404)
    secrets = inventory.secrets_for(rec)
    from agent.tools import files, ssh
    use_sudo = bool(row['used_sudo'])
    path = row['path']
    if row['had_before']:
        before = changes.before_content(row)
        res = files.push_file(rec, secrets, path, before, use_sudo)
    else:
        # file didn't exist before this change → remove it
        res = ssh.run(rec, secrets, f"rm -f {files._q(path)}", use_sudo=use_sudo)
    if res['exit_code'] != 0:
        return err(f'revert failed: {res.get("error") or res.get("output", "")[:200]}')
    changes.mark_reverted(cid)
    db.execute('INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
               ' VALUES(?,?,?,?,?,?,?)',
               (_now(), g.user['id'], g.user['username'], row['host_id'],
                'change:revert', path, 'approved'))
    return ok()


# ─── memory ───────────────────────────────────────────────────────────
@app.route('/api/memories')
@auth.require_login
def api_memories():
    host_id = request.args.get('host_id')
    out = {'mission': memory.get_mission(), 'global': memory.list_global(exclude_mission=True)}
    if host_id:
        if not inventory.find_for_user(host_id, g.user):
            return err('host not found', 404)
        out['host'] = memory.list_host(host_id)
    return ok(**out)


@app.route('/api/memories', methods=['POST'])
@auth.require_operator
def api_memory_create():
    d = request.get_json(force=True, silent=True) or {}
    host_id = None
    if d.get('scope') == 'host':
        host_id = d.get('host_id')
        if not host_id or not inventory.find_for_user(host_id, g.user):
            return err('host not found', 404)
    mid = memory.create(d.get('kind', 'fact'), (d.get('title') or '').strip(),
                        (d.get('body') or '').strip(), host_id)
    return ok(id=mid)


@app.route('/api/memories/<int:mid>', methods=['PUT'])
@auth.require_operator
def api_memory_update(mid):
    d = request.get_json(force=True, silent=True) or {}
    memory.update(mid, title=d.get('title'), body=d.get('body'), kind=d.get('kind'))
    return ok()


@app.route('/api/memories/<int:mid>', methods=['DELETE'])
@auth.require_operator
def api_memory_delete(mid):
    memory.delete(mid)
    return ok()


@app.route('/api/memories/mission', methods=['PUT'])
@auth.require_operator
def api_mission_set():
    d = request.get_json(force=True, silent=True) or {}
    memory.set_mission((d.get('body') or '').strip())
    return ok()


# ─── skills / playbooks ───────────────────────────────────────────────
@app.route('/api/skills')
@auth.require_login
def api_skills():
    out = skills.list_all()
    for s in out:                       # advisory: blocking-step warnings for the approver
        s['warnings'] = skills.lint(s.get('body', ''))
    return ok(skills=out)


@app.route('/api/skills', methods=['POST'])
@auth.require_operator
def api_skill_create():
    d = request.get_json(force=True, silent=True) or {}
    try:
        sid = skills.save(d.get('name', ''), d.get('description', ''), d.get('body', ''),
                          d.get('params'), approved=bool(d.get('approved')))
    except ValueError as e:
        return err(str(e))
    return ok(id=sid)


@app.route('/api/skills/<int:sid>', methods=['PUT'])
@auth.require_operator
def api_skill_update(sid):
    d = request.get_json(force=True, silent=True) or {}
    if 'approved' in d:
        skills.set_approved(sid, bool(d['approved']))
    skills.update(sid, name=d.get('name'), description=d.get('description'), body=d.get('body'))
    return ok()


@app.route('/api/skills/<int:sid>', methods=['DELETE'])
@auth.require_operator
def api_skill_delete(sid):
    skills.delete(sid)
    return ok()


# ─── scheduled jobs ───────────────────────────────────────────────────
def _job_visible(job):
    if g.user['role'] == 'admin':
        return True
    if job['created_by'] == g.user['id']:
        return True
    if job['host_id']:
        return bool(inventory.find_for_user(job['host_id'], g.user))
    return False


@app.route('/api/jobs')
@auth.require_login
def api_jobs():
    return ok(jobs=[j for j in schedule.list_all() if _job_visible(j)])


@app.route('/api/jobs', methods=['POST'])
@auth.require_operator
def api_job_create():
    d = request.get_json(force=True, silent=True) or {}
    if not d.get('name') or not d.get('instruction'):
        return err('name and instruction required')
    if d.get('kind') != 'once' and not schedule.is_valid_cron(d.get('schedule', '')):
        return err('invalid cron expression (need: min hour dom mon dow)')
    if d.get('host_id') and not inventory.find_for_user(d['host_id'], g.user):
        return err('host not found', 404)
    jid = schedule.create(d, created_by=g.user['id'])
    return ok(id=jid)


@app.route('/api/jobs/<jid>', methods=['PUT'])
@auth.require_operator
def api_job_update(jid):
    job = schedule.get(jid)
    if not job or not _job_visible(job):
        return err('not found', 404)
    schedule.update(jid, request.get_json(force=True, silent=True) or {})
    return ok()


@app.route('/api/jobs/<jid>', methods=['DELETE'])
@auth.require_operator
def api_job_delete(jid):
    job = schedule.get(jid)
    if not job or not _job_visible(job):
        return err('not found', 404)
    schedule.delete(jid)
    return ok()


@app.route('/api/jobs/<jid>/run', methods=['POST'])
@auth.require_operator
def api_job_run(jid):
    job = schedule.get(jid)
    if not job or not _job_visible(job):
        return err('not found', 404)
    threading.Thread(target=schedule.run_job, args=(jid,), daemon=True).start()
    return ok(note='running now — refresh for the report')


# ─── deferred approvals ───────────────────────────────────────────────
def _deferred_in_scope(row_or_dict):
    """A pending action names a host and a command — both are disclosure, and
    denying someone else's is tampering. Gate the whole set by host scope."""
    hid = row_or_dict.get('host_id')
    return not hid or bool(inventory.find_for_user(hid, g.user))


@app.route('/api/deferred')
@auth.require_login
def api_deferred():
    return ok(deferred=[d for d in schedule.list_deferred('pending')
                        if _deferred_in_scope(d)])


@app.route('/api/deferred/<int:did>/approve', methods=['POST'])
@auth.require_operator
def api_deferred_approve(did):
    d = request.get_json(force=True, silent=True) or {}
    row = db.query_one('SELECT * FROM deferred_actions WHERE id=?', (did,))
    if not row or row['status'] != 'pending' or not _deferred_in_scope(row):
        return err('not found', 404)
    result = schedule.approve_deferred(did, g.user, add_to_allow=bool(d.get('add_to_allow')))
    return ok(result=result)


@app.route('/api/deferred/<int:did>/deny', methods=['POST'])
@auth.require_operator
def api_deferred_deny(did):
    row = db.query_one('SELECT * FROM deferred_actions WHERE id=?', (did,))
    if not row or row['status'] != 'pending' or not _deferred_in_scope(row):
        return err('not found', 404)
    schedule.deny_deferred(did, g.user)
    return ok()


# ─── service checks ───────────────────────────────────────────────────
def _check_visible(c):
    """A check is visible when its pinned host is in scope (or it pins none)."""
    if g.user['role'] == 'admin' or not c.get('host_id'):
        return True
    return bool(inventory.find_for_user(c['host_id'], g.user))


@app.route('/api/checks')
@auth.require_login
def api_checks():
    return ok(checks=[c for c in services.list_all() if _check_visible(c)])


@app.route('/api/checks', methods=['POST'])
@auth.require_operator
def api_check_create():
    d = request.get_json(force=True, silent=True) or {}
    if not (d.get('name') or '').strip():
        return err('name is required')
    if not (d.get('target') or '').strip():
        return err('target is required (a URL, address or host:port to probe)')
    if d.get('host_id') and not inventory.find_for_user(d['host_id'], g.user):
        return err('host not found', 404)
    if d.get('auto_fix') and not d.get('host_id'):
        return err('autonomous troubleshooting needs a host — pin the check to the '
                   'host the service runs on')
    cid = services.create(d, created_by=g.user['id'])
    log.info('check created %s by %s', d.get('name'), g.user['username'])
    return ok(id=cid)


@app.route('/api/checks/<cid>', methods=['PUT'])
@auth.require_operator
def api_check_update(cid):
    c = services.get(cid)
    if not c or not _check_visible(c):
        return err('not found', 404)
    d = request.get_json(force=True, silent=True) or {}
    if d.get('host_id') and not inventory.find_for_user(d['host_id'], g.user):
        return err('host not found', 404)
    if d.get('auto_fix') and not (d.get('host_id') or c['host_id']):
        return err('autonomous troubleshooting needs a host — pin the check to the '
                   'host the service runs on')
    services.update(cid, d)
    return ok()


@app.route('/api/checks/<cid>', methods=['DELETE'])
@auth.require_operator
def api_check_delete(cid):
    c = services.get(cid)
    if not c or not _check_visible(c):
        return err('not found', 404)
    services.delete(cid)
    return ok()


@app.route('/api/checks/<cid>/run', methods=['POST'])
@auth.require_operator
def api_check_run(cid):
    """Probe now. Deliberately does NOT trigger auto-fix: a manual 'test this
    check' click should tell you what's happening, not start repairing things."""
    c = services.get(cid)
    if not c or not _check_visible(c):
        return err('not found', 404)
    return ok(check=services.run_check(cid, allow_auto_fix=False))


@app.route('/api/checks/<cid>/history')
@auth.require_login
def api_check_history(cid):
    c = services.get(cid)
    if not c or not _check_visible(c):
        return err('not found', 404)
    return ok(history=services.history(cid, limit=int(request.args.get('limit', 100))))


@app.route('/api/checks/probe', methods=['POST'])
@auth.require_operator
def api_check_probe():
    """Try a probe without saving it — the 'Test' button in the editor."""
    d = request.get_json(force=True, silent=True) or {}
    return ok(result=services.probe_once(
        d.get('kind', 'https'), d.get('target', ''), int(d.get('port') or 0),
        min(int(d.get('timeout_s') or 10), 30), d.get('options') or {}))


# ─── audit (admin) ────────────────────────────────────────────────────
@app.route('/api/audit')
@auth.require_admin
def api_audit():
    rows = db.query('SELECT * FROM audit ORDER BY id DESC LIMIT 500')
    return ok(audit=rows)


if __name__ == '__main__':
    boot()
    kwargs = {'host': '0.0.0.0', 'port': config.PORT, 'threaded': True}
    if config.TLS:
        kwargs['ssl_context'] = (config.TLS_CERT, config.TLS_KEY)
    app.run(**kwargs)
