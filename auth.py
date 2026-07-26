"""Authentication, roles, and tag-scoping.

Roles: admin (all + user/host/LLM management), operator (use the agent on hosts
in scope, no admin), viewer (read-only). Tag scope: a user with non-empty
scope_tags sees/acts only on hosts bearing any of those tags; admins are always
unscoped. Enforcement lives here + in inventory.py (out-of-scope host = 404).
"""
import functools
import json
import os
import secrets
import sys
from datetime import datetime, timezone

from flask import g, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash

from store import db

ROLES = ('admin', 'operator', 'viewer')


def _now():
    return datetime.now(timezone.utc).isoformat()


def _uid():
    return secrets.token_hex(8)


# ─── bootstrap ────────────────────────────────────────────────────────
def ensure_admin():
    """First-run: create an admin if no users exist. Password from
    NAA_ADMIN_PASSWORD or random (printed once to stderr)."""
    if db.query_one('SELECT id FROM users LIMIT 1'):
        return
    pw = os.environ.get('NAA_ADMIN_PASSWORD') or secrets.token_urlsafe(12)
    db.execute(
        'INSERT INTO users(id, username, pw_hash, role, scope_tags, must_change, created_at)'
        ' VALUES(?,?,?,?,?,?,?)',
        (_uid(), 'admin', generate_password_hash(pw), 'admin', '[]', 1, _now()),
    )
    if not os.environ.get('NAA_ADMIN_PASSWORD'):
        print(f'\n*** First-run admin created: admin / {pw}  (change on first login) ***\n',
              file=sys.stderr)


# ─── login / session ──────────────────────────────────────────────────
def authenticate(username, password):
    rec = db.query_one('SELECT * FROM users WHERE username=?', (username,))
    if not rec or not check_password_hash(rec['pw_hash'], password or ''):
        return None
    return rec


def login_session(rec):
    session.clear()
    session['uid'] = rec['id']
    session['username'] = rec['username']
    session['role'] = rec['role']
    session.permanent = True


def current_user():
    uid = session.get('uid')
    if not uid:
        return None
    return db.query_one('SELECT * FROM users WHERE id=?', (uid,))


def scope_tags(rec):
    """Return the user's tag scope as a list, or None if unscoped (admins/empty)."""
    if not rec or rec['role'] == 'admin':
        return None
    tags = json.loads(rec.get('scope_tags') or '[]')
    return tags or None


def scope_allows(rec, host_tags):
    scope = scope_tags(rec)
    if scope is None:
        return True
    return bool(set(scope) & set(host_tags or []))


# ─── guards ───────────────────────────────────────────────────────────
def require_login(fn):
    @functools.wraps(fn)
    def wrap(*a, **k):
        rec = current_user()
        if not rec:
            return jsonify({'success': False, 'error': 'auth required'}), 401
        g.user = rec
        return fn(*a, **k)
    return wrap


def require_role(*roles):
    def deco(fn):
        @functools.wraps(fn)
        def wrap(*a, **k):
            rec = current_user()
            if not rec:
                return jsonify({'success': False, 'error': 'auth required'}), 401
            if rec['role'] not in roles:
                return jsonify({'success': False, 'error': 'forbidden'}), 403
            g.user = rec
            return fn(*a, **k)
        return wrap
    return deco


require_admin = require_role('admin')
# operators and admins may write; viewers are read-only
require_operator = require_role('admin', 'operator')


# ─── user CRUD (admin) ────────────────────────────────────────────────
def public_user(rec):
    return {
        'id': rec['id'], 'username': rec['username'], 'role': rec['role'],
        'scope_tags': json.loads(rec.get('scope_tags') or '[]'),
        'must_change': bool(rec['must_change']),
    }


def list_users():
    return [public_user(r) for r in db.query('SELECT * FROM users ORDER BY username')]


def create_user(username, password, role='operator', tags=None):
    if role not in ROLES:
        raise ValueError('bad role')
    if db.query_one('SELECT id FROM users WHERE username=?', (username,)):
        raise ValueError('username exists')
    uid = _uid()
    db.execute(
        'INSERT INTO users(id, username, pw_hash, role, scope_tags, must_change, created_at)'
        ' VALUES(?,?,?,?,?,?,?)',
        (uid, username, generate_password_hash(password), role,
         json.dumps(tags or []), 1, _now()),
    )
    return uid


def set_password(uid, password, must_change=False):
    db.execute('UPDATE users SET pw_hash=?, must_change=? WHERE id=?',
               (generate_password_hash(password), 1 if must_change else 0, uid))


def update_user(uid, role=None, tags=None):
    if role is not None:
        if role not in ROLES:
            raise ValueError('bad role')
        db.execute('UPDATE users SET role=? WHERE id=?', (role, uid))
    if tags is not None:
        db.execute('UPDATE users SET scope_tags=? WHERE id=?', (json.dumps(tags), uid))


def delete_user(uid):
    rec = db.query_one('SELECT * FROM users WHERE id=?', (uid,))
    if not rec:
        return
    if rec['role'] == 'admin':
        admins = db.query('SELECT id FROM users WHERE role="admin"')
        if len(admins) <= 1:
            raise ValueError('cannot delete the last admin')
    db.execute('DELETE FROM users WHERE id=?', (uid,))
