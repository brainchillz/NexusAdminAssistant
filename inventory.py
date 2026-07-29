"""Host inventory + credential vault.

Hosts live in SQLite; secrets (password, ssh key, token, sudo password) are
Fernet-encrypted columns. public() strips every secret. Tag-scope is enforced
here: find_for_user() returns None for out-of-scope hosts so callers 404 them
(invisible, not forbidden).
"""
import json
import secrets
from datetime import datetime, timezone

import auth
from store import crypto, db

SECRET_FIELDS = {
    'password': 'password_enc',
    'ssh_key': 'ssh_key_enc',
    'token': 'token_enc',
    'sudo_password': 'sudo_password_enc',
}
AUTONOMY_LEVELS = ('lab', 'default', 'prod')


def _now():
    return datetime.now(timezone.utc).isoformat()


def _hid():
    return secrets.token_hex(8)


def public(rec):
    """Host record for the browser — no secrets, just which creds are present."""
    return {
        'id': rec['id'], 'name': rec['name'], 'address': rec['address'],
        'port': rec['port'], 'conn_type': rec['conn_type'],
        'username': rec.get('username') or '',
        'tags': json.loads(rec.get('tags') or '[]'),
        'autonomy_level': rec.get('autonomy_level') or 'default',
        'notes': rec.get('notes') or '',
        'created_at': rec.get('created_at') or '', 'last_seen': rec.get('last_seen') or '',
        'has_password': bool(rec.get('password_enc')),
        'has_ssh_key': bool(rec.get('ssh_key_enc')),
        'has_token': bool(rec.get('token_enc')),
        'has_sudo_password': bool(rec.get('sudo_password_enc')),
        'credential_id': rec.get('credential_id') or '',
    }


def list_for_user(user):
    rows = db.query('SELECT * FROM hosts ORDER BY name')
    out = []
    for r in rows:
        tags = json.loads(r.get('tags') or '[]')
        if auth.scope_allows(user, tags):
            out.append(public(r))
    return out


def get_raw(host_id):
    return db.query_one('SELECT * FROM hosts WHERE id=?', (host_id,))


def find_for_user(host_id, user):
    """Raw record if it exists AND is in the user's scope, else None."""
    rec = get_raw(host_id)
    if not rec:
        return None
    tags = json.loads(rec.get('tags') or '[]')
    if not auth.scope_allows(user, tags):
        return None
    return rec


def _apply_secrets(cols, params, data, is_new):
    """Encrypt provided secrets; on edit, a blank value keeps the stored secret."""
    for field, col in SECRET_FIELDS.items():
        if field in data:
            val = data.get(field)
            if val:
                cols.append(col)
                params.append(crypto.encrypt(val))
            elif is_new:
                cols.append(col)
                params.append('')
            # edit + blank => leave column untouched (keep existing secret)


def create(data):
    hid = _hid()
    cols = ['id', 'name', 'address', 'port', 'conn_type', 'username', 'tags',
            'autonomy_level', 'notes', 'credential_id', 'created_at']
    level = data.get('autonomy_level', 'default')
    if level not in AUTONOMY_LEVELS:
        level = 'default'
    params = [hid, data['name'], data['address'], int(data.get('port', 22)),
              data.get('conn_type', 'ssh'), data.get('username', ''),
              json.dumps(data.get('tags', [])), level, data.get('notes', ''),
              data.get('credential_id', ''), _now()]
    _apply_secrets(cols, params, data, is_new=True)
    ph = ','.join('?' * len(cols))
    db.execute(f'INSERT INTO hosts({",".join(cols)}) VALUES({ph})', params)
    return hid


def update(host_id, data):
    cols, params = [], []
    for field in ('name', 'address', 'conn_type', 'username', 'notes', 'credential_id'):
        if field in data:
            cols.append(f'{field}=?')
            params.append(data[field])
    if 'port' in data:
        cols.append('port=?')
        params.append(int(data['port']))
    if 'tags' in data:
        cols.append('tags=?')
        params.append(json.dumps(data['tags']))
    if 'autonomy_level' in data and data['autonomy_level'] in AUTONOMY_LEVELS:
        cols.append('autonomy_level=?')
        params.append(data['autonomy_level'])
    sec_cols, sec_params = [], []
    _apply_secrets(sec_cols, sec_params, data, is_new=False)
    for c, p in zip(sec_cols, sec_params, strict=True):
        cols.append(f'{c}=?')
        params.append(p)
    if not cols:
        return
    params.append(host_id)
    db.execute(f'UPDATE hosts SET {",".join(cols)} WHERE id=?', params)


def delete(host_id):
    db.execute('DELETE FROM hosts WHERE id=?', (host_id,))


def touch(host_id):
    db.execute('UPDATE hosts SET last_seen=? WHERE id=?', (_now(), host_id))


def set_doc(host_id, doc):
    db.execute('UPDATE hosts SET doc=?, doc_updated=? WHERE id=?', (doc or '', _now(), host_id))


def get_doc(host_id):
    r = db.query_one('SELECT doc, doc_updated FROM hosts WHERE id=?', (host_id,))
    return {'doc': (r['doc'] if r else '') or '', 'doc_updated': (r['doc_updated'] if r else '') or ''}


def secrets_for(rec):
    """Decrypt a host's secrets for execution-time use. NEVER serialize this.
    A host's own key wins; otherwise its shared credential (if any) supplies
    the SSH key (and the login username, when the host leaves it blank)."""
    out = {
        'username': rec.get('username') or '',
        'password': crypto.decrypt(rec.get('password_enc')),
        'ssh_key': crypto.decrypt(rec.get('ssh_key_enc')),
        'token': crypto.decrypt(rec.get('token_enc')),
        'sudo_password': crypto.decrypt(rec.get('sudo_password_enc')),
    }
    if not out['ssh_key'] and rec.get('credential_id'):
        cred = cred_get(rec['credential_id'])
        if cred:
            out['ssh_key'] = crypto.decrypt(cred.get('ssh_key_enc'))
            if not out['username']:
                out['username'] = cred.get('username') or ''
    return out


# ─── Shared credentials — named reusable SSH identities ───────────────
# One private key stored once (Fernet), referenced by any number of hosts.
# The derived public key is kept in the clear for display/copy/deploy.

def cred_public(rec):
    return {'id': rec['id'], 'name': rec['name'],
            'username': rec.get('username') or '',
            'public_key': rec.get('public_key') or '',
            'created_at': rec.get('created_at') or ''}


def cred_list():
    counts = {r['credential_id']: r['n'] for r in db.query(
        "SELECT credential_id, COUNT(*) AS n FROM hosts WHERE credential_id != '' GROUP BY credential_id")}
    out = []
    for r in db.query('SELECT * FROM credentials ORDER BY name'):
        p = cred_public(r)
        p['hosts_using'] = counts.get(r['id'], 0)
        out.append(p)
    return out


def cred_get(cred_id):
    return db.query_one('SELECT * FROM credentials WHERE id=?', (cred_id,))


def cred_create(name, ssh_key, username='', public_key=''):
    cid = _hid()
    db.execute('INSERT INTO credentials(id, name, username, ssh_key_enc, public_key, created_at)'
               ' VALUES(?,?,?,?,?,?)',
               (cid, name, username, crypto.encrypt(ssh_key), public_key, _now()))
    return cid


def cred_key(cred_id):
    """Decrypted private key for execution-time use only."""
    r = cred_get(cred_id)
    return crypto.decrypt(r.get('ssh_key_enc')) if r else ''


def cred_delete(cred_id):
    db.execute("UPDATE hosts SET credential_id='' WHERE credential_id=?", (cred_id,))
    db.execute('DELETE FROM credentials WHERE id=?', (cred_id,))
