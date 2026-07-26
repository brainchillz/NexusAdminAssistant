"""Change journal — per-host record of what the agent changed, with undo.

File writes are recorded reversibly: the previous content is captured before
overwriting (Fernet-encrypted at rest), so a change can be reverted (restore the
old content, or delete the file if it didn't exist before). Risky commands are
recorded as non-reversible notes for visibility. The actual revert (a host write)
is performed by the API layer, which has host/credential access.
"""
from datetime import datetime, timezone

from store import crypto, db

MAX_CONTENT = 400_000  # cap stored file content


def _now():
    return datetime.now(timezone.utc).isoformat()


def record_file_change(host_id, user, conversation_id, path, before, after,
                       had_before, used_sudo):
    db.execute(
        'INSERT INTO change_journal(host_id, ts, user_id, username, conversation_id, kind,'
        ' summary, path, before_enc, after_enc, had_before, used_sudo, reversible)'
        ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)',
        (host_id, _now(), (user or {}).get('id', ''), (user or {}).get('username', ''),
         conversation_id or '', 'write_file', path, path,
         crypto.encrypt((before or '')[:MAX_CONTENT]),
         crypto.encrypt((after or '')[:MAX_CONTENT]),
         1 if had_before else 0, 1 if used_sudo else 0))


def record_command(host_id, user, conversation_id, command, risk):
    db.execute(
        'INSERT INTO change_journal(host_id, ts, user_id, username, conversation_id, kind,'
        ' summary, reversible) VALUES(?,?,?,?,?,?,?,0)',
        (host_id, _now(), (user or {}).get('id', ''), (user or {}).get('username', ''),
         conversation_id or '', 'command', f'[{risk}] {command}'[:500]))


def list_for_host(host_id, limit=80):
    """Metadata only — never returns the encrypted before/after content."""
    rows = db.query(
        'SELECT id, ts, username, kind, summary, path, had_before, used_sudo, reversible,'
        ' reverted, reverted_at FROM change_journal WHERE host_id=? ORDER BY id DESC LIMIT ?',
        (host_id, limit))
    return [dict(r) for r in rows]


def get(cid):
    return db.query_one('SELECT * FROM change_journal WHERE id=?', (cid,))


def before_content(row):
    return crypto.decrypt(row['before_enc']) or ''


def mark_reverted(cid):
    db.execute('UPDATE change_journal SET reverted=1, reverted_at=? WHERE id=?', (_now(), cid))
