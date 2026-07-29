"""Skills / playbook library — the assistant's reusable procedures.

A skill is a named, parameterized playbook the agent authored or refined (e.g.
"install-lamp": step-by-step LAMP setup). Skills start as DRAFTS; the user
reviews/edits/approves them in the Skills UI. Approved skills are summarized into
every conversation's context so the agent reaches for a known-good procedure
instead of improvising — this is how it improves over time.
"""
import json
import re
from datetime import datetime, timezone

from store import db


def _now():
    return datetime.now(timezone.utc).isoformat()


# ─── skill linting ────────────────────────────────────────────────────
# A skill is executed UNATTENDED by the agent over ssh_exec — there is no human
# to answer a prompt or press Ctrl+C. These patterns block forever (or until the
# tool timeout) and are the #1 cause of "the agent locked up on a playbook".
# Pure + tested (mirrors policy.py / scrub.py). Returns human-readable warnings;
# it never blocks a save — it informs the agent (to revise) and the human (to
# review before approving).
# Whole-body single-pattern rules.
_LINT_RULES = [
    (re.compile(r'(?<![-\w])(?:tail|less|more)\s+(?:-\w*\s+)*-\w*f\b'),
     'runs a follower (tail -f / less) that never exits — capture a bounded '
     'snapshot instead (e.g. `journalctl -n 50 --no-pager`)'),
    (re.compile(r'\bjournalctl\b[^\n]*\s-\w*f\b(?![^\n]*--no-pager)'),
     '`journalctl -f` follows the log forever — use `-n N --no-pager`'),
    (re.compile(r'(?<![-\w])watch\s'),
     '`watch` loops forever — run the command once and check its output'),
    (re.compile(r'(?i)press\s+ctrl'),
     'contains a "press Ctrl+C" step — a skill has no keyboard; a command that '
     'needs Ctrl+C to stop must not run in the foreground at all'),
    (re.compile(r'(?i)\bwait for\b[^\n]*\b(?:then|and)\b[^\n]*\b(?:ctrl|stop|kill)\b'),
     'describes a manual wait-then-stop step — automate it (systemd, or a '
     '`timeout`-wrapped run) instead'),
    (re.compile(r'\bmysql_secure_installation\b'),
     'mysql_secure_installation is interactive — set the same state with '
     '`mariadb -e "…"` statements'),
    (re.compile(r'(?<![-\w])read\s+-\w'),
     'a bash `read` waits for stdin that never comes — hardcode or parameterize '
     'the value'),
    # Bare enable/reset/delete prompts "Proceed (y|n)?". `--force` between `ufw`
    # and the verb naturally prevents this from matching the safe form.
    (re.compile(r'\bufw\s+(?:enable|reset|delete)\b'),
     '`ufw enable/reset/delete` prompts "Proceed (y|n)?" — add `--force` (or '
     'use non-prompting `ufw allow …`)'),
]

# Foreground server/daemon launches that never return — checked per line so a
# systemd/background/timeout context on the SAME line exempts them.
_SERVER_LAUNCH = re.compile(
    r'\bjava\b[^\n]*-jar\b|python\d?\s+-m\s+http\.server|node\s+\S+\.js|'
    r'\bnpm\s+start\b|\bnc\s+-l')
_SERVER_OK = re.compile(r'ExecStart|nohup|systemd-run|systemctl|\btimeout\s|&\s*$')

# apt install needs an assume-yes somewhere on the line (guard may come before
# the command, e.g. `DEBIAN_FRONTEND=noninteractive apt-get install …`).
_APT_INSTALL = re.compile(r'\bapt(?:-get)?\s+(?:-\S+\s+)*install\b')
_APT_OK = re.compile(r'\s-y\b|--yes|--assume-yes|DEBIAN_FRONTEND=|(?<![-\w])-q\b')


def lint(body):
    """Return a list of warnings about steps that would block an unattended run.
    Empty list = looks safe to execute over ssh_exec."""
    warnings = []
    text = body or ''
    for pat, msg in _LINT_RULES:
        if pat.search(text):
            warnings.append(msg)
    for line in text.splitlines():
        if _SERVER_LAUNCH.search(line) and not _SERVER_OK.search(line):
            warnings.append(
                'launches a server/daemon in the foreground (it never returns) — '
                'run it under a systemd unit, not as a step: `' + line.strip()[:70] + '`')
            break
    for line in text.splitlines():
        if _APT_INSTALL.search(line) and not _APT_OK.search(line):
            warnings.append(
                'apt install without `-y` waits for a yes/no prompt — add `-y` '
                '(and `DEBIAN_FRONTEND=noninteractive` to guard debconf prompts)')
            break
    return warnings


def _row(r):
    try:
        params = json.loads(r['params_json'] or '{}')
    except ValueError:
        params = {}
    return {'id': r['id'], 'name': r['name'], 'description': r['description'] or '',
            'params': params, 'body': r['body'], 'approved': bool(r['approved']),
            'created_at': r['created_at']}


def get_by_name(name):
    r = db.query_one('SELECT * FROM skills WHERE name=? ORDER BY id LIMIT 1', (name,))
    return _row(r) if r else None


def get(sid):
    r = db.query_one('SELECT * FROM skills WHERE id=?', (sid,))
    return _row(r) if r else None


def save(name, description='', body='', params=None, approved=None):
    """Create a new draft skill, or update an existing one by name. Updating does
    NOT change approval state (refining a playbook doesn't silently un-approve);
    new skills start unapproved unless approved=True is passed."""
    name = (name or '').strip()
    if not name:
        raise ValueError('name required')
    existing = get_by_name(name)
    pj = json.dumps(params or {})
    if existing:
        appr = existing['approved'] if approved is None else bool(approved)
        db.execute('UPDATE skills SET description=?, body=?, params_json=?, approved=? WHERE id=?',
                   (description, body, pj, 1 if appr else 0, existing['id']))
        return existing['id']
    return db.execute(
        'INSERT INTO skills(name, description, body, params_json, approved, created_at)'
        ' VALUES(?,?,?,?,?,?)',
        (name, description, body, pj, 1 if approved else 0, _now()))


def update(sid, name=None, description=None, body=None):
    cur = get(sid)
    if not cur:
        return
    db.execute('UPDATE skills SET name=?, description=?, body=? WHERE id=?',
               (name if name is not None else cur['name'],
                description if description is not None else cur['description'],
                body if body is not None else cur['body'], sid))


def set_approved(sid, approved):
    db.execute('UPDATE skills SET approved=? WHERE id=?', (1 if approved else 0, sid))


def delete(sid):
    db.execute('DELETE FROM skills WHERE id=?', (sid,))


def list_all():
    return [_row(r) for r in db.query('SELECT * FROM skills ORDER BY name')]


def list_approved():
    return [_row(r) for r in db.query('SELECT * FROM skills WHERE approved=1 ORDER BY name')]


def search(query, limit=6):
    like = f'%{query}%'
    rows = db.query('SELECT * FROM skills WHERE name LIKE ? OR description LIKE ? OR body LIKE ? '
                    'ORDER BY approved DESC, name LIMIT ?', (like, like, like, limit))
    return [_row(r) for r in rows]


def context_text():
    """One-line-per-skill summary of APPROVED skills, injected into context."""
    approved = list_approved()
    if not approved:
        return ''
    lines = [f"- {s['name']}: {s['description']}" for s in approved]
    return ('PLAYBOOKS YOU HAVE (approved reusable procedures — prefer these over '
            'improvising; read the full body with skill_search before running one):\n' +
            '\n'.join(lines))
