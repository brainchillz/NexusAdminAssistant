"""Scheduled unattended jobs.

A job runs an instruction on a host on a cron schedule (or once at a time), with
NO human present — so its authorization is the pre-approved envelope set at
creation (ceiling + allow-list, see agent/policy.unattended_decision). Anything
outside the envelope is deferred (recorded in deferred_actions) and reported,
never silently performed. Each run produces a report delivered via webhook.

Cron: 5-field "min hour dom mon dow", evaluated in the job's timezone. One-shot:
kind='once', schedule = an ISO datetime.
"""
import json
import secrets as _secrets
import threading
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import requests

import logs
from store import db

log = logs.get('schedule')

SCHED_TICK = 30  # seconds
_started = False
_fired = {}      # job_id -> last minute-key fired (in-memory double-fire guard)
_lock = threading.Lock()


def _now_utc():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


# ─── cron ─────────────────────────────────────────────────────────────
def _parse_field(field, lo, hi):
    out = set()
    for part in field.split(','):
        step = 1
        rng = part
        if '/' in part:
            rng, s = part.split('/', 1)
            step = int(s)
        if rng == '*':
            a, b = lo, hi
        elif '-' in rng:
            a, b = (int(x) for x in rng.split('-', 1))
        else:
            a = b = int(rng)
        out.update(range(a, b + 1, step))
    return out


def _cron_sets(expr):
    f = expr.split()
    if len(f) != 5:
        raise ValueError('cron needs 5 fields: min hour dom mon dow')
    mins = _parse_field(f[0], 0, 59)
    hours = _parse_field(f[1], 0, 23)
    doms = _parse_field(f[2], 1, 31)
    mons = _parse_field(f[3], 1, 12)
    dows = _parse_field(f[4], 0, 7)
    if 7 in dows:
        dows.add(0)
    return mins, hours, doms, mons, dows, (f[2] != '*'), (f[4] != '*')


def cron_match(expr, dt):
    """Does datetime `dt` (in the job's tz) match this cron expression?"""
    try:
        mins, hours, doms, mons, dows, dom_r, dow_r = _cron_sets(expr)
    except ValueError:
        return False
    cron_dow = (dt.weekday() + 1) % 7  # py Mon=0..Sun=6 -> cron Sun=0..Sat=6
    if dt.minute not in mins or dt.hour not in hours or dt.month not in mons:
        return False
    dom_ok, dow_ok = dt.day in doms, cron_dow in dows
    day = (dom_ok or dow_ok) if (dom_r and dow_r) else (dom_ok and dow_ok)
    return day


def is_valid_cron(expr):
    try:
        _cron_sets(expr)
        return True
    except ValueError:
        return False


def compute_next_run(kind, schedule, tz):
    """Next fire time as a UTC ISO string, or '' if none within ~90 days."""
    try:
        z = ZoneInfo(tz)
    except Exception:  # noqa: BLE001
        z = ZoneInfo('UTC')
    if kind == 'once':
        return schedule  # already an ISO datetime
    if not is_valid_cron(schedule):
        return ''
    mins, hours, doms, mons, dows, dom_r, dow_r = _cron_sets(schedule)
    now = _now_utc().astimezone(z).replace(second=0, microsecond=0)
    from datetime import timedelta
    t = now + timedelta(minutes=1)
    for _ in range(90 * 24 * 60):
        cron_dow = (t.weekday() + 1) % 7
        if t.minute in mins and t.hour in hours and t.month in mons:
            dom_ok, dow_ok = t.day in doms, cron_dow in dows
            day = (dom_ok or dow_ok) if (dom_r and dow_r) else (dom_ok and dow_ok)
            if day:
                return t.astimezone(timezone.utc).isoformat()
        t += timedelta(minutes=1)
    return ''


# ─── job CRUD ─────────────────────────────────────────────────────────
def _row(r):
    return {'id': r['id'], 'name': r['name'], 'host_id': r['host_id'],
            'kind': r['kind'], 'schedule': r['schedule'], 'instruction': r['instruction'],
            'enabled': bool(r['enabled']), 'ceiling': r['ceiling'],
            'allow': json.loads(r['allow_json'] or '[]'), 'tz': r['tz'],
            'next_run': r['next_run'], 'created_by': r['created_by'],
            'notify_url': r['notify_url'], 'last_run': r['last_run'],
            'last_status': r['last_status'], 'last_report': r['last_report'],
            'created_at': r['created_at']}


def get(job_id):
    r = db.query_one('SELECT * FROM jobs WHERE id=?', (job_id,))
    return _row(r) if r else None


def list_all():
    return [_row(r) for r in db.query('SELECT * FROM jobs ORDER BY created_at DESC')]


def list_enabled():
    return [_row(r) for r in db.query('SELECT * FROM jobs WHERE enabled=1')]


def create(d, created_by=''):
    jid = _secrets.token_hex(8)
    kind = 'once' if d.get('kind') == 'once' else 'cron'
    ceiling = d.get('ceiling', 'caution')
    if ceiling not in ('safe', 'caution', 'risky', 'critical'):
        ceiling = 'caution'
    tz = d.get('tz', 'UTC')
    schedule = d.get('schedule', '')
    db.execute(
        'INSERT INTO jobs(id, name, host_id, schedule, instruction, enabled, ceiling,'
        ' allow_json, tz, next_run, created_by, notify_url, kind, last_run, last_status,'
        ' last_report, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (jid, d.get('name', 'job'), d.get('host_id'), schedule, d.get('instruction', ''),
         1 if d.get('enabled', True) else 0, ceiling, json.dumps(d.get('allow', [])),
         tz, compute_next_run(kind, schedule, tz), created_by, d.get('notify_url', ''),
         kind, '', '', '', _iso(_now_utc())))
    return jid


def update(job_id, d):
    cur = get(job_id)
    if not cur:
        return
    kind = 'once' if d.get('kind', cur['kind']) == 'once' else 'cron'
    ceiling = d.get('ceiling', cur['ceiling'])
    if ceiling not in ('safe', 'caution', 'risky', 'critical'):
        ceiling = cur['ceiling']
    schedule = d.get('schedule', cur['schedule'])
    tz = d.get('tz', cur['tz'])
    db.execute(
        'UPDATE jobs SET name=?, host_id=?, schedule=?, instruction=?, enabled=?, ceiling=?,'
        ' allow_json=?, tz=?, kind=?, notify_url=?, next_run=? WHERE id=?',
        (d.get('name', cur['name']), d.get('host_id', cur['host_id']), schedule,
         d.get('instruction', cur['instruction']),
         1 if d.get('enabled', cur['enabled']) else 0, ceiling,
         json.dumps(d.get('allow', cur['allow'])), tz, kind,
         d.get('notify_url', cur['notify_url']), compute_next_run(kind, schedule, tz), job_id))


def set_enabled(job_id, enabled):
    db.execute('UPDATE jobs SET enabled=? WHERE id=?', (1 if enabled else 0, job_id))


def delete(job_id):
    db.execute('DELETE FROM jobs WHERE id=?', (job_id,))


def record_deferred(job_id, host_id, tool, args, command, risk, reason='outside job envelope'):
    did = db.execute(
        'INSERT INTO deferred_actions(job_id, host_id, tool, args_json, command, risk, reason,'
        ' status, created_at) VALUES(?,?,?,?,?,?,?,?,?)',
        (job_id, host_id or '', tool, json.dumps(args), command, risk, reason, 'pending',
         _iso(_now_utc())))
    try:
        import telegrambot
        telegrambot.push_deferred(did, command, risk)
    except Exception:  # noqa: BLE001
        pass


def list_deferred(status='pending'):
    rows = db.query('SELECT * FROM deferred_actions WHERE status=? ORDER BY id DESC', (status,))
    return [{'id': r['id'], 'job_id': r['job_id'], 'host_id': r['host_id'], 'tool': r['tool'],
             'args': json.loads(r['args_json'] or '{}'), 'command': r['command'],
             'risk': r['risk'], 'reason': r['reason'], 'created_at': r['created_at']} for r in rows]


def _audit_deferred(row, user, decision):
    """Every resolution of a deferred action is audited, whoever approved it.

    The web route used to write this row itself while the Telegram path called
    approve_deferred() directly — so a phone approval executed a command on a
    host with no audit trail at all. Auditing here covers both callers."""
    db.execute('INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
               ' VALUES(?,?,?,?,?,?,?)',
               (_iso(_now_utc()), (user or {}).get('id', ''), (user or {}).get('username', ''),
                row['host_id'] or '', f"deferred:{row['tool']}",
                (row['command'] or '')[:500], decision))
    log.info('deferred %s id=%s tool=%s host=%s by=%s', decision, row['id'], row['tool'],
             row['host_id'] or '-', (user or {}).get('username', '?'))


def approve_deferred(did, user, add_to_allow=False):
    """Run a deferred action now (as `user`) and mark it approved. The single
    implementation — the web API and the Telegram bridge both go through here."""
    import inventory
    from agent import tools as toolkit
    row = db.query_one('SELECT * FROM deferred_actions WHERE id=?', (did,))
    if not row or row['status'] != 'pending':
        return {'ok': False, 'error': 'not pending'}
    host = db.query_one('SELECT * FROM hosts WHERE id=?', (row['host_id'],)) if row['host_id'] else None
    tool = toolkit.get(row['tool'])
    args = json.loads(row['args_json'] or '{}')
    result = {'ok': True, 'note': 'approved'}
    if tool and (host or not tool.needs_host):
        ctx = toolkit.ToolContext(host=dict(host) if host else None,
                                  secrets=inventory.secrets_for(host) if host else None, user=user)
        try:
            result = tool.run(ctx, args)
        except Exception as e:  # noqa: BLE001
            result = {'ok': False, 'error': str(e)}
            log.warning('deferred %s failed: %s', did, e)
    db.execute('UPDATE deferred_actions SET status=?, resolved_at=? WHERE id=?',
               ('approved', _iso(_now_utc()), did))
    if add_to_allow and row['command'] and row['job_id']:
        job = get(row['job_id'])
        if job and row['command'] not in job['allow']:
            update(row['job_id'], {'allow': job['allow'] + [row['command']]})
    _audit_deferred(row, user, 'approved')
    return result


def deny_deferred(did, user=None):
    row = db.query_one('SELECT * FROM deferred_actions WHERE id=?', (did,))
    if not row or row['status'] != 'pending':
        return
    db.execute('UPDATE deferred_actions SET status=?, resolved_at=? WHERE id=? AND status="pending"',
               ('denied', _iso(_now_utc()), did))
    _audit_deferred(row, user, 'denied')


# ─── running a job ────────────────────────────────────────────────────
def run_job(job_id):
    """Execute one job run unattended and record its report. Safe to call from a
    thread. Never raises."""
    import inventory
    from agent import core
    job = get(job_id)
    if not job:
        return
    try:
        host = secrets = user = None
        if job['created_by']:
            user = db.query_one('SELECT * FROM users WHERE id=?', (job['created_by'],))
        if job['host_id']:
            host = db.query_one('SELECT * FROM hosts WHERE id=?', (job['host_id'],))
            if host:
                secrets = inventory.secrets_for(host)
        result = core.run_unattended(job, host, secrets, user, record_deferred)
        status, report = result['status'], result['report']
    except Exception as e:  # noqa: BLE001
        status, report = 'error', f'job run failed: {e}'
    db.execute('UPDATE jobs SET last_run=?, last_status=?, last_report=?, next_run=? WHERE id=?',
               (_iso(_now_utc()), status, report[:20000],
                compute_next_run(job['kind'], job['schedule'], job['tz']), job_id))
    if job['kind'] == 'once':
        set_enabled(job_id, False)
    _notify(job, status, report)


def _notify(job, status, report):
    text = f"[{job['name']}] {status}\n\n{report[:3500]}"
    url = job.get('notify_url', '')
    if url:
        try:
            requests.post(url, json={'text': text}, timeout=10)
        except requests.RequestException:
            pass
    try:
        import telegrambot
        telegrambot.push(f"*Job: {job['name']}* — {status}\n{report[:1500]}")
    except Exception:  # noqa: BLE001
        pass


# ─── scheduler loop ───────────────────────────────────────────────────
def start_scheduler():
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_loop, daemon=True).start()


def _loop():
    while True:
        try:
            _tick()
        except Exception:  # noqa: BLE001 — never let the loop die
            log.exception('scheduler tick failed')
        time.sleep(SCHED_TICK)


def _tick():
    now = _now_utc()
    for job in list_enabled():
        try:
            z = ZoneInfo(job['tz'])
        except Exception:  # noqa: BLE001
            z = ZoneInfo('UTC')
        local = now.astimezone(z)
        due = False
        if job['kind'] == 'once':
            try:
                at = datetime.fromisoformat(job['schedule'])
                if at.tzinfo is None:
                    at = at.replace(tzinfo=z)
                due = now >= at
            except ValueError:
                due = False
        else:
            minute_key = local.strftime('%Y%m%d%H%M')
            if cron_match(job['schedule'], local) and _fired.get(job['id']) != minute_key:
                _fired[job['id']] = minute_key
                due = True
        if due:
            threading.Thread(target=run_job, args=(job['id'],), daemon=True).start()
