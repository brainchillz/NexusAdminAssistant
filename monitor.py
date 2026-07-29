"""Back-seat health monitoring.

A background thread polls each SSH host for basic health (reachable, OS, uptime,
load, memory %, max-disk %), computes a status (ok/warn/bad) + issues, keeps the
latest snapshot in memory, samples history to SQLite, and fires proactive alerts
(disk filling, unreachable) to a notification webhook. Its outputs feed: sidebar
health dots, the agent's host context + the host_health tool, and notifications.

This is deliberately lightweight — our hosts are generic SSH boxes, not the
dashboard fleet NexusController's monitoring.py was written for.
"""
import threading
import time
from datetime import datetime, timezone

import requests

import logs
from store import db, settings

log = logs.get('monitor')

POLL_INTERVAL = 120
DISK_WARN, DISK_BAD = 85, 95
MEM_WARN = 95
LOAD_PER_CORE_WARN = 4.0

_snap = {}          # host_id -> snapshot dict
_prev_issues = {}   # host_id -> set(issue keys) for alert debounce
_lock = threading.Lock()
_started = False

# single-shot metric probe (runs in the host's shell; no sudo needed)
METRIC_CMD = r"""
DTOP=$(df -P 2>/dev/null | awk 'NR>1 && $1 !~ /^(tmpfs|devtmpfs|udev|overlay)$/ {gsub(/%/,"",$5); print $5" "$6}' | sort -rn | head -1)
printf 'OS=%s\n' "$(. /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME")"
printf 'UP=%s\n' "$(cut -d. -f1 /proc/uptime 2>/dev/null)"
printf 'CORES=%s\n' "$(nproc 2>/dev/null || echo 1)"
printf 'LOAD=%s\n' "$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)"
printf 'MEM=%s\n' "$(free 2>/dev/null | awk '/Mem:/{a=$7; printf "%d",($2>0)?((a>0)?($2-a)/$2*100:$3/$2*100):0}')"
printf 'DISK=%s\n' "$(printf '%s' "$DTOP" | cut -d' ' -f1)"
printf 'DISKMNT=%s\n' "$(printf '%s' "$DTOP" | cut -d' ' -f2)"
"""


def _now():
    return datetime.now(timezone.utc).isoformat()


def parse_metrics(output):
    d = {}
    for line in (output or '').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            d[k.strip()] = v.strip()
    out = {'os': d.get('OS', ''), 'disk_mnt': d.get('DISKMNT', '')}
    for k, src in (('uptime', 'UP'), ('cores', 'CORES'), ('mem', 'MEM'), ('disk', 'DISK')):
        try:
            out[k] = int(float(d.get(src, 0)))
        except (ValueError, TypeError):
            out[k] = 0
    try:
        out['load1'] = float(d.get('LOAD', 0))
    except (ValueError, TypeError):
        out['load1'] = 0.0
    cores = out['cores'] or 1
    out['cpu'] = min(100, int(out['load1'] / cores * 100))
    return out


def compute_status(reachable, m):
    """Return (status, issues[]). issues are (key, text) tuples."""
    if not reachable:
        return 'bad', [('unreachable', 'unreachable')]
    issues = []
    disk = m.get('disk', 0)
    if disk >= DISK_BAD:
        issues.append(('disk', f"disk {disk}% full on {m.get('disk_mnt', '/')}"))
    elif disk >= DISK_WARN:
        issues.append(('disk', f"disk {disk}% on {m.get('disk_mnt', '/')}"))
    if m.get('mem', 0) >= MEM_WARN:
        issues.append(('mem', f"memory {m['mem']}%"))
    cores = m.get('cores', 1) or 1
    if m.get('load1', 0) > LOAD_PER_CORE_WARN * cores:
        issues.append(('load', f"load {m['load1']:.1f} on {cores} cores"))
    status = 'ok'
    if any(k in ('disk',) and 'full' in t for k, t in issues):
        status = 'bad'
    elif issues:
        status = 'warn'
    return status, issues


def snapshot(host_id):
    with _lock:
        return dict(_snap[host_id]) if host_id in _snap else None


def all_snapshots():
    with _lock:
        return {k: dict(v) for k, v in _snap.items()}


def health_line(host_id):
    s = snapshot(host_id)
    if not s:
        return ''
    if not s['reachable']:
        return 'LIVE HEALTH: host is currently unreachable.'
    parts = [f"disk {s['metrics'].get('disk', 0)}%", f"mem {s['metrics'].get('mem', 0)}%",
             f"cpu~{s['metrics'].get('cpu', 0)}%", f"up {s['metrics'].get('uptime', 0) // 86400}d"]
    line = 'LIVE HEALTH: ' + ' · '.join(parts)
    if s['issues']:
        line += ' — ISSUES: ' + '; '.join(t for _, t in s['issues'])
    return line


# ─── polling ──────────────────────────────────────────────────────────
def poll_host(host):
    import inventory
    from agent.tools import ssh
    secrets = inventory.secrets_for(host)
    res = ssh.run(host, secrets, METRIC_CMD, timeout=20)
    reachable = res['exit_code'] == 0 and 'OS=' in res.get('output', '')
    metrics = parse_metrics(res['output']) if reachable else {}
    status, issues = compute_status(reachable, metrics)
    snap = {'host_id': host['id'], 'ts': _now(), 'reachable': reachable,
            'status': status, 'issues': issues, 'metrics': metrics,
            'error': '' if reachable else (res.get('error') or 'no metrics')}
    with _lock:
        _snap[host['id']] = snap
    db.execute('INSERT INTO host_metrics(host_id, ts, reachable, cpu, mem, disk, load1)'
               ' VALUES(?,?,?,?,?,?,?)',
               (host['id'], snap['ts'], 1 if reachable else 0, metrics.get('cpu', 0),
                metrics.get('mem', 0), metrics.get('disk', 0), metrics.get('load1', 0)))
    if reachable:
        db.execute('UPDATE hosts SET last_seen=? WHERE id=?', (snap['ts'], host['id']))
    _check_alerts(host, snap)
    return snap


def _check_alerts(host, snap):
    keys = {k for k, _ in snap['issues']}
    prev = _prev_issues.get(host['id'], set())
    new = keys - prev
    _prev_issues[host['id']] = keys
    if new:
        texts = [t for k, t in snap['issues'] if k in new]
        notify(f"[{host['name']}] {snap['status']}: " + '; '.join(texts))


def notify(text):
    """Send an operational alert to the notification webhook + Telegram.
    Public: service checks (services.py) raise alerts through here too."""
    url = settings.get_notify().get('url')
    if url:
        try:
            requests.post(url, json={'text': text}, timeout=10)
        except requests.RequestException as e:
            # a dropped alert is exactly the thing you need to know about later
            log.warning('alert webhook failed: %s', e)
    try:
        import telegrambot
        telegrambot.push('🔔 ' + text)
    except Exception as e:  # noqa: BLE001
        log.warning('alert telegram push failed: %s', e)


def _cycle():
    from store import db as _db
    hosts = _db.query("SELECT * FROM hosts WHERE conn_type='ssh' OR conn_type=''")
    for h in hosts:
        try:
            poll_host(h)
        except Exception:  # noqa: BLE001 — one bad host never stops the cycle
            with _lock:
                _snap[h['id']] = {'host_id': h['id'], 'ts': _now(), 'reachable': False,
                                  'status': 'bad', 'issues': [('error', 'probe failed')],
                                  'metrics': {}, 'error': 'probe failed'}


def start_monitor():
    global _started
    with _lock:
        if _started:
            return
        _started = True

    def loop():
        time.sleep(5)  # let the app settle before the first poll
        while True:
            try:
                _cycle()
            except Exception:  # noqa: BLE001 — never let the poller die
                log.exception('monitor cycle failed')
            time.sleep(POLL_INTERVAL)
    threading.Thread(target=loop, daemon=True).start()
