"""Application & service checks — is the service up, and where do I fix it?

Host monitoring (monitor.py) answers "is the box healthy". This answers "is the
thing people actually use working" — the website, the DNS resolver, the file
share — which is the question that gets asked first and the one host metrics
routinely get wrong: a server with perfect load and disk can still be serving
502s.

Two separate facts per check, deliberately:
  * `target` — where the service ANSWERS (a URL, a VIP, a floating IP, a
    published container port). What we probe.
  * `host_id` — the inventory host the service RUNS ON. Where you go to fix it.
They differ constantly (reverse proxies, VIPs, NAT), and only the second is
useful to an agent asked to repair something.

With `auto_fix` on, a check going red starts an unattended agent run against
the pinned host under a pre-authorized envelope — the same ceiling/allow-list
model as scheduled jobs (agent/policy.unattended_decision), so troubleshooting
proceeds on its own while anything beyond the envelope is deferred for
approval rather than silently performed.

Probes are pure-ish and unit-tested via probe_once(); the poller is a thin loop.
"""
import json
import secrets as _secrets
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone

import requests

import logs
from store import db

log = logs.get('services')

KINDS = ('http', 'https', 'tcp', 'dns', 'smb', 'ssh', 'ping', 'cert')

# Stored check state (what the UI shows).
STATUSES = ('unknown', 'ok', 'warn', 'down')

# What a PROBE returns — deliberately a different vocabulary from the stored
# status, because conflating them was a bug: a probe used to return 'warn' for a
# 404, and the escalation expression could only ever escalate to what the probe
# already said, so a 404 stayed 'warn' through any number of failures and never
# reached 'down' (the state that triggers auto-fix). A probe now reports what it
# SAW; run_check alone decides what that means over time.
#   ok      — working
#   fail    — genuinely broken. Counts toward fail_threshold, becomes 'down'.
#   warn    — ADVISORY only: working now, but you should know (cert expiring).
#             Never escalates, no matter how long it persists.
#   unknown — the check itself is unusable (misconfigured, unknown kind). Not an
#             outage; never counts and never escalates.
PROBE_VERDICTS = ('ok', 'fail', 'warn', 'unknown')
DEFAULT_PORTS = {'http': 80, 'https': 443, 'smb': 445, 'ssh': 22, 'dns': 53, 'cert': 443}
POLL_TICK = 15          # how often the loop looks for checks that are due
RESULT_RETENTION_DAYS = 14

_started = False
_lock = threading.Lock()


def _now_dt():
    return datetime.now(timezone.utc)


def _now():
    return _now_dt().isoformat()


# ─── probes ───────────────────────────────────────────────────────────
def _split_target(target, default_port):
    """host[:port] → (host, port). Tolerates a bare URL for the tcp/ssh kinds."""
    t = (target or '').strip()
    if '://' in t:
        t = t.split('://', 1)[1]
    t = t.split('/', 1)[0]
    if t.startswith('['):                       # bracketed IPv6
        addr, _, rest = t[1:].partition(']')
        port = rest.lstrip(':')
        return addr, int(port) if port.isdigit() else default_port
    if t.count(':') == 1:
        addr, _, port = t.partition(':')
        return addr, int(port) if port.isdigit() else default_port
    return t, default_port


def _probe_tcp(target, port, timeout, _opts):
    addr, port = _split_target(target, port)
    with socket.create_connection((addr, port), timeout=timeout):
        return 'ok', ''


def _probe_ssh(target, port, timeout, _opts):
    addr, port = _split_target(target, port)
    with socket.create_connection((addr, port), timeout=timeout) as s:
        banner = s.recv(256).decode(errors='replace').strip()
    if not banner.startswith('SSH-'):
        return 'fail', f'port open but no SSH banner ({banner[:40]!r})'
    return 'ok', ''


def _probe_smb(target, port, timeout, _opts):
    """SMB without a client library: a TCP session plus the negotiate handshake.
    Open-but-mute is a real failure mode (a wedged smbd), so we check it replies."""
    addr, port = _split_target(target, port or 445)
    # minimal SMB1 NegotiateProtocol asking for SMB2 — every modern server answers
    neg = bytes.fromhex(
        '000000d4ff534d4272000000001843c800000000000000000000000000'
        'feff0000000000b100025043204e4554574f524b2050524f4752414d20'
        '312e3000024d4943524f534f4654204e4554574f524b5320312e303300'
        '024d4943524f534f4654204e4554574f524b5320332e3000024c414e4d'
        '414e312e3000024c4d312e325830303200024454204c414e4d414e322e'
        '3100024e54204c414e4d414e20312e3000025348415245202e0000024e'
        '54204c4d20302e313200025342322e3030320002534d4220322e2a2a2a00')
    with socket.create_connection((addr, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(neg)
        resp = s.recv(256)
    if len(resp) < 8:
        return 'fail', 'connected but the SMB server did not answer the handshake'
    if resp[4:8] not in (b'\xffSMB', b'\xfeSMB'):
        return 'fail', 'connected but the reply was not SMB'
    return 'ok', ''


def _probe_ping(target, _port, timeout, _opts):
    """No ICMP without root, so this is a reachability probe: try the TCP ports a
    host almost always answers on. Named 'ping' because that is what people mean."""
    addr, _ = _split_target(target, 0)
    errors = []
    for port in (22, 80, 443, 445, 3389):
        try:
            with socket.create_connection((addr, port), timeout=min(timeout, 3)):
                return 'ok', ''
        except OSError as e:
            errors.append(f'{port}:{e.__class__.__name__}')
    return 'fail', f'no TCP response from {addr} ({", ".join(errors)})'


def _probe_dns(target, port, timeout, opts):
    """Ask a resolver for a name and (optionally) require an expected answer."""
    qname = (opts.get('dns_query') or '').strip()
    if not qname:
        return 'unknown', 'no name configured to look up (set dns_query)'
    server, port = _split_target(target, port or 53)
    qtype = {'A': 1, 'AAAA': 28, 'MX': 15, 'TXT': 16, 'NS': 2,
             'CNAME': 5, 'PTR': 12}.get((opts.get('dns_type') or 'A').upper(), 1)
    qid = _secrets.randbelow(65536)
    header = qid.to_bytes(2, 'big') + b'\x01\x00' + (1).to_bytes(2, 'big') + b'\x00' * 6
    qname_wire = b''.join(bytes([len(p)]) + p.encode('idna')
                          for p in qname.rstrip('.').split('.')) + b'\x00'
    packet = header + qname_wire + qtype.to_bytes(2, 'big') + b'\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        resp, _ = s.recvfrom(4096)
    if len(resp) < 12 or resp[:2] != packet[:2]:
        return 'fail', 'malformed DNS reply'
    rcode = resp[3] & 0x0F
    answers = int.from_bytes(resp[6:8], 'big')
    if rcode == 3:
        return 'fail', f'{qname} does not resolve (NXDOMAIN)'
    if rcode != 0:
        return 'fail', f'resolver returned error code {rcode}'
    if not answers:
        return 'fail', f'{qname} resolved with no answer records'
    expect = (opts.get('dns_expect') or '').strip()
    if expect:
        ips = _dns_answer_ips(resp)
        if expect not in ips:
            return 'fail', (f'{qname} resolved to {", ".join(ips) or "?"}, '
                            f'expected {expect}')
    return 'ok', ''


def _dns_answer_ips(resp):
    """Pull A/AAAA rdata out of a response. Best-effort: used for the expected-
    answer check, and a parse miss degrades to 'no match' rather than an error."""
    ips = []
    try:
        i = 12
        while resp[i]:                                   # skip the question name
            i += resp[i] + 1
        i += 5
        for _ in range(int.from_bytes(resp[6:8], 'big')):
            if resp[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while resp[i]:
                    i += resp[i] + 1
                i += 1
            rtype = int.from_bytes(resp[i:i + 2], 'big')
            rdlen = int.from_bytes(resp[i + 8:i + 10], 'big')
            rdata = resp[i + 10:i + 10 + rdlen]
            if rtype == 1 and rdlen == 4:
                ips.append('.'.join(str(b) for b in rdata))
            elif rtype == 28 and rdlen == 16:
                ips.append(':'.join(rdata[j:j + 2].hex() for j in range(0, 16, 2)))
            i += 10 + rdlen
    except (IndexError, ValueError):
        pass
    return ips


def _probe_http(target, port, timeout, opts, scheme='http'):
    url = (target or '').strip()
    if '://' not in url:
        host, p = _split_target(url, port or DEFAULT_PORTS[scheme])
        default = DEFAULT_PORTS[scheme]
        url = f'{scheme}://{host}' + (f':{p}' if p != default else '')
    r = requests.get(url, timeout=timeout, allow_redirects=True,
                     verify=bool(opts.get('verify_tls', True)),
                     headers={'User-Agent': 'NexusAdminAssistant/health-check'})
    expect = opts.get('expect_status')
    if expect:
        try:
            if r.status_code != int(expect):
                return 'fail', f'HTTP {r.status_code} (expected {int(expect)})'
        except (TypeError, ValueError):
            pass
    elif r.status_code >= 500:
        return 'fail', f'HTTP {r.status_code} — the server is erroring'
    elif r.status_code >= 400:
        # 404/403 on a URL someone chose to monitor means the thing they are
        # watching is not being served. That is an outage, not a curiosity.
        return 'fail', f'HTTP {r.status_code}'
    body = (opts.get('expect_body') or '').strip()
    if body and body not in r.text:
        return 'fail', f'page loaded (HTTP {r.status_code}) but did not contain {body!r}'
    return 'ok', ''


def _probe_cert(target, port, timeout, opts):
    """TLS certificate expiry — the outage everyone schedules for themselves."""
    addr, port = _split_target(target, port or 443)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # we want the dates even if untrusted
    with socket.create_connection((addr, port), timeout=timeout) as raw, \
            ctx.wrap_socket(raw, server_hostname=opts.get('sni') or addr) as s:
        cert = ssl.DER_cert_to_PEM_cert(s.getpeercert(binary_form=True))
    try:
        from cryptography import x509
        not_after = x509.load_pem_x509_certificate(cert.encode()).not_valid_after_utc
    except Exception as e:  # noqa: BLE001 — cryptography version differences
        return 'unknown', f'could not read the certificate dates: {e}'
    days = (not_after - _now_dt()).days
    warn_days = int(opts.get('cert_warn_days') or 21)
    if days < 0:
        return 'fail', f'the TLS certificate EXPIRED {abs(days)} day(s) ago'
    if days <= warn_days:
        # advisory: it still works today, so never escalate to an outage
        return 'warn', f'the TLS certificate expires in {days} day(s)'
    return 'ok', ''


_PROBES = {
    'http': lambda t, p, to, o: _probe_http(t, p, to, o, 'http'),
    'https': lambda t, p, to, o: _probe_http(t, p, to, o, 'https'),
    'tcp': _probe_tcp, 'dns': _probe_dns, 'smb': _probe_smb,
    'ssh': _probe_ssh, 'ping': _probe_ping, 'cert': _probe_cert,
}


def probe_once(kind, target, port=0, timeout=10, options=None):
    """Run one probe. Returns {status, error, latency_ms}. Never raises."""
    opts = options or {}
    fn = _PROBES.get(kind)
    if not fn:
        return {'status': 'unknown', 'error': f'unknown check type {kind!r}', 'latency_ms': 0}
    if not (target or '').strip():
        return {'status': 'unknown', 'error': 'no target configured', 'latency_ms': 0}
    started = time.monotonic()
    try:
        status, error = fn(target, port or DEFAULT_PORTS.get(kind, 0), timeout, opts)
    except requests.exceptions.SSLError as e:
        status, error = 'fail', f'TLS error: {e.__class__.__name__}'
    except requests.exceptions.ConnectTimeout:
        status, error = 'fail', 'connection timed out'
    except requests.exceptions.ConnectionError:
        status, error = 'fail', 'could not connect'
    except requests.RequestException as e:
        status, error = 'fail', f'request failed: {e.__class__.__name__}'
    except socket.timeout:
        status, error = 'fail', 'timed out'
    except socket.gaierror:
        status, error = 'fail', 'DNS lookup for the target failed'
    except OSError as e:
        status, error = 'fail', f'{e.strerror or e}'
    except Exception as e:  # noqa: BLE001 — a probe must never break the poller
        status, error = 'fail', f'{e.__class__.__name__}: {e}'
    return {'status': status, 'error': error,
            'latency_ms': int((time.monotonic() - started) * 1000)}


# ─── CRUD ─────────────────────────────────────────────────────────────
def _row(r):
    return {
        'id': r['id'], 'name': r['name'], 'kind': r['kind'], 'target': r['target'],
        'port': r['port'], 'host_id': r['host_id'], 'enabled': bool(r['enabled']),
        'interval_s': r['interval_s'], 'timeout_s': r['timeout_s'],
        'options': json.loads(r['options_json'] or '{}'),
        'fail_threshold': r['fail_threshold'],
        'auto_fix': bool(r['auto_fix']), 'auto_fix_ceiling': r['auto_fix_ceiling'],
        'auto_fix_allow': json.loads(r['auto_fix_allow_json'] or '[]'),
        'auto_fix_instruction': r['auto_fix_instruction'],
        'auto_fix_cooldown_s': r['auto_fix_cooldown_s'],
        'status': r['status'], 'last_check': r['last_check'], 'last_ok': r['last_ok'],
        'last_error': r['last_error'], 'latency_ms': r['latency_ms'],
        'fail_count': r['fail_count'], 'last_auto_fix': r['last_auto_fix'],
        'created_at': r['created_at'],
    }


def get(check_id):
    r = db.query_one('SELECT * FROM service_checks WHERE id=?', (check_id,))
    return _row(r) if r else None


def list_all():
    return [_row(r) for r in db.query('SELECT * FROM service_checks ORDER BY name')]


def _clean(d, cur=None):
    cur = cur or {}
    kind = d.get('kind', cur.get('kind', 'https'))
    if kind not in KINDS:
        kind = 'https'
    ceiling = d.get('auto_fix_ceiling', cur.get('auto_fix_ceiling', 'caution'))
    if ceiling not in ('safe', 'caution', 'risky', 'critical'):
        ceiling = 'caution'
    return {
        'name': (d.get('name', cur.get('name', '')) or 'check').strip()[:80],
        'kind': kind,
        'target': (d.get('target', cur.get('target', '')) or '').strip()[:300],
        'port': int(d.get('port', cur.get('port', 0)) or 0),
        'host_id': d.get('host_id', cur.get('host_id', '')) or '',
        'enabled': 1 if d.get('enabled', cur.get('enabled', True)) else 0,
        # a check that hammers a service is its own outage — floor the interval
        'interval_s': max(30, int(d.get('interval_s', cur.get('interval_s', 120)) or 120)),
        'timeout_s': max(1, min(60, int(d.get('timeout_s', cur.get('timeout_s', 10)) or 10))),
        'options_json': json.dumps(d.get('options', cur.get('options', {})) or {}),
        'fail_threshold': max(1, int(d.get('fail_threshold', cur.get('fail_threshold', 2)) or 2)),
        'auto_fix': 1 if d.get('auto_fix', cur.get('auto_fix', False)) else 0,
        'auto_fix_ceiling': ceiling,
        'auto_fix_allow_json': json.dumps(d.get('auto_fix_allow', cur.get('auto_fix_allow', [])) or []),
        'auto_fix_instruction': (d.get('auto_fix_instruction',
                                       cur.get('auto_fix_instruction', '')) or '')[:2000],
        'auto_fix_cooldown_s': max(300, int(d.get('auto_fix_cooldown_s',
                                                 cur.get('auto_fix_cooldown_s', 1800)) or 1800)),
    }


def create(d, created_by=''):
    cid = _secrets.token_hex(8)
    v = _clean(d)
    db.execute(
        'INSERT INTO service_checks(id, name, kind, target, port, host_id, enabled,'
        ' interval_s, timeout_s, options_json, fail_threshold, auto_fix, auto_fix_ceiling,'
        ' auto_fix_allow_json, auto_fix_instruction, auto_fix_cooldown_s, created_by,'
        ' created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (cid, v['name'], v['kind'], v['target'], v['port'], v['host_id'], v['enabled'],
         v['interval_s'], v['timeout_s'], v['options_json'], v['fail_threshold'],
         v['auto_fix'], v['auto_fix_ceiling'], v['auto_fix_allow_json'],
         v['auto_fix_instruction'], v['auto_fix_cooldown_s'], created_by, _now()))
    return cid


def update(check_id, d):
    cur = get(check_id)
    if not cur:
        return
    v = _clean(d, cur)
    db.execute(
        'UPDATE service_checks SET name=?, kind=?, target=?, port=?, host_id=?, enabled=?,'
        ' interval_s=?, timeout_s=?, options_json=?, fail_threshold=?, auto_fix=?,'
        ' auto_fix_ceiling=?, auto_fix_allow_json=?, auto_fix_instruction=?,'
        ' auto_fix_cooldown_s=? WHERE id=?',
        (v['name'], v['kind'], v['target'], v['port'], v['host_id'], v['enabled'],
         v['interval_s'], v['timeout_s'], v['options_json'], v['fail_threshold'],
         v['auto_fix'], v['auto_fix_ceiling'], v['auto_fix_allow_json'],
         v['auto_fix_instruction'], v['auto_fix_cooldown_s'], check_id))


def delete(check_id):
    db.execute('DELETE FROM service_checks WHERE id=?', (check_id,))


def history(check_id, limit=100):
    return db.query('SELECT ts, status, latency_ms, error FROM service_check_results'
                    ' WHERE check_id=? ORDER BY id DESC LIMIT ?', (check_id, limit))


# ─── running a check ──────────────────────────────────────────────────
def fold_result(verdict, fail_count, threshold):
    """Fold one probe verdict into (status, fail_count). Pure — the escalation
    rule lives here alone so it can be tested without a socket.

    Only a 'fail' counts. Once `threshold` consecutive failures accumulate the
    check is DOWN and stays down until something works again — it does not
    matter which failure class the probe reported, which is the bug this
    replaces: a 404 reported 'warn', and the old expression could only escalate
    to whatever the probe had already said, so it sat at 'warn' through 122
    consecutive failures against a threshold of 2 and auto-fix never fired.
    """
    if verdict == 'ok':
        return 'ok', 0
    if verdict == 'unknown':
        return 'unknown', fail_count      # misconfigured: not an outage, no count
    if verdict == 'warn':
        return 'warn', fail_count         # advisory (cert expiring): never escalates
    fail_count += 1                       # 'fail'
    # ride out a blip, then commit: sustained failure is an outage
    return ('down' if fail_count >= max(1, threshold) else 'warn'), fail_count


def run_check(check_id, allow_auto_fix=True):
    """Probe once, fold the result into the check's state, and (if the check just
    went red and has auto_fix on) kick off an unattended troubleshooting run.
    Returns the updated check. Never raises."""
    c = get(check_id)
    if not c:
        return None
    res = probe_once(c['kind'], c['target'], c['port'], c['timeout_s'], c['options'])
    prev_status = c['status']
    status, fail_count = fold_result(res['status'], c['fail_count'], c['fail_threshold'])

    now = _now()
    db.execute(
        'UPDATE service_checks SET status=?, last_check=?, last_error=?, latency_ms=?,'
        ' fail_count=?' + (', last_ok=?' if status == 'ok' else '') + ' WHERE id=?',
        ((status, now, res['error'], res['latency_ms'], fail_count, now, check_id)
         if status == 'ok' else
         (status, now, res['error'], res['latency_ms'], fail_count, check_id)))
    db.execute('INSERT INTO service_check_results(check_id, ts, status, latency_ms, error)'
               ' VALUES(?,?,?,?,?)',
               (check_id, now, status, res['latency_ms'], res['error'][:500]))

    if status != prev_status:
        log.info('check %s (%s) %s → %s: %s', c['name'], c['kind'], prev_status, status,
                 res['error'] or 'ok')
        _notify_transition(c, prev_status, status, res)

    # Trigger on the STATE, not the transition. Transition-only meant a repair
    # that didn't work was never retried — the check stayed 'down', so no new
    # edge ever occurred and the cooldown was dead code. It also meant ticking
    # auto-fix on an already-down check did nothing until it recovered and broke
    # again. The cooldown in _maybe_auto_fix is what prevents a repair storm.
    if status == 'down' and c['auto_fix'] and allow_auto_fix:
        _maybe_auto_fix(c, res, repeat=(prev_status == 'down'))
    return get(check_id)


def _notify_transition(c, prev, status, res):
    where = f" on {_host_name(c['host_id'])}" if c['host_id'] else ''
    if status == 'down':
        text = f"🔴 {c['name']} is DOWN{where} — {res['error'] or 'no response'}"
    elif status == 'ok' and prev in ('down', 'warn'):
        text = f"🟢 {c['name']} recovered{where} ({res['latency_ms']}ms)"
    elif status == 'warn':
        text = f"🟡 {c['name']} degraded{where} — {res['error']}"
    else:
        return
    try:
        import monitor
        monitor.notify(text)
    except Exception as e:  # noqa: BLE001 — a dropped alert must not stop checks
        log.warning('service alert failed: %s', e)


def _host_name(host_id):
    r = db.query_one('SELECT name FROM hosts WHERE id=?', (host_id,)) if host_id else None
    return r['name'] if r else ''


def auto_fix_ready(c, now=None):
    """Cooldown gate: never start a second repair run while one may still be
    working, and never loop on a service that is down for reasons the agent
    cannot fix (an unplugged switch shouldn't generate a run every 2 minutes)."""
    if not c['last_auto_fix']:
        return True
    try:
        last = datetime.fromisoformat(c['last_auto_fix'])
    except ValueError:
        return True
    return (now or _now_dt()) - last >= timedelta(seconds=c['auto_fix_cooldown_s'])


def build_instruction(c, res):
    """What the agent is actually asked to do when a check goes red."""
    if c['auto_fix_instruction'].strip():
        return c['auto_fix_instruction'].strip()
    where = _host_name(c['host_id']) or 'this host'
    return (
        f"The service check \"{c['name']}\" just started failing.\n"
        f"- What it checks: a {c['kind']} probe of {c['target']}"
        + (f":{c['port']}" if c['port'] else '') + '\n'
        f"- The failure: {res.get('error') or 'no response'}\n"
        f"- The service runs on {where}, which is the host you are acting on "
        f"(the probe target may be a proxy, VIP or floating IP — fix it at the source).\n\n"
        "Investigate and repair it if you safely can: check whether the service is "
        "running and listening, read its recent logs and configuration, look for a full "
        "disk or a failed dependency, and restart it if that is genuinely the fix. "
        "Verify the service actually answers again afterwards. If the cause is outside "
        "this host or the fix is riskier than your envelope allows, stop and report what "
        "you found and what you would do — do not force it."
    )


def _maybe_auto_fix(c, res, repeat=False):
    if not c['host_id']:
        log.warning('check %s is down with auto-fix on but no host pinned', c['name'])
        return
    if not auto_fix_ready(c):
        # every poll while down reaches here; keep it at debug so a long outage
        # doesn't fill the log with one line every interval
        log.debug('check %s down; auto-fix in cooldown', c['name'])
        return
    if repeat:
        log.info('check %s still down after the last attempt; retrying auto-fix', c['name'])
    db.execute('UPDATE service_checks SET last_auto_fix=? WHERE id=?', (_now(), c['id']))
    threading.Thread(target=_run_auto_fix, args=(c['id'], res), daemon=True,
                     name=f"autofix-{c['id']}").start()


def _run_auto_fix(check_id, res):
    """Unattended troubleshooting run under the check's pre-authorized envelope."""
    import inventory
    from agent import core
    c = get(check_id)
    if not c:
        return
    host = db.query_one('SELECT * FROM hosts WHERE id=?', (c['host_id'],))
    if not host:
        log.warning('auto-fix for %s: pinned host is gone', c['name'])
        return
    user = _agent_user()
    job = {'id': f"check:{c['id']}", 'name': f"auto-fix {c['name']}",
           'host_id': c['host_id'], 'instruction': build_instruction(c, res),
           'ceiling': c['auto_fix_ceiling'], 'allow': c['auto_fix_allow']}
    log.info('auto-fix starting for %s on %s (ceiling %s)', c['name'],
             host['name'], c['auto_fix_ceiling'])
    try:
        # deferred actions are recorded against no job row (this isn't a scheduled
        # job), so pass a defer sink that records + notifies the same way
        out = core.run_unattended(job, dict(host), inventory.secrets_for(host), user,
                                  on_defer=_defer_sink)
        status = out.get('status')
        after = run_check(check_id, allow_auto_fix=False)   # did it actually work?
        recovered = after and after['status'] == 'ok'
        log.info('auto-fix for %s finished: %s (service %s)', c['name'], status,
                 'recovered' if recovered else 'still failing')
        outcome = 'service recovered ✅' if recovered else 'still failing ⚠'
        deferred = out.get('deferred') or 0
        try:
            import monitor
            monitor.notify(f"🛠 Auto-fix for {c['name']} on {host['name']}: {outcome}"
                           + (f" — {deferred} action(s) need your approval" if deferred else '')
                           + '\n' + (out.get('report') or '')[:1200])
        except Exception as e:  # noqa: BLE001
            log.warning('auto-fix notification failed: %s', e)
        _record_autofix_audit(c, user, status, recovered)
    except Exception:  # noqa: BLE001 — a failed repair must not kill the poller
        log.exception('auto-fix run for %s failed', c['name'])


def _defer_sink(job_id, host_id, tool, args, command, risk):
    """An action the repair run wanted but that sits outside its envelope."""
    import schedule
    schedule.record_deferred(None, host_id, tool, args, command, risk,
                             reason=f'outside auto-fix envelope ({job_id})')


def _record_autofix_audit(c, user, status, recovered):
    db.execute('INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
               ' VALUES(?,?,?,?,?,?,?)',
               (_now(), (user or {}).get('id', ''), (user or {}).get('username', 'system'),
                c['host_id'] or '', f"autofix:{c['name']}",
                f"check {c['kind']} {c['target']} — run {status}, service "
                f"{'recovered' if recovered else 'still failing'}", 'auto'))


def _agent_user():
    """The identity repair runs act as: the configured job user, else an admin."""
    r = db.query_one('SELECT * FROM users WHERE role="admin" ORDER BY created_at LIMIT 1')
    return dict(r) if r else None


# ─── poller ───────────────────────────────────────────────────────────
def _due(c, now):
    if not c['enabled']:
        return False
    if not c['last_check']:
        return True
    try:
        last = datetime.fromisoformat(c['last_check'])
    except ValueError:
        return True
    return (now - last).total_seconds() >= c['interval_s']


def _cycle():
    now = _now_dt()
    for c in list_all():
        if _due(c, now):
            try:
                run_check(c['id'])
            except Exception:  # noqa: BLE001 — one bad check never stops the rest
                log.exception('check %s failed to run', c['name'])


def prune_results(days=RESULT_RETENTION_DAYS):
    cutoff = (_now_dt() - timedelta(days=days)).isoformat()
    db.execute('DELETE FROM service_check_results WHERE ts < ?', (cutoff,))


def start_checker():
    global _started
    with _lock:
        if _started:
            return
        _started = True

    def loop():
        time.sleep(8)          # let the app settle before the first probes
        ticks = 0
        while True:
            try:
                _cycle()
                ticks += 1
                if ticks % 240 == 0:        # ~hourly
                    prune_results()
            except Exception:  # noqa: BLE001 — never let the poller die
                log.exception('service check cycle failed')
            time.sleep(POLL_TICK)
    threading.Thread(target=loop, daemon=True, name='service-checks').start()
