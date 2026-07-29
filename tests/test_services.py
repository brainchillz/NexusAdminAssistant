"""Service checks: probes, failure debouncing, and the auto-fix envelope."""
import http.server
import socket
import threading
from datetime import datetime, timedelta, timezone

import pytest

import services


# ─── target parsing ───────────────────────────────────────────────────
def test_split_target_forms():
    assert services._split_target('10.0.0.5', 443) == ('10.0.0.5', 443)
    assert services._split_target('10.0.0.5:8443', 443) == ('10.0.0.5', 8443)
    assert services._split_target('https://web.lan/status', 443) == ('web.lan', 443)
    assert services._split_target('https://web.lan:8443/x', 443) == ('web.lan', 8443)
    assert services._split_target('[2001:db8::1]:8080', 443) == ('2001:db8::1', 8080)
    assert services._split_target('2001:db8::1', 443)[1] == 443   # bare v6, no port


# ─── live probes against a local socket ───────────────────────────────
@pytest.fixture
def tcp_server():
    """A real listening socket, so the TCP probe is exercised end to end."""
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    banner = {'data': b''}

    def serve():
        try:
            conn, _ = srv.accept()
            if banner['data']:
                conn.sendall(banner['data'])
            conn.close()
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    yield port, banner
    srv.close()


def test_tcp_probe_ok(tcp_server):
    port, _ = tcp_server
    r = services.probe_once('tcp', '127.0.0.1', port, timeout=3)
    assert r['status'] == 'ok' and r['error'] == ''


def test_tcp_probe_refused():
    # port 1 on loopback: nothing listens there
    r = services.probe_once('tcp', '127.0.0.1', 1, timeout=2)
    assert r['status'] == 'fail'      # a real failure; run_check decides if it's an outage
    assert r['error']


def test_ssh_probe_wants_a_banner(tcp_server):
    port, banner = tcp_server
    banner['data'] = b'HTTP/1.1 200 OK\r\n'      # open, but not SSH
    r = services.probe_once('ssh', '127.0.0.1', port, timeout=3)
    assert r['status'] == 'fail', 'a port that will not speak SSH is broken, not advisory'
    assert 'banner' in r['error']


def test_unknown_kind_and_empty_target():
    assert services.probe_once('carrier-pigeon', 'x')['status'] == 'unknown'
    assert services.probe_once('https', '  ')['status'] == 'unknown'


def test_probe_never_raises():
    """Whatever the network does, a probe returns a verdict."""
    for kind in services.KINDS:
        r = services.probe_once(kind, 'no-such-host.invalid', timeout=2)
        assert r['status'] in services.PROBE_VERDICTS
        assert isinstance(r['latency_ms'], int)


def test_dns_probe_needs_a_query_name():
    """A misconfigured check is not an outage — it must never escalate."""
    r = services.probe_once('dns', '127.0.0.1', 53, timeout=2, options={})
    assert r['status'] == 'unknown' and 'dns_query' in r['error']


# ─── state machine ────────────────────────────────────────────────────
def _mk_check(**kw):
    d = {'name': 'test-check', 'kind': 'tcp', 'target': '127.0.0.1', 'port': 1,
         'interval_s': 60, 'timeout_s': 2, 'fail_threshold': 2}
    d.update(kw)
    return services.create(d)


def test_flap_is_absorbed_until_the_threshold(flask_app):
    cid = _mk_check(fail_threshold=3)      # port 1 always fails
    c = services.run_check(cid)
    assert c['status'] == 'warn' and c['fail_count'] == 1, 'one miss is not an outage'
    c = services.run_check(cid)
    assert c['status'] == 'warn' and c['fail_count'] == 2
    c = services.run_check(cid)
    assert c['status'] == 'down' and c['fail_count'] == 3
    services.delete(cid)


def test_recovery_clears_the_failure_count(flask_app, tcp_server):
    port, _ = tcp_server
    cid = _mk_check(fail_threshold=1)
    services.run_check(cid)                                   # fails on port 1
    services.update(cid, {'port': port})                      # now point at a live socket
    c = services.run_check(cid)
    assert c['status'] == 'ok' and c['fail_count'] == 0
    assert c['last_ok']
    services.delete(cid)


def test_history_is_recorded(flask_app):
    cid = _mk_check()
    services.run_check(cid)
    services.run_check(cid)
    rows = services.history(cid)
    assert len(rows) == 2
    assert all(r['status'] in services.STATUSES for r in rows)
    services.delete(cid)


# ─── auto-fix guards ──────────────────────────────────────────────────
def test_interval_and_cooldown_are_floored(flask_app):
    cid = _mk_check(interval_s=1, auto_fix_cooldown_s=5)
    c = services.get(cid)
    assert c['interval_s'] >= 30, 'a check must not hammer the service it watches'
    assert c['auto_fix_cooldown_s'] >= 300, 'auto-fix must not loop on an unfixable outage'
    services.delete(cid)


def test_auto_fix_cooldown_blocks_a_second_run(flask_app):
    cid = _mk_check(auto_fix=True, auto_fix_cooldown_s=1800)
    c = services.get(cid)
    assert services.auto_fix_ready(c), 'never repaired before → ready'

    now = datetime.now(timezone.utc)
    c['last_auto_fix'] = now.isoformat()
    assert not services.auto_fix_ready(c, now=now + timedelta(minutes=5))
    assert services.auto_fix_ready(c, now=now + timedelta(minutes=31))
    services.delete(cid)


def test_auto_fix_does_not_start_without_a_pinned_host(flask_app):
    """The probe target may be a proxy or VIP; repairs need the real host."""
    cid = _mk_check(auto_fix=True, host_id='', fail_threshold=1)
    c = services.run_check(cid)             # goes down, auto_fix on, no host
    assert c['status'] == 'down'            # ...and nothing was launched
    assert c['last_auto_fix'] == ''
    services.delete(cid)


def test_instruction_names_the_host_not_just_the_target(flask_app):
    cid = _mk_check(target='https://shop.example.com')
    c = services.get(cid)
    text = services.build_instruction(c, {'error': 'HTTP 502'})
    assert 'shop.example.com' in text          # what failed
    assert 'proxy, VIP or floating IP' in text  # and the caveat that it may not be the host
    assert 'HTTP 502' in text
    services.delete(cid)


def test_custom_instruction_wins(flask_app):
    cid = _mk_check(auto_fix_instruction='Restart the widget service and verify it.')
    text = services.build_instruction(services.get(cid), {'error': 'x'})
    assert text == 'Restart the widget service and verify it.'
    services.delete(cid)


def test_api_rejects_auto_fix_without_a_host(client, login, flask_app):
    tok = login('admin', 'testpass123')
    r = client.post('/api/checks', json={'name': 'x', 'target': 'https://x.lan',
                                        'auto_fix': True},
                    headers={'X-CSRF-Token': tok})
    assert r.status_code == 400
    assert 'host' in r.get_json()['error']


# ─── escalation: the 404-never-escalates bug ──────────────────────────
# Live regression: a check sat at 'warn' through 122 consecutive HTTP 404s
# against fail_threshold=2, so it never reached 'down' and autonomous
# troubleshooting could never fire.
@pytest.fixture
def http_404_server():
    """A real server that always 404s — reproduces the reported failure."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'not found')

        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_http_404_is_a_failure_not_an_advisory(http_404_server):
    r = services.probe_once('http', f'http://127.0.0.1:{http_404_server}/missing', timeout=5)
    assert r['status'] == 'fail', 'a 404 on a monitored URL is an outage, not a note'
    assert '404' in r['error']


def test_404_escalates_to_down_at_the_threshold(flask_app, http_404_server):
    cid = _mk_check(kind='http', target=f'http://127.0.0.1:{http_404_server}/missing',
                    port=0, fail_threshold=2)
    c = services.run_check(cid)
    assert (c['status'], c['fail_count']) == ('warn', 1)     # blip absorbed
    c = services.run_check(cid)
    assert (c['status'], c['fail_count']) == ('down', 2), 'must escalate at the threshold'
    c = services.run_check(cid)
    assert c['status'] == 'down', 'and stay down while it keeps failing'
    services.delete(cid)


def test_fold_result_escalation_rules():
    # a failure counts and escalates once the threshold is met
    assert services.fold_result('fail', 0, 2) == ('warn', 1)
    assert services.fold_result('fail', 1, 2) == ('down', 2)
    assert services.fold_result('fail', 50, 2) == ('down', 51)
    # threshold of 1 goes straight down
    assert services.fold_result('fail', 0, 1) == ('down', 1)
    # success resets
    assert services.fold_result('ok', 99, 2) == ('ok', 0)
    # advisory never escalates, however long it persists, and never counts
    for n in (0, 5, 500):
        assert services.fold_result('warn', n, 2) == ('warn', n)
    # a misconfigured check is not an outage
    assert services.fold_result('unknown', 3, 2) == ('unknown', 3)


def test_expiring_cert_stays_advisory_forever():
    """The one verdict that must NOT escalate: it still works today."""
    status = 'warn'
    count = 0
    for _ in range(200):
        status, count = services.fold_result('warn', count, 2)
    assert status == 'warn' and count == 0


def test_auto_fix_retries_while_down_once_cooldown_expires(flask_app):
    """Transition-only triggering meant a failed repair was never retried."""
    cid = _mk_check(auto_fix=True, host_id='x', fail_threshold=1,
                    auto_fix_cooldown_s=1800)
    c = services.get(cid)
    now = datetime.now(timezone.utc)

    c['last_auto_fix'] = now.isoformat()
    assert not services.auto_fix_ready(c, now=now + timedelta(minutes=10))
    assert services.auto_fix_ready(c, now=now + timedelta(minutes=31)), \
        'a check still down after the cooldown must be retried'
    services.delete(cid)


def test_still_down_check_calls_auto_fix(flask_app, monkeypatch):
    """The trigger is the STATE (down), not the edge into it."""
    calls = []
    monkeypatch.setattr(services, '_maybe_auto_fix',
                        lambda c, res, repeat=False: calls.append(repeat))
    cid = _mk_check(auto_fix=True, host_id='x', fail_threshold=1)  # port 1 = refused
    services.run_check(cid)                      # ok -> down (first)
    services.run_check(cid)                      # down -> down (repeat)
    assert calls == [False, True], 'a still-down check must keep asking for a repair'
    services.delete(cid)
