"""Route-level authorization + CSRF regressions.

These are the tests that could never exist while `import app` booted the whole
service. Each one pins a hole that was live: conversation transcripts readable
across users and tag scopes, deferred approvals visible/deniable estate-wide,
and cookie-authenticated mutations with no CSRF token.
"""
import secrets as _secrets

import pytest

from store import db


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _mk_host(name, tags):
    import inventory
    return inventory.create({'name': name, 'address': '10.0.0.9', 'port': 22,
                             'conn_type': 'ssh', 'tags': tags, 'autonomy_level': 'default'})


def _mk_convo(uid, host_id, title='secret work'):
    cid = _secrets.token_hex(8)
    db.execute('INSERT INTO conversations(id, host_id, user_id, title, created_at, updated_at)'
               ' VALUES(?,?,?,?,?,?)', (cid, host_id, uid, title, _now(), _now()))
    db.execute('INSERT INTO messages(conversation_id, role, content, created_at) VALUES(?,?,?,?)',
               (cid, 'tool', '$ cat /etc/shadow\nroot:$6$hunter2', _now()))
    return cid


@pytest.fixture
def two_users(make_user):
    alice, apw = make_user('alice-authz', role='operator', tags=['web'])
    bob, bpw = make_user('bob-authz', role='operator', tags=['db'])
    return (alice, apw), (bob, bpw)


def test_other_users_transcript_is_not_readable(client, login, two_users):
    (alice, apw), (bob, bpw) = two_users
    host = _mk_host('web-authz', ['web'])
    cid = _mk_convo(alice['id'], host)

    login(bob['username'], bpw)
    r = client.get(f'/api/conversations/{cid}')
    assert r.status_code == 404, 'bob read alice\'s transcript'
    body = r.get_data(as_text=True)
    assert 'hunter2' not in body


def test_conversation_list_is_scoped(client, login, two_users):
    (alice, apw), (bob, bpw) = two_users
    host = _mk_host('web-authz2', ['web'])
    _mk_convo(alice['id'], host, title='alice-only-title')

    login(bob['username'], bpw)
    titles = [c['title'] for c in client.get('/api/conversations').get_json()['conversations']]
    assert 'alice-only-title' not in titles


def test_owner_can_read_their_own_transcript(client, login, two_users):
    (alice, apw), _ = two_users
    host = _mk_host('web-authz3', ['web'])
    cid = _mk_convo(alice['id'], host)

    login(alice['username'], apw)
    r = client.get(f'/api/conversations/{cid}')
    assert r.status_code == 200
    assert r.get_json()['messages']


def test_admin_sees_everything(client, login, two_users):
    (alice, apw), _ = two_users
    host = _mk_host('web-authz4', ['web'])
    cid = _mk_convo(alice['id'], host)

    login('admin', 'testpass123')
    assert client.get(f'/api/conversations/{cid}').status_code == 200


def test_out_of_scope_host_hides_own_conversation(client, login, two_users):
    """Alice's conversation ran on a host she no longer has scope for."""
    (alice, apw), _ = two_users
    host = _mk_host('db-authz', ['db'])          # alice is scoped to 'web'
    cid = _mk_convo(alice['id'], host)

    login(alice['username'], apw)
    assert client.get(f'/api/conversations/{cid}').status_code == 404


def test_mutating_call_without_csrf_is_rejected(client, login, two_users):
    (alice, apw), _ = two_users
    login(alice['username'], apw)
    # a cross-site form post arrives with cookies but no X-CSRF-Token header
    r = client.post('/api/conversations', json={})
    assert r.status_code == 403
    assert 'CSRF' in r.get_json()['error']


def test_mutating_call_with_csrf_succeeds(client, login, two_users):
    (alice, apw), _ = two_users
    tok = login(alice['username'], apw)
    r = client.post('/api/conversations', json={}, headers={'X-CSRF-Token': tok})
    assert r.status_code == 200


def test_wrong_csrf_token_is_rejected(client, login, two_users):
    (alice, apw), _ = two_users
    login(alice['username'], apw)
    r = client.post('/api/conversations', json={}, headers={'X-CSRF-Token': 'not-the-token'})
    assert r.status_code == 403


def test_deferred_actions_are_scope_filtered(client, login, two_users):
    (alice, apw), (bob, bpw) = two_users
    import schedule
    host = _mk_host('web-defer', ['web'])
    jid = schedule.create({'name': 'nightly', 'instruction': 'tidy up', 'host_id': host,
                           'schedule': '0 2 * * *'}, created_by=alice['id'])
    schedule.record_deferred(jid, host, 'ssh_exec', {}, 'systemctl restart nginx', 'risky')
    did = db.query_one('SELECT id FROM deferred_actions ORDER BY id DESC')['id']

    login(bob['username'], bpw)                 # scoped to 'db', not 'web'
    assert all(d['id'] != did for d in client.get('/api/deferred').get_json()['deferred'])
    tok = client.get('/api/me').get_json()['csrf']
    assert client.post(f'/api/deferred/{did}/deny',
                       headers={'X-CSRF-Token': tok}).status_code == 404

    login(alice['username'], apw)               # in scope — can see and resolve it
    assert any(d['id'] == did for d in client.get('/api/deferred').get_json()['deferred'])


def test_login_is_rate_limited(client, flask_app):
    import app as app_module
    app_module._LOGIN_FAILS.clear()
    for _ in range(app_module.LOGIN_MAX_FAILS):
        client.post('/api/login', json={'username': 'admin', 'password': 'wrong'})
    r = client.post('/api/login', json={'username': 'admin', 'password': 'testpass123'})
    assert r.status_code == 429
    app_module._LOGIN_FAILS.clear()


def test_unauthenticated_routes_need_login(client):
    client.post('/api/logout')
    for path in ['/api/conversations', '/api/deferred', '/api/hosts', '/api/audit']:
        assert client.get(path).status_code == 401, path
