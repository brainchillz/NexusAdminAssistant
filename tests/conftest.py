import os
import tempfile

import pytest

# Point all state at a throwaway dir BEFORE importing app modules.
_tmp = tempfile.mkdtemp(prefix='naa-test-')
os.environ['NAA_DATA_DIR'] = _tmp
os.environ['NAA_ADMIN_PASSWORD'] = 'testpass123'


@pytest.fixture(scope='session', autouse=True)
def _boot():
    import config
    from store import db
    import auth
    config.load()
    db.configure(config.DB_FILE)
    auth.ensure_admin()
    yield


@pytest.fixture
def flask_app():
    """The Flask app wired to the test DB, with NO background workers.

    Importing `app` is side-effect free (boot() is called by wsgi.py, not at
    import), which is what makes route testing possible at all.
    """
    import app as app_module
    app_module.boot(background=False)
    app_module.app.config['TESTING'] = True
    return app_module.app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture
def make_user():
    """Create a user and return (record, login_helper)."""
    import auth
    created = []

    def _make(username, role='operator', tags=None, password='pw-testing-123'):
        import store.db as db
        existing = db.query_one('SELECT id FROM users WHERE username=?', (username,))
        if existing:
            auth.delete_user(existing['id'])
        uid = auth.create_user(username, password, role=role, tags=tags or [])
        created.append(uid)
        rec = db.query_one('SELECT * FROM users WHERE id=?', (uid,))
        return dict(rec), password

    yield _make


@pytest.fixture
def login(client):
    """Log a client in and return its CSRF token (needed for mutating calls)."""
    def _login(username, password):
        r = client.post('/api/login', json={'username': username, 'password': password})
        assert r.status_code == 200, r.get_json()
        return r.get_json()['csrf']
    return _login
