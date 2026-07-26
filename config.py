"""Config + secrets bootstrap.

A small 0600 JSON file holds the Fernet key + Flask secret_key (NOT in the DB).
Everything else (DB path, TLS, port) comes from NAA_* env vars. On first run the
key file and an admin account are created; the one-time admin password is printed
to stderr.
"""
import json
import os
import secrets

from store import crypto

# State lives OUTSIDE the repo — a per-user data dir (XDG), or override with
# NAA_DATA_DIR (e.g. /data in a container, /var/lib/... under systemd).
_xdg = os.environ.get('XDG_DATA_HOME') or os.path.join(os.path.expanduser('~'), '.local', 'share')
DEFAULT_DATA_DIR = os.path.join(_xdg, 'nexus-admin-assistant')
DATA_DIR = os.environ.get('NAA_DATA_DIR', DEFAULT_DATA_DIR)
CONFIG_FILE = os.environ.get('NAA_CONFIG_FILE', os.path.join(DATA_DIR, 'config.json'))
DB_FILE = os.environ.get('NAA_DB_FILE', os.path.join(DATA_DIR, 'naa.db'))

PORT = int(os.environ.get('NAA_PORT', '8080'))
TLS = os.environ.get('NAA_TLS', '0') == '1'
TLS_CERT = os.environ.get('NAA_TLS_CERT', os.path.join(DATA_DIR, 'tls', 'cert.pem'))
TLS_KEY = os.environ.get('NAA_TLS_KEY', os.path.join(DATA_DIR, 'tls', 'key.pem'))

_cfg = None


def _write_atomic(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f'{path}.tmp.{os.getpid()}'
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def load():
    """Load (bootstrapping the key file if missing) and install the Fernet key."""
    global _cfg
    if _cfg is not None:
        return _cfg
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
    except (FileNotFoundError, ValueError):
        cfg = {}
    changed = False
    if not cfg.get('fernet_key'):
        cfg['fernet_key'] = crypto.new_key()
        changed = True
    if not cfg.get('secret_key'):
        cfg['secret_key'] = secrets.token_hex(32)
        changed = True
    if changed:
        _write_atomic(CONFIG_FILE, cfg)
    crypto.configure(cfg['fernet_key'])
    _cfg = cfg
    return cfg


def secret_key():
    return load()['secret_key']
