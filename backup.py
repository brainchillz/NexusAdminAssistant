"""Encrypted app-state backup + restore.

A backup bundles a consistent snapshot of the SQLite database AND the key file
(config.json) — both are needed, since the DB's secrets are encrypted with the
Fernet key in config.json. The bundle is itself encrypted with a user-supplied
passphrase (PBKDF2 + Fernet), so it's safe to store off-box. Restore replaces the
live state and the app restarts to load the restored keys/DB.
"""
import base64
import io
import json
import os
import tarfile
import tempfile

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import config
from store import db

MAGIC = b'NAABK1\n'
ITERATIONS = 200_000
MIN_PASSPHRASE = 8


def _derive(passphrase, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def create_backup(passphrase):
    """Return the encrypted backup bytes (magic + salt + Fernet token)."""
    if not passphrase or len(passphrase) < MIN_PASSPHRASE:
        raise ValueError(f'passphrase must be at least {MIN_PASSPHRASE} characters')
    fd, snap = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    os.remove(snap)  # VACUUM INTO needs the target to not exist
    try:
        with db.connect() as conn:
            conn.execute('VACUUM INTO ?', (snap,))   # consistent snapshot, no WAL
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            tar.add(snap, arcname='naa.db')
            tar.add(config.CONFIG_FILE, arcname='config.json')
            manifest = json.dumps({'version': 1}).encode()
            info = tarfile.TarInfo('manifest.json')
            info.size = len(manifest)
            tar.addfile(info, io.BytesIO(manifest))
        plain = buf.getvalue()
    finally:
        if os.path.exists(snap):
            os.remove(snap)
    salt = os.urandom(16)
    token = Fernet(_derive(passphrase, salt)).encrypt(plain)
    return MAGIC + salt + token


def restore_backup(data, passphrase):
    """Decrypt + validate a backup and replace the live state files on disk.
    The caller must then restart the process so the new keys/DB load."""
    if not data or not data.startswith(MAGIC):
        raise ValueError('not a valid Nexus Admin Assistant backup file')
    body = data[len(MAGIC):]
    salt, token = body[:16], body[16:]
    try:
        plain = Fernet(_derive(passphrase, salt)).decrypt(token)
    except InvalidToken:
        raise ValueError('wrong passphrase or corrupt backup')
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:gz') as tar:
        names = tar.getnames()
        if 'naa.db' not in names or 'config.json' not in names:
            raise ValueError('backup is missing required files')
        db_bytes = tar.extractfile('naa.db').read()
        cfg_bytes = tar.extractfile('config.json').read()
    # validate before touching anything
    try:
        cfg = json.loads(cfg_bytes)
    except ValueError:
        raise ValueError('backup config is not valid JSON')
    if not cfg.get('fernet_key'):
        raise ValueError('backup config is missing its encryption key')
    if not db_bytes.startswith(b'SQLite format 3'):
        raise ValueError('backup database is invalid')
    # write atomically; drop the old WAL/SHM so the new DB opens clean
    _write_atomic(config.CONFIG_FILE, cfg_bytes, 0o600)
    _write_atomic(config.DB_FILE, db_bytes, 0o600)
    for ext in ('-wal', '-shm'):
        p = config.DB_FILE + ext
        if os.path.exists(p):
            os.remove(p)
    return {'restored': True}


def _write_atomic(path, data_bytes, mode):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f'{path}.tmp.{os.getpid()}'
    with open(tmp, 'wb') as f:
        f.write(data_bytes)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)
