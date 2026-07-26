"""Fernet secret vault (lifted from NexusController's app.py).

The Fernet key + Flask secret_key live in a small 0600 config file *outside* the
SQLite DB (config.py owns that file). Secrets (passwords, SSH keys, API tokens,
sudo passwords, LLM API keys) are stored as Fernet ciphertext in DB columns and
decrypted only at execution time — never sent to the LLM, rendered, or logged.
"""
from cryptography.fernet import Fernet, InvalidToken

_fernet = None


def configure(key: str):
    """Install the Fernet key (base64 str). Called once at startup by config.py."""
    global _fernet
    _fernet = Fernet(key.encode() if isinstance(key, str) else key)


def new_key() -> str:
    """Generate a fresh base64 Fernet key string (for first-run bootstrap)."""
    return Fernet.generate_key().decode()


def encrypt(plaintext) -> str:
    if plaintext is None or plaintext == '':
        return ''
    if _fernet is None:
        raise RuntimeError('crypto.configure() not called')
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext):
    """Return the plaintext, or None if empty/undecryptable."""
    if not ciphertext:
        return None
    if _fernet is None:
        raise RuntimeError('crypto.configure() not called')
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except (InvalidToken, AttributeError, ValueError):
        return None
