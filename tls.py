"""TLS certificate management for the app's own HTTPS listener.

The app is served by gunicorn (or the dev server) with --certfile/--keyfile at
config.TLS_CERT / config.TLS_KEY. This module lets an admin inspect, regenerate
(self-signed), or replace that serving certificate from the UI — the same
capability NexusController exposes. Pure `cryptography` (no openssl shell-out),
so it works identically in the slim Docker image and under systemd.

Applying a new cert needs the gunicorn worker to restart (it wraps the listening
socket with the SSL context once at startup); the /api/tls/apply route bounces
the worker the same way restore does.
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import config

MAX_PEM = 100_000  # generous ceiling; a real cert chain + key is far smaller


def _paths():
    return config.TLS_CERT, config.TLS_KEY


def _tls_dir():
    return os.path.dirname(config.TLS_CERT)


def _expiry(cert):
    try:
        return cert.not_valid_after_utc            # cryptography >= 42
    except AttributeError:                          # older: naive UTC
        return cert.not_valid_after


def cert_info(cert_path=None):
    """Metadata for the serving certificate (for the UI). Never raises."""
    cert_path = cert_path or config.TLS_CERT
    if not os.path.exists(cert_path):
        return {'present': False, 'tls_enabled': config.TLS}
    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
    except Exception:  # noqa: BLE001 — surface as a soft error, not a 500
        return {'present': True, 'error': 'unreadable certificate', 'tls_enabled': config.TLS}
    fp = cert.fingerprint(hashes.SHA256()).hex()
    exp = _expiry(cert)
    # normalize to aware UTC so "days left" is correct on both cryptography eras
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        'present': True,
        'tls_enabled': config.TLS,
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'expires': exp.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'days_left': (exp - now).days,
        'self_signed': cert.subject == cert.issuer,
        'fingerprint_sha256': ':'.join(fp[i:i + 2] for i in range(0, len(fp), 2)),
    }


def generate_self_signed(common_name=None):
    """Create a self-signed cert+key and write them to the serving paths.
    Returns (ok, error)."""
    try:
        import socket
        cn = common_name or socket.gethostname() or 'nexus-admin-assistant'
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=825))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = _paths()
        os.makedirs(_tls_dir(), exist_ok=True)
        _write_atomic(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        _write_atomic(key_path, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()), mode=0o600)
        return True, ''
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def validate_and_install_cert(cert_pem, key_pem):
    """Validate a PEM cert+key pair (well-formed + the key matches the cert) and
    install them atomically to the serving paths. Returns (ok, error)."""
    cert_pem = (cert_pem or '').strip()
    key_pem = (key_pem or '').strip()
    if 'BEGIN CERTIFICATE' not in cert_pem:
        return False, 'Certificate must be PEM (-----BEGIN CERTIFICATE-----)'
    if 'PRIVATE KEY' not in key_pem:
        return False, 'Key must be a PEM private key'
    if len(cert_pem) > MAX_PEM or len(key_pem) > MAX_PEM:
        return False, 'Certificate or key too large'
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:  # noqa: BLE001
        return False, 'Invalid certificate'
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except Exception:  # noqa: BLE001
        return False, 'Invalid private key (encrypted keys are not supported — decrypt it first)'
    try:
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        enc = serialization.Encoding.PEM
        cpub = cert.public_key().public_bytes(enc, spki)
        kpub = key.public_key().public_bytes(enc, spki)
    except Exception:  # noqa: BLE001
        return False, 'Could not compare certificate and key'
    if cpub != kpub:
        return False, 'Certificate and private key do not match'
    try:
        os.makedirs(_tls_dir(), exist_ok=True)
        cert_path, key_path = _paths()
        _write_atomic(cert_path, cert_pem.encode() + b'\n')
        _write_atomic(key_path, key_pem.encode() + b'\n', mode=0o600)
    except OSError as e:
        return False, f'Could not write certificate: {e}'
    return True, ''


def ensure_tls_cert():
    """Ensure a usable cert+key exist (called at startup when TLS is on).
    Generate a self-signed pair only when BOTH are missing — never overwrite an
    operator-supplied certificate. Returns (ok, error)."""
    cert_path, key_path = _paths()
    have_cert, have_key = os.path.exists(cert_path), os.path.exists(key_path)
    if have_cert and have_key:
        return True, ''
    if have_cert or have_key:
        return False, f'TLS cert/key mismatch: one of {cert_path} / {key_path} is missing'
    return generate_self_signed()


def _write_atomic(path, data, mode=0o644):
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        os.replace(tmp, path)
        os.chmod(path, mode)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
