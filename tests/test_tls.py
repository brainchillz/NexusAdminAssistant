"""TLS certificate management: generation, validation, install, inspection."""
import os
import stat

import pytest

import config
import tls


@pytest.fixture
def tlsdir(tmp_path, monkeypatch):
    d = tmp_path / 'tls'
    monkeypatch.setattr(config, 'TLS_CERT', str(d / 'cert.pem'))
    monkeypatch.setattr(config, 'TLS_KEY', str(d / 'key.pem'))
    return d


def _pem_pair(tlsdir):
    """Generate a self-signed pair and return (cert_pem, key_pem) strings."""
    ok, e = tls.generate_self_signed()
    assert ok, e
    with open(config.TLS_CERT) as fh:
        cert = fh.read()
    with open(config.TLS_KEY) as fh:
        key = fh.read()
    return cert, key


def test_generate_self_signed_then_info(tlsdir):
    ok, e = tls.generate_self_signed()
    assert ok, e
    info = tls.cert_info()
    assert info['present'] and info['self_signed']
    assert info['days_left'] > 800            # ~825-day validity
    assert len(info['fingerprint_sha256'].split(':')) == 32
    # private key must be 0600
    mode = stat.S_IMODE(os.stat(config.TLS_KEY).st_mode)
    assert mode == 0o600


def test_cert_info_absent(tlsdir):
    info = tls.cert_info()
    assert info['present'] is False


def test_install_valid_pair(tlsdir):
    cert, key = _pem_pair(tlsdir)
    os.remove(config.TLS_CERT); os.remove(config.TLS_KEY)
    ok, e = tls.validate_and_install_cert(cert, key)
    assert ok, e
    assert os.path.exists(config.TLS_CERT) and os.path.exists(config.TLS_KEY)
    assert stat.S_IMODE(os.stat(config.TLS_KEY).st_mode) == 0o600


def test_reject_mismatched_key(tlsdir, tmp_path, monkeypatch):
    cert, _ = _pem_pair(tlsdir)
    # a DIFFERENT pair's key
    d2 = tmp_path / 'other'
    monkeypatch.setattr(config, 'TLS_CERT', str(d2 / 'c.pem'))
    monkeypatch.setattr(config, 'TLS_KEY', str(d2 / 'k.pem'))
    _, other_key = _pem_pair(d2)
    ok, e = tls.validate_and_install_cert(cert, other_key)
    assert not ok and 'do not match' in e


def test_reject_malformed(tlsdir):
    ok, e = tls.validate_and_install_cert('not a cert', 'not a key')
    assert not ok
    cert, _ = _pem_pair(tlsdir)
    ok, e = tls.validate_and_install_cert(cert, 'garbage')
    assert not ok and 'key' in e.lower()


def test_ensure_generates_when_both_missing(tlsdir):
    ok, e = tls.ensure_tls_cert()
    assert ok, e
    assert os.path.exists(config.TLS_CERT)
    # idempotent: second call keeps the existing cert
    fp1 = tls.cert_info()['fingerprint_sha256']
    tls.ensure_tls_cert()
    assert tls.cert_info()['fingerprint_sha256'] == fp1


def test_ensure_errors_on_half_present(tlsdir):
    tls.generate_self_signed()
    os.remove(config.TLS_KEY)          # cert present, key gone
    ok, e = tls.ensure_tls_cert()
    assert not ok and 'mismatch' in e
