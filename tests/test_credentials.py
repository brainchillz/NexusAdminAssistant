import pytest

import inventory
import provision
from agent.tools import ssh


def _mkkey(comment='t'):
    return provision.gen_ed25519(comment)


def test_derive_pubkey_matches_generated():
    priv, pub = _mkkey('naa-x')
    derived = provision.derive_pubkey(priv, comment='naa-x')
    assert derived == pub
    assert derived.startswith('ssh-ed25519 ')


def test_cred_roundtrip_and_no_private_leak():
    priv, pub = _mkkey()
    cid = inventory.cred_create('fleet-admin', priv, username='otnops', public_key=pub)
    creds = inventory.cred_list()
    me = [c for c in creds if c['id'] == cid][0]
    assert me['name'] == 'fleet-admin' and me['username'] == 'otnops'
    assert me['public_key'] == pub and me['hosts_using'] == 0
    assert priv not in str(creds)                      # private key never listed
    assert inventory.cred_key(cid) == priv             # execution-time decrypt


def test_secrets_for_falls_back_to_shared_credential():
    priv, pub = _mkkey()
    cid = inventory.cred_create('shared1', priv, username='shareduser', public_key=pub)
    hid = inventory.create({'name': 'ch1', 'address': '10.9.9.1', 'credential_id': cid})
    sec = inventory.secrets_for(inventory.get_raw(hid))
    assert sec['ssh_key'] == priv
    assert sec['username'] == 'shareduser'             # blank host user -> cred hint
    # a per-host key (and username) wins over the shared credential
    inventory.update(hid, {'ssh_key': 'OWNKEY', 'username': 'me'})
    sec = inventory.secrets_for(inventory.get_raw(hid))
    assert sec['ssh_key'] == 'OWNKEY' and sec['username'] == 'me'


def test_cred_delete_detaches_hosts():
    priv, pub = _mkkey()
    cid = inventory.cred_create('doomed', priv, public_key=pub)
    hid = inventory.create({'name': 'ch2', 'address': '10.9.9.2', 'credential_id': cid})
    assert [c for c in inventory.cred_list() if c['id'] == cid][0]['hosts_using'] == 1
    inventory.cred_delete(cid)
    assert not [c for c in inventory.cred_list() if c['id'] == cid]
    rec = inventory.get_raw(hid)
    assert not rec['credential_id']
    assert not inventory.secrets_for(rec)['ssh_key']


def test_public_carries_credential_id_not_secrets():
    priv, pub = _mkkey()
    cid = inventory.cred_create('pubcheck', priv, public_key=pub)
    hid = inventory.create({'name': 'ch3', 'address': '10.9.9.3', 'credential_id': cid})
    p = inventory.public(inventory.get_raw(hid))
    assert p['credential_id'] == cid
    assert priv not in str(p)


def test_pkey_from_str_rejects_public_key_with_reason():
    _, pub = _mkkey()
    with pytest.raises(ValueError, match='PUBLIC'):
        ssh._pkey_from_str(pub)


def test_pkey_from_str_rejects_garbage_with_reason():
    with pytest.raises(ValueError, match='unrecognized'):
        ssh._pkey_from_str('this is not a key at all')


def test_pkey_from_str_rejects_ppk_with_reason():
    with pytest.raises(ValueError, match='PuTTY'):
        ssh._pkey_from_str('PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none')


def test_pkey_from_str_parses_valid_and_empty():
    priv, _ = _mkkey()
    assert ssh._pkey_from_str(priv) is not None
    assert ssh._pkey_from_str('') is None
    assert ssh._pkey_from_str(None) is None
