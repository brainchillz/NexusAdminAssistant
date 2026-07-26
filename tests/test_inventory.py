import auth
import inventory
from store import db, settings


def test_secret_roundtrip_and_public_strip():
    hid = inventory.create({'name': 'h1', 'address': '10.0.0.1', 'username': 'root',
                            'password': 'sekret', 'ssh_key': 'KEYDATA', 'tags': ['lab']})
    rec = inventory.get_raw(hid)
    sec = inventory.secrets_for(rec)
    assert sec['password'] == 'sekret'
    assert sec['ssh_key'] == 'KEYDATA'
    pub = inventory.public(rec)
    blob = str(pub)
    assert 'sekret' not in blob and 'KEYDATA' not in blob
    assert pub['has_password'] and pub['has_ssh_key'] and not pub['has_token']


def test_edit_keeps_secret_when_blank():
    hid = inventory.create({'name': 'h2', 'address': '10.0.0.2', 'password': 'orig'})
    inventory.update(hid, {'name': 'h2b'})  # no password field -> keep
    assert inventory.secrets_for(inventory.get_raw(hid))['password'] == 'orig'
    inventory.update(hid, {'password': 'new'})
    assert inventory.secrets_for(inventory.get_raw(hid))['password'] == 'new'


def test_tag_scope_visibility():
    hid = inventory.create({'name': 'scoped', 'address': '10.0.0.3', 'tags': ['prod']})
    admin = db.query_one('SELECT * FROM users WHERE username="admin"')
    # scoped operator with only "lab" cannot see a "prod" host
    op = {'role': 'operator', 'scope_tags': '["lab"]'}
    assert auth.scope_allows(admin, ['prod']) is True       # admin unscoped
    assert auth.scope_allows(op, ['prod']) is False
    assert auth.scope_allows(op, ['lab', 'prod']) is True
    assert inventory.find_for_user(hid, op) is None


def test_llm_settings_key_encrypted_and_masked():
    settings.set_llm({'provider': 'anthropic', 'model': 'claude-sonnet-5', 'api_key': 'sk-secret'})
    pub = settings.public_llm()
    assert 'sk-secret' not in str(pub)
    assert pub['has_key'] is True
    assert settings.get_llm()['api_key'] == 'sk-secret'
    # blank key on re-save keeps the stored one
    settings.set_llm({'provider': 'anthropic', 'model': 'claude-sonnet-5'})
    assert settings.get_llm()['api_key'] == 'sk-secret'
