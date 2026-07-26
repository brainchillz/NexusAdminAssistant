import pytest

import backup
import inventory
import memory
from store import db


def test_backup_restore_roundtrip():
    hid = inventory.create({'name': 'bkhost', 'address': '10.9.9.9', 'password': 'pw123'})
    memory.create('fact', 'bk-note', 'remember this', None)
    blob = backup.create_backup('passphrase12')
    assert blob.startswith(backup.MAGIC)
    # mutate: delete the host + a memory
    db.execute('DELETE FROM hosts WHERE id=?', (hid,))
    assert inventory.get_raw(hid) is None
    # restore brings everything back
    backup.restore_backup(blob, 'passphrase12')
    rec = inventory.get_raw(hid)
    assert rec is not None and rec['name'] == 'bkhost'
    # credential still decrypts (Fernet key came along in the bundle)
    assert inventory.secrets_for(rec)['password'] == 'pw123'
    assert any(m['title'] == 'bk-note' for m in memory.list_global(exclude_mission=True))


def test_wrong_passphrase_rejected():
    blob = backup.create_backup('rightpass1')
    with pytest.raises(ValueError):
        backup.restore_backup(blob, 'wrongpass1')


def test_short_passphrase_rejected():
    with pytest.raises(ValueError):
        backup.create_backup('short')


def test_garbage_is_rejected():
    with pytest.raises(ValueError):
        backup.restore_backup(b'not a backup', 'passphrase12')
