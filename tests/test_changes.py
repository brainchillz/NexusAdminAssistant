import changes
import inventory


def test_record_and_list_metadata_only():
    hid = inventory.create({'name': 'ch1', 'address': '10.0.0.1'})
    changes.record_file_change(hid, {'id': 'u1', 'username': 'admin'}, 'conv1',
                               '/etc/nginx/nginx.conf', 'old', 'new', True, True)
    lst = changes.list_for_host(hid)
    assert len(lst) == 1
    e = lst[0]
    assert e['kind'] == 'write_file' and e['reversible'] == 1 and e['had_before'] == 1
    # list must NOT expose encrypted content fields
    assert 'before_enc' not in e and 'after_enc' not in e


def test_before_content_roundtrip_encrypted():
    hid = inventory.create({'name': 'ch2', 'address': '10.0.0.2'})
    changes.record_file_change(hid, {'id': 'u1', 'username': 'admin'}, '',
                               '/tmp/f', 'SECRET_OLD_CONTENT', 'newer', True, False)
    row = changes.get(changes.list_for_host(hid)[0]['id'])
    # stored encrypted (not plaintext), decrypts correctly
    assert 'SECRET_OLD_CONTENT' not in (row['before_enc'] or '')
    assert changes.before_content(row) == 'SECRET_OLD_CONTENT'


def test_command_note_not_reversible():
    hid = inventory.create({'name': 'ch3', 'address': '10.0.0.3'})
    changes.record_command(hid, {'id': 'u1', 'username': 'admin'}, '', 'systemctl restart nginx', 'risky')
    e = changes.list_for_host(hid)[0]
    assert e['kind'] == 'command' and e['reversible'] == 0
    assert 'systemctl restart nginx' in e['summary']
