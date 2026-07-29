import inventory
import memory


def _host(name):
    return inventory.create({'name': name, 'address': '10.0.0.9'})


def test_mission_seed_and_update():
    memory.ensure_mission()
    m = memory.get_mission()
    assert m and m['kind'] == 'mission'
    memory.set_mission('custom mission text')
    assert memory.get_mission()['body'] == 'custom mission text'


def test_global_vs_host_scope():
    hid = _host('mem-host-a')
    gid = memory.create('service', 'Shared NTP', 'chrony at 10.0.0.5', None)
    hid_mem = memory.create('state', 'LAMP installed', 'apache+mariadb+php', hid)
    glist = memory.list_global(exclude_mission=True)
    assert any(m['id'] == gid for m in glist)
    assert all(m['host_id'] is None for m in glist)
    hlist = memory.list_host(hid)
    assert any(m['id'] == hid_mem for m in hlist)


def test_search_finds_global_and_scoped():
    owner = _host('mem-owner')
    other = _host('mem-other')
    memory.create('service', 'DNS resolver', 'dnsmasq on gw at 10.0.0.1', None)
    memory.create('fact', 'private note', 'docker on box7', owner)
    # global always visible; other hosts' memories are not
    res = memory.search('dnsmasq', host_id=other)
    assert any(r['title'] == 'DNS resolver' for r in res)
    res2 = memory.search('docker', host_id=other)
    assert not any(r['title'] == 'private note' for r in res2)
    # the owning host does see its own
    res3 = memory.search('docker', host_id=owner)
    assert any(r['title'] == 'private note' for r in res3)


def test_estate_context_mentions_shared_service():
    memory.create('service', 'Shared NTP timekeeper', 'chrony at 10.0.0.5', None)
    ctx = memory.estate_context([{'id': 'h1', 'name': 'web01', 'address': '10.0.0.9', 'tags': ['web']}])
    assert 'web01' in ctx
    assert 'timekeeper' in ctx.lower() or 'ntp' in ctx.lower()
