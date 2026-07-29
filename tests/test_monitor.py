import monitor

SAMPLE = """OS=Ubuntu 24.04.4 LTS
UP=259200
CORES=4
LOAD=0.50
MEM=42
DISK=32
DISKMNT=/
"""


def test_parse_metrics():
    m = monitor.parse_metrics(SAMPLE)
    assert m['os'] == 'Ubuntu 24.04.4 LTS'
    assert m['uptime'] == 259200 and m['cores'] == 4
    assert m['mem'] == 42 and m['disk'] == 32 and m['disk_mnt'] == '/'
    assert m['load1'] == 0.5
    assert m['cpu'] == int(0.5 / 4 * 100)  # 12


def test_status_healthy():
    m = monitor.parse_metrics(SAMPLE)
    status, issues = monitor.compute_status(True, m)
    assert status == 'ok' and issues == []


def test_status_disk_warn_and_bad():
    m = monitor.parse_metrics(SAMPLE.replace('DISK=32', 'DISK=88'))
    status, issues = monitor.compute_status(True, m)
    assert status == 'warn' and any(k == 'disk' for k, _ in issues)
    m2 = monitor.parse_metrics(SAMPLE.replace('DISK=32', 'DISK=97'))
    status2, issues2 = monitor.compute_status(True, m2)
    assert status2 == 'bad' and any('full' in t for _, t in issues2)


def test_status_mem_warn():
    m = monitor.parse_metrics(SAMPLE.replace('MEM=42', 'MEM=95'))
    status, issues = monitor.compute_status(True, m)
    assert status == 'warn' and any(k == 'mem' for k, _ in issues)


def test_status_unreachable():
    status, issues = monitor.compute_status(False, {})
    assert status == 'bad' and issues[0][0] == 'unreachable'


def test_parse_garbage_is_safe():
    m = monitor.parse_metrics('nonsense\n\nOS=\nDISK=notanumber')
    assert m['disk'] == 0 and m['mem'] == 0  # no crash, defaults
