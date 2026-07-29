from datetime import datetime
from zoneinfo import ZoneInfo

import schedule
from agent import policy


def test_cron_match_basic():
    dt = datetime(2026, 7, 25, 22, 0, tzinfo=ZoneInfo('UTC'))  # Saturday
    assert schedule.cron_match('0 22 * * *', dt)
    assert not schedule.cron_match('0 22 * * *', dt.replace(minute=1))
    assert schedule.cron_match('*/15 * * * *', dt.replace(minute=15))
    assert not schedule.cron_match('*/15 * * * *', dt.replace(minute=16))


def test_cron_dow_and_ranges():
    sat = datetime(2026, 7, 25, 9, 0, tzinfo=ZoneInfo('UTC'))  # Saturday = cron dow 6
    assert schedule.cron_match('0 9 * * 6', sat)
    assert not schedule.cron_match('0 9 * * 1', sat)
    assert schedule.cron_match('0 9-17 * * *', sat)
    assert not schedule.cron_match('0 10-17 * * *', sat)


def test_invalid_cron():
    assert not schedule.is_valid_cron('bogus')
    assert not schedule.is_valid_cron('0 22 * *')  # only 4 fields
    assert schedule.is_valid_cron('0 22 * * *')


def test_next_run_timezone():
    # 22:00 America/New_York (EDT, UTC-4 in July) == 02:00 UTC next day
    nxt = schedule.compute_next_run('cron', '0 22 * * *', 'America/New_York')
    assert nxt.endswith('+00:00') or 'T' in nxt
    assert 'T02:00' in nxt


def test_job_lifecycle():
    jid = schedule.create({'name': 'nightly-prune', 'kind': 'cron', 'schedule': '0 22 * * *',
                           'instruction': 'prune docker', 'ceiling': 'caution',
                           'allow': ['docker image prune']}, created_by='u1')
    j = schedule.get(jid)
    assert j['name'] == 'nightly-prune' and j['ceiling'] == 'caution'
    assert j['allow'] == ['docker image prune']
    schedule.update(jid, {'ceiling': 'risky'})
    assert schedule.get(jid)['ceiling'] == 'risky'
    schedule.set_enabled(jid, False)
    assert schedule.get(jid)['enabled'] is False


def test_deferred_recording():
    jid = schedule.create({'name': 'j2', 'schedule': '0 3 * * *', 'instruction': 'x'}, created_by='u1')
    schedule.record_deferred(jid, '', 'ssh_exec', {'command': 'reboot'}, 'reboot', 'critical')
    pend = schedule.list_deferred('pending')
    assert any(p['command'] == 'reboot' and p['risk'] == 'critical' for p in pend)


def test_unattended_envelope_end_to_end():
    # caution job: install runs, restart defers unless allow-listed
    assert policy.unattended_decision('caution', 'caution', [], 'apt-get install -y nginx') == 'run'
    assert policy.unattended_decision('risky', 'caution', [], 'systemctl restart nginx') == 'defer'
    assert policy.unattended_decision('risky', 'caution', ['systemctl restart nginx'],
                                      'systemctl restart nginx') == 'run'
    assert policy.unattended_decision('critical', 'risky', [], 'reboot') == 'defer'
    assert policy.unattended_decision('critical', 'critical', [], 'reboot') == 'run'
