"""Plan envelopes: one informed approval covers the work it described."""
from agent import policy


def _env(**kw):
    base = {'ceiling': 'caution', 'allow': [], 'hosts': ['web1'], 'summary': 'install a website'}
    base.update(kw)
    return base


def test_no_envelope_covers_nothing():
    assert policy.envelope_covers(None, 'caution', 'apt-get install -y nginx') is False


def test_inside_the_ceiling_runs():
    env = _env(ceiling='risky')
    assert policy.envelope_covers(env, 'caution', 'apt-get install -y nginx', 'web1')
    assert policy.envelope_covers(env, 'risky', 'systemctl restart nginx', 'web1')


def test_above_the_ceiling_still_gates():
    env = _env(ceiling='caution')
    assert not policy.envelope_covers(env, 'risky', 'systemctl restart nginx', 'web1')


def test_critical_is_never_pre_authorized_by_ceiling():
    """Even asking for a critical ceiling can't buy a blanket pass on reboots."""
    env = _env(ceiling='critical')
    assert policy.clamp_ceiling('critical') == 'risky'
    assert not policy.envelope_covers(env, 'critical', 'reboot', 'web1')


def test_named_command_can_be_pre_approved_by_name():
    env = _env(ceiling='caution', allow=['reboot'])
    assert policy.envelope_covers(env, 'critical', 'sudo reboot', 'web1')


def test_envelope_does_not_leak_to_another_host():
    env = _env(ceiling='risky', hosts=['web1'])
    assert policy.envelope_covers(env, 'risky', 'systemctl restart nginx', 'web1')
    assert not policy.envelope_covers(env, 'risky', 'systemctl restart nginx', 'db1')


def test_hostless_envelope_covers_the_run():
    env = _env(ceiling='risky', hosts=[])
    assert policy.envelope_covers(env, 'risky', 'systemctl restart nginx', 'anything')


def test_plan_tool_is_registered_and_capped():
    from agent import tools as toolkit
    tool = toolkit.get('propose_plan')
    assert tool is not None
    ceilings = tool.parameters['properties']['ceiling']['enum']
    assert 'critical' not in ceilings, 'the model must not be able to request a critical ceiling'


def test_core_intercepts_plan_and_sets_envelope(monkeypatch):
    """An approved plan becomes the run's envelope; a declined one does not."""
    from agent import core

    class FakeRun:
        def __init__(self):
            import threading
            self.id = 'r1'
            self.pending, self.pending_lock = {}, threading.Lock()
            self.envelope, self.unattended = None, False
            self.events = []
            self.user = {'id': 'u1', 'username': 'alice'}
            self.host = {'id': 'h1'}

        def emit(self, etype, **d):
            self.events.append((etype, d))
            # answer the plan card the moment it is raised
            if etype == 'plan_request':
                p = self.pending[d['call_id']]
                p['decision'] = self.answer
                p['event'].set()

        def audit(self, *a, **k):
            pass

    call = {'id': 'c1', 'name': 'propose_plan'}
    args = {'summary': 'install a website', 'steps': ['install nginx'],
            'ceiling': 'risky', 'hosts': ['web1']}

    run = FakeRun(); run.answer = 'approve'
    res = core._propose_plan(run, call, args, {'id': 'h1', 'name': 'web1'})
    assert res['approved'] is True
    assert run.envelope['ceiling'] == 'risky' and run.envelope['hosts'] == ['web1']

    run2 = FakeRun(); run2.answer = 'deny'
    res2 = core._propose_plan(run2, call, args, {'id': 'h1', 'name': 'web1'})
    assert res2['approved'] is False and run2.envelope is None
    assert 'Do NOT start' in res2['note']


def test_unattended_run_never_gets_an_interactive_plan():
    from agent import core

    class Run:
        unattended, job_ceiling, envelope = True, 'caution', None
        def emit(self, *a, **k): raise AssertionError('should not prompt a job')
        def audit(self, *a, **k): pass

    res = core._propose_plan(Run(), {'id': 'c1', 'name': 'propose_plan'},
                             {'summary': 's', 'steps': [], 'ceiling': 'risky'}, None)
    assert res['approved'] is False
    assert 'No human is present' in res['note']
