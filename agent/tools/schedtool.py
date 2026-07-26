"""Agent-facing scheduling tools: schedule_job / list_jobs / cancel_job.

The agent can create its own timed jobs ("at 22:00 prune dangling images and
report"). SAFETY: agent-created jobs are always capped at the 'caution' ceiling —
the agent cannot self-grant authority to do disruptive things unattended. Raising
a job's ceiling or adding allow-list entries is a human action in the Jobs panel.
"""
import schedule as sched


def _schedule_run(ctx, args):
    name = (args.get('name') or '').strip()
    instruction = (args.get('instruction') or '').strip()
    if not name or not instruction:
        return {'ok': False, 'error': 'name and instruction are required'}
    at = args.get('at')
    cron = args.get('cron')
    if at:
        kind, schedule_str = 'once', at
    elif cron:
        if not sched.is_valid_cron(cron):
            return {'ok': False, 'error': 'invalid cron (need "min hour dom mon dow")'}
        kind, schedule_str = 'cron', cron
    else:
        return {'ok': False, 'error': 'provide either cron="..." or at="ISO datetime"'}
    jid = sched.create({
        'name': name, 'kind': kind, 'schedule': schedule_str, 'instruction': instruction,
        'host_id': (ctx.host or {}).get('id'), 'ceiling': 'caution',  # agent cannot raise this
        'tz': args.get('tz', 'UTC'), 'enabled': True,
    }, created_by=(ctx.user or {}).get('id', ''))
    if ctx.audit:
        ctx.audit('job:create', f'{name} ({schedule_str})', 'auto')
    return {'ok': True, 'id': jid, 'name': name,
            'note': 'Scheduled at the caution ceiling (reads + installs/config run '
                    'unattended; anything disruptive is deferred for the user to approve). '
                    'The user can raise the ceiling or pre-approve specific actions in the Jobs panel.'}


def _list_run(ctx, args):
    jobs = sched.list_all()
    return {'ok': True, 'jobs': [
        {'id': j['id'], 'name': j['name'], 'schedule': j['schedule'], 'kind': j['kind'],
         'enabled': j['enabled'], 'ceiling': j['ceiling'], 'next_run': j['next_run'],
         'last_status': j['last_status']} for j in jobs]}


def _cancel_run(ctx, args):
    ident = (args.get('name') or args.get('id') or '').strip()
    if not ident:
        return {'ok': False, 'error': 'name or id required'}
    jobs = sched.list_all()
    match = next((j for j in jobs if j['id'] == ident or j['name'] == ident), None)
    if not match:
        return {'ok': False, 'error': f'no job named {ident}'}
    sched.delete(match['id'])
    if ctx.audit:
        ctx.audit('job:cancel', match['name'], 'auto')
    return {'ok': True, 'cancelled': match['name']}


def register_all(register, Tool):
    register(Tool(
        name='schedule_job', needs_host=False, risk_hint='safe',
        description='Schedule a task to run later or on a recurring schedule, unattended. '
                    'Give a cron expression ("min hour dom mon dow") or a one-off "at" ISO '
                    'datetime, plus a plain-language instruction. Runs against the selected '
                    'host. Jobs run at the caution ceiling; disruptive steps are deferred '
                    'for the user unless they pre-approve them.',
        parameters={'type': 'object', 'properties': {
            'name': {'type': 'string'},
            'instruction': {'type': 'string', 'description': 'what to do when it runs'},
            'cron': {'type': 'string', 'description': 'e.g. "0 22 * * *" for 22:00 daily'},
            'at': {'type': 'string', 'description': 'one-off ISO datetime, e.g. 2026-07-25T22:00:00'},
            'tz': {'type': 'string', 'description': 'IANA tz, e.g. America/New_York (default UTC)'}},
            'required': ['name', 'instruction']},
        run=_schedule_run))
    register(Tool(
        name='list_jobs', needs_host=False, risk_hint='safe',
        description='List the scheduled jobs and their next run / last status.',
        parameters={'type': 'object', 'properties': {}},
        run=_list_run))
    register(Tool(
        name='cancel_job', needs_host=False, risk_hint='safe',
        description='Delete a scheduled job by name or id.',
        parameters={'type': 'object', 'properties': {
            'name': {'type': 'string'}, 'id': {'type': 'string'}}},
        run=_cancel_run))
