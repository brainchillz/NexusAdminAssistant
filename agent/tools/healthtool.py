"""host_health tool — the agent can query the selected host's latest monitored
health (reachable, uptime, load, memory %, disk %, issues) to ground itself."""
import monitor


def _run(ctx, args):
    if not ctx.host:
        return {'ok': False, 'error': 'no host selected'}
    snap = monitor.snapshot(ctx.host['id'])
    if not snap:
        return {'ok': True, 'note': 'no health sample yet (monitor polls periodically); '
                'run ssh_exec (df -h / free -h) for a live reading'}
    return {'ok': True, 'reachable': snap['reachable'], 'status': snap['status'],
            'metrics': snap['metrics'], 'issues': [t for _, t in snap['issues']],
            'sampled_at': snap['ts']}


def register_all(register, Tool):
    register(Tool(
        name='host_health', needs_host=True, risk_hint='safe',
        description='Get the latest monitored health of the selected host (reachable, '
                    'uptime, load, memory %, disk %, and any current issues). Use it to '
                    'ground yourself before acting or when the user asks how a host is doing.',
        parameters={'type': 'object', 'properties': {'host': {'type': 'string', 'description': 'optional: target a different host by name instead of the selected one'},}},
        run=_run))
