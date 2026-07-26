"""Agent-facing memory tools: memory_write + memory_search.

The agent records durable knowledge (per-host or estate-wide) and recalls it.
Estate-wide memory is always injected into context, but memory_search lets the
agent dig for specifics ("is there already an NTP server?").
"""
import memory as memstore

_KINDS = ['service', 'decision', 'fact', 'state', 'changelog']


def _write_run(ctx, args):
    scope = args.get('scope', 'host')
    kind = args.get('kind', 'fact')
    title = (args.get('title') or '').strip()
    body = (args.get('body') or '').strip()
    if not title:
        return {'ok': False, 'error': 'title is required'}
    host_id = None
    if scope == 'host':
        if not ctx.host:
            return {'ok': False, 'error': 'no host selected — use scope="global" for estate-wide notes'}
        host_id = ctx.host['id']
    mid = memstore.create(kind, title, body, host_id)
    if ctx.audit:
        ctx.audit('memory:write', f'[{scope}/{kind}] {title}', 'auto')
    return {'ok': True, 'id': mid, 'scope': scope, 'kind': kind, 'saved': title}


def _search_run(ctx, args):
    query = (args.get('query') or '').strip()
    if not query:
        return {'ok': False, 'error': 'query is required'}
    host_id = ctx.host['id'] if (ctx.host and args.get('scope') != 'global') else None
    hits = memstore.search(query, host_id=host_id, limit=int(args.get('limit', 8)))
    return {'ok': True, 'results': [
        {'scope': 'global' if m['host_id'] is None else 'host', 'kind': m['kind'],
         'title': m['title'], 'body': m['body']} for m in hits]}


def register_all(register, Tool):
    register(Tool(
        name='memory_write', needs_host=False, risk_hint='safe',
        description='Save a durable note so you remember it in future sessions. Use '
                    'scope="global" for estate-wide knowledge (shared services like an '
                    'NTP/DNS server, cross-host architecture, overarching decisions) and '
                    'scope="host" for facts about the selected host (what you installed, '
                    'decisions, a changelog entry). Record these proactively as you work.',
        parameters={'type': 'object', 'properties': {
            'scope': {'type': 'string', 'enum': ['global', 'host']},
            'kind': {'type': 'string', 'enum': _KINDS},
            'title': {'type': 'string', 'description': 'short headline'},
            'body': {'type': 'string', 'description': 'the details'}},
            'required': ['scope', 'title']},
        run=_write_run))
    register(Tool(
        name='memory_search', needs_host=False, risk_hint='safe',
        description='Search your memory (estate-wide + this host) for what you already '
                    'know before assuming something must be built new — e.g. before adding '
                    'an NTP client, search "ntp" to see if a server already exists.',
        parameters={'type': 'object', 'properties': {
            'query': {'type': 'string'},
            'scope': {'type': 'string', 'enum': ['all', 'global'],
                      'description': 'all (default) or global-only'},
            'limit': {'type': 'integer'}},
            'required': ['query']},
        run=_search_run))
