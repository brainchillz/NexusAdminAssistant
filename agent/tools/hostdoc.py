"""write_host_doc — the agent saves/updates the selected host's documentation
(markdown). The user views it in the Docs panel and can export it."""
import inventory


def _run(ctx, args):
    if not ctx.host:
        return {'ok': False, 'error': 'no host selected'}
    content = (args.get('content') or '').strip()
    if not content:
        return {'ok': False, 'error': 'content (markdown documentation) is required'}
    inventory.set_doc(ctx.host['id'], content)
    if ctx.audit:
        ctx.audit('host:doc', ctx.host.get('name', ''), 'auto')
    return {'ok': True, 'saved': True, 'chars': len(content)}


def register_all(register, Tool):
    register(Tool(
        name='write_host_doc', needs_host=True, risk_hint='safe',
        description="Save or update the selected host's documentation (markdown). "
                    "Inspect the host first, then write clear docs: OS/version, "
                    "CPU/memory/disk, installed services + their roles, key config and "
                    "file locations, and what the host is used for. Overwrites the "
                    "existing doc, so include everything (start from the current doc if "
                    "one exists and you're updating).",
        parameters={'type': 'object', 'properties': {
            'content': {'type': 'string', 'description': 'the full markdown documentation'},
            'host': {'type': 'string', 'description': 'optional: target a different host by name instead of the selected one'},},
            'required': ['content']},
        run=_run))
