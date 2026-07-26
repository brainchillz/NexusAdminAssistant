"""write_remote_file — write a file to the selected host over SSH, base64-safe
(no shell-quoting hazards, which bit the agent when it used sed for config files).
Supports sudo for root-owned paths. Overwriting existing files is 'caution'.
"""
import base64

from agent.tools import ssh


def push_file(host, secrets, path, content, use_sudo, on_output=None):
    """Base64-safe write of `content` to `path`. Reusable (tool + revert)."""
    b64 = base64.b64encode(content.encode()).decode()
    cmd = (f'printf %s {b64} | base64 -d | tee {_q(path)} > /dev/null '
           f'&& echo WROTE {len(content)} bytes')
    return ssh.run(host, secrets, cmd, on_output=on_output, use_sudo=use_sudo)


def read_file(host, secrets, path, use_sudo):
    """Read a file's current content. Returns (content, exists)."""
    res = ssh.run(host, secrets, f'cat {_q(path)} 2>/dev/null', use_sudo=use_sudo)
    if res['exit_code'] == 0:
        return res['output'], True
    return '', False


def _run(ctx, args):
    if not ctx.host:
        return {'ok': False, 'error': 'no host selected'}
    path = (args.get('path') or '').strip()
    content = args.get('content')
    if not path or content is None:
        return {'ok': False, 'error': 'path and content are required'}
    use_sudo = bool(args.get('sudo', False))
    # capture the current file for rollback (best-effort) BEFORE overwriting
    before, had_before = read_file(ctx.host, ctx.secrets, path, use_sudo)
    res = push_file(ctx.host, ctx.secrets, path, content, use_sudo, on_output=ctx.on_output)
    if res['exit_code'] == 0:
        try:
            import changes
            changes.record_file_change(ctx.host['id'], ctx.user, ctx.conversation_id,
                                       path, before, content, had_before, use_sudo)
        except Exception:  # noqa: BLE001 — journaling must never break the write
            pass
    return {'ok': res['exit_code'] == 0, 'exit_code': res['exit_code'],
            'output': res['output'][-2000:], 'error': res['error']}


def _q(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _read_run(ctx, args):
    if not ctx.host:
        return {'ok': False, 'error': 'no host selected'}
    path = (args.get('path') or '').strip()
    if not path:
        return {'ok': False, 'error': 'path is required'}
    limit = min(int(args.get('max_bytes', 20000)), 200000)
    client = None
    try:
        client = ssh.connect(ctx.host, ctx.secrets)
        sftp = client.open_sftp()
        st = sftp.stat(path)
        with sftp.open(path, 'r') as f:
            data = f.read(limit + 1)
        text = data.decode(errors='replace') if isinstance(data, bytes) else data
        truncated = len(text) > limit or st.st_size > limit
        return {'ok': True, 'path': path, 'size': st.st_size,
                'truncated': truncated, 'content': text[:limit]}
    except IOError as e:
        # Root-only file. No SILENT escalation: sudo must be asked for
        # explicitly so it shows on the tool card and in the audit trail.
        if not bool(args.get('sudo')):
            return {'ok': False, 'error':
                    f'cannot read {path}: {e} — if it is root-only, retry with sudo=true'}
        res = ssh.run(ctx.host, ctx.secrets, f'cat {_q(path)}', use_sudo=True)
        if res['exit_code'] == 0:
            return {'ok': True, 'path': path, 'content': res['output'][:limit], 'truncated': False}
        return {'ok': False, 'error': f'cannot read {path}: {e}'}
    finally:
        if client:
            client.close()


def register_all(register, Tool):
    register(Tool(
        name='write_remote_file', needs_host=True, risk_hint='caution',
        description='Write a text file to an exact path on the selected host (creates '
                    'or overwrites). Base64-safe — prefer this over sed/echo for config '
                    'files. Set sudo=true for root-owned paths.',
        parameters={'type': 'object', 'properties': {
            'path': {'type': 'string', 'description': 'absolute path on the host'},
            'content': {'type': 'string'},
            'sudo': {'type': 'boolean'},
            'intent': {'type': 'string', 'enum': ['safe', 'caution', 'risky', 'critical']},
            'host': {'type': 'string', 'description': 'optional: target a different host by name instead of the selected one'},},
            'required': ['path', 'content']},
        run=_run))
    register(Tool(
        name='read_remote_file', needs_host=True, risk_hint='safe',
        description='Read a file from the selected host over SFTP and return its text. '
                    'For root-only files set sudo=true explicitly. Use to inspect '
                    'configs and logs cleanly.',
        parameters={'type': 'object', 'properties': {
            'path': {'type': 'string', 'description': 'absolute path on the host'},
            'max_bytes': {'type': 'integer', 'description': 'cap (default 20000)'},
            'sudo': {'type': 'boolean', 'description': 'read as root (root-only files). Default false.'},
            'host': {'type': 'string', 'description': 'optional: target a different host by name instead of the selected one'},},
            'required': ['path']},
        run=_read_run))
