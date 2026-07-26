"""Tool registry. ssh_exec + write_remote_file (host tools); web_search/web_fetch/
http_request (hostless). Later phases add telnet/schedule/memory — each is one
register() call."""
from agent.tools import (files, healthtool, hostdoc, http, memtool, plantool,
                         schedtool, skilltool, ssh, telnet, web)
from agent.tools.base import Tool, ToolContext, all_tools, get, register


def _ssh_exec_run(ctx: ToolContext, args: dict):
    if not ctx.host:
        return {'ok': False, 'error': 'no host selected — pick a host in the sidebar first'}
    command = args.get('command', '').strip()
    if not command:
        return {'ok': False, 'error': 'empty command'}
    use_sudo = bool(args.get('sudo', False))
    res = ssh.run(ctx.host, ctx.secrets, command, on_output=ctx.on_output,
                  use_sudo=use_sudo)
    return {
        'ok': res['exit_code'] == 0,
        'exit_code': res['exit_code'],
        'output': res['output'][-8000:],  # cap what goes back into the LLM context
        'error': res['error'],
    }


register(Tool(
    name='ssh_exec',
    description=(
        'Run a shell command on the currently selected host over SSH and return '
        'its combined stdout/stderr and exit code. Use for inspecting the system '
        '(OS, packages, services, files) and for making changes (installing and '
        'configuring software). Set sudo=true when the command needs root. Prefer '
        'idempotent, non-interactive commands (e.g. apt-get -y). One command per '
        'call; chain with && or ; inside a single command when needed.'
    ),
    parameters={
        'type': 'object',
        'properties': {
            'command': {'type': 'string', 'description': 'The shell command to run.'},
            'sudo': {'type': 'boolean', 'description': 'Run with sudo (root). Default false.'},
            'intent': {
                'type': 'string',
                'enum': ['safe', 'caution', 'risky', 'critical'],
                'description': (
                    'Your honest assessment of this command\'s risk: safe=read-only/'
                    'inspection; caution=installs/writes new files; risky=restarts '
                    'services, deletes, firewall/user changes; critical=reboot, disk '
                    'format, mass delete. Be truthful — it drives the human approval gate.'
                ),
            },
            'host': {'type': 'string', 'description': (
                'Optional: run on a DIFFERENT host by name (from the hosts you manage) '
                'instead of the selected one. Use to orchestrate across hosts.')},
        },
        'required': ['command'],
    },
    risk_hint='caution',
    run=_ssh_exec_run,
))

# hostless + file tools self-register through their register_all()
web.register_all(register, Tool)
http.register_all(register, Tool)
files.register_all(register, Tool)
telnet.register_all(register, Tool)
memtool.register_all(register, Tool)
skilltool.register_all(register, Tool)
schedtool.register_all(register, Tool)
healthtool.register_all(register, Tool)
hostdoc.register_all(register, Tool)
plantool.register_all(register, Tool)

__all__ = ['Tool', 'ToolContext', 'register', 'get', 'all_tools']
