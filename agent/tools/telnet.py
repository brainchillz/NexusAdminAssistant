"""telnet tool — raw line-protocol access for legacy gear (switches, IPMI,
serial-over-LAN consoles). Python 3.13+ removed telnetlib, so this is a minimal
socket client that answers IAC option negotiation with refusals (WONT/DONT) and
returns the text transcript. The model drives login by sending username/password
as commands.
"""
import socket
import time

IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251


def _negotiate(sock, data):
    """Strip Telnet IAC sequences from `data`, replying to DO/WILL with refusals
    so the far end stops asking. Returns the plain bytes."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == IAC and i + 2 < len(data):
            cmd, opt = data[i + 1], data[i + 2]
            if cmd == DO:
                sock.sendall(bytes([IAC, WONT, opt]))
            elif cmd == WILL:
                sock.sendall(bytes([IAC, DONT, opt]))
            i += 3
            continue
        if b == IAC and i + 1 < len(data):  # 2-byte command
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


def _run(ctx, args):
    host = (args.get('host') or (ctx.host or {}).get('address') or '').strip()
    if not host:
        return {'ok': False, 'error': 'no host (select one or pass host=)'}
    port = int(args.get('port', 23))
    commands = args.get('commands') or ([args['command']] if args.get('command') else [])
    wait = float(args.get('read_wait', 1.5))
    transcript = []
    try:
        sock = socket.create_connection((host, port), timeout=15)
        sock.settimeout(wait)

        def drain():
            buf = bytearray()
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            except socket.timeout:
                pass
            text = _negotiate(sock, bytes(buf)).decode(errors='replace')
            if text:
                transcript.append(text)
                if ctx.on_output:
                    ctx.on_output(text)

        drain()  # banner / initial prompt
        for cmd in commands:
            sock.sendall(cmd.encode() + b'\r\n')
            time.sleep(0.2)
            drain()
        sock.close()
        return {'ok': True, 'transcript': ''.join(transcript)[-6000:]}
    except (socket.timeout, OSError) as e:
        return {'ok': False, 'error': f'telnet failed: {e}', 'transcript': ''.join(transcript)}


def register_all(register, Tool):
    register(Tool(
        name='telnet', needs_host=False, risk_hint='caution',
        description='Open a raw telnet/line-protocol session to legacy gear (switches, '
                    'IPMI, console servers). Sends each string in `commands` and returns '
                    'the text transcript. Drive logins by sending username then password.',
        parameters={'type': 'object', 'properties': {
            'host': {'type': 'string', 'description': 'target (defaults to the selected host)'},
            'port': {'type': 'integer', 'description': 'default 23'},
            'commands': {'type': 'array', 'items': {'type': 'string'},
                         'description': 'lines to send in order (e.g. [user, pass, "show version"])'},
            'read_wait': {'type': 'number', 'description': 'seconds to wait for output per step'},
            'intent': {'type': 'string', 'enum': ['safe', 'caution', 'risky', 'critical']}},
            'required': ['commands']},
        run=_run))
