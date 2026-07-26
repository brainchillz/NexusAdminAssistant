"""SSH primitives — connect, run (streaming), sudo handling, test connection.

Secrets arrive decrypted from inventory.secrets_for() and are used only here;
they never enter the LLM context or logs. Passwordless sudo is auto-detected;
otherwise the stored sudo password is fed to `sudo -S` over stdin.
"""
import io
import re
import socket
import time

try:
    import paramiko
except ImportError:  # allow import without paramiko (tests that don't touch SSH)
    paramiko = None

DEFAULT_TIMEOUT = 120

# Commands run WITHOUT a PTY (see run()), so most tools won't colorize — but
# anything forced (ls --color=always, tools that ignore isatty) would still put
# escape bytes in the chat tool-card and the LLM context. Strip them from
# captured output as belt-and-braces. (The interactive xterm.js shell is a
# separate path and keeps its colors.)
_ANSI_RE = re.compile(
    r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)'   # OSC ... terminated by BEL or ST
    r'|\x1b[@-Z\\-_]'                        # two-char Fe escapes
    r'|\x1b\[[0-?]*[ -/]*[@-~]'             # CSI ... (colors, cursor moves)
    r'|\x1b[ -/]*[0-~]'                      # any other escape
)
# C0 control chars except tab (09) and newline (0a); also DEL (7f).
_CTRL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def strip_terminal(text):
    """Remove ANSI escape sequences + stray control chars from PTY output."""
    text = _ANSI_RE.sub('', text)
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return _CTRL_RE.sub('', text)


def _pkey_from_str(key_str):
    """Parse a private key string. Raises ValueError with a human-readable
    reason when a key was supplied but is unusable — a silent None here used to
    make auth fall through to password/no-auth with a baffling generic error."""
    if not key_str:
        return None
    key_str = key_str.strip()
    first = key_str.splitlines()[0] if key_str else ''
    if first.startswith(('ssh-', 'ecdsa-', 'sk-')):
        raise ValueError('that is a PUBLIC key — paste the PRIVATE key '
                         '(starts with "-----BEGIN ... PRIVATE KEY-----"), '
                         'or store it as a shared credential and deploy it')
    if 'PuTTY-User-Key-File' in first:
        raise ValueError('PuTTY .ppk keys are not supported — export to OpenSSH '
                         'format (puttygen: Conversions → Export OpenSSH key)')
    needs_passphrase = False
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(key_str + '\n'))
        except paramiko.PasswordRequiredException:
            needs_passphrase = True
        except Exception:
            continue
    if needs_passphrase:
        raise ValueError('the private key is passphrase-protected — store an '
                         'unencrypted copy (ssh-keygen -p -N "" -f <key>)')
    raise ValueError('unrecognized private key — expected an OpenSSH/PEM '
                     'Ed25519, RSA or ECDSA private key')


def connect(host, secrets, timeout=20):
    """Open a paramiko SSHClient to a host record. Raises on failure."""
    if paramiko is None:
        raise RuntimeError('paramiko not installed')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(
        hostname=host['address'], port=int(host.get('port') or 22),
        username=secrets.get('username') or 'root', timeout=timeout,
        allow_agent=False, look_for_keys=False, banner_timeout=timeout,
    )
    pkey = _pkey_from_str(secrets.get('ssh_key'))
    if pkey is not None:
        kwargs['pkey'] = pkey
    if secrets.get('password'):
        kwargs['password'] = secrets['password']
    client.connect(**kwargs)
    return client


def _has_passwordless_sudo(client):
    try:
        _, out, _ = client.exec_command('sudo -n true 2>/dev/null && echo OK', timeout=10)
        return out.read().decode(errors='replace').strip() == 'OK'
    except Exception:
        return False


# Pager-aware tools — resolvectl, journalctl, systemctl status, git log —
# must never hang waiting for a keypress. With no PTY they shouldn't page at
# all, but tools that check env before isatty still get `cat`. Exported inside
# the command (so it also survives the sudo bash -lc wrap).
_NO_PAGER = 'export PAGER=cat SYSTEMD_PAGER=cat GIT_PAGER=cat; '


def run(host, secrets, command, on_output=None, timeout=DEFAULT_TIMEOUT, use_sudo=False):
    """Run `command`, streaming stdout+stderr to on_output(chunk). Returns
    {exit_code, output, error}. Handles sudo (auto-detect passwordless, else the
    stored sudo password over stdin)."""
    command = _NO_PAGER + command
    client = None
    buf = []          # RAW chunks — final result is cleaned from these at return
    line_buf = ['']   # holds a partial trailing line so escape seqs aren't split

    def emit(chunk):
        buf.append(chunk)
        if not on_output:
            return
        # line-buffer the live stream: an ANSI sequence never spans a newline, so
        # cleaning whole lines avoids stripping a sequence split across recv() reads.
        line_buf[0] += chunk
        if '\n' in line_buf[0]:
            *done, line_buf[0] = line_buf[0].split('\n')
            on_output(strip_terminal('\n'.join(done) + '\n'))

    def flush():
        if on_output and line_buf[0]:
            on_output(strip_terminal(line_buf[0]))
            line_buf[0] = ''

    try:
        client = connect(host, secrets)
        sudo_pw = secrets.get('sudo_password')
        prefixed = command
        stdin_pw = None
        if use_sudo:
            if _has_passwordless_sudo(client):
                prefixed = f'sudo -n bash -lc {_shquote(command)}'
            elif sudo_pw:
                prefixed = f'sudo -S -p "" bash -lc {_shquote(command)}'
                stdin_pw = sudo_pw
            else:
                # no stored password and no NOPASSWD: fails fast with a clear
                # "a terminal is required" error instead of hanging at a prompt
                prefixed = f'sudo bash -lc {_shquote(command)}'

        chan = client.get_transport().open_session()
        chan.settimeout(timeout)
        # No PTY: a PTY's line discipline echoes everything written to stdin —
        # including the sudo password — back into the captured output (and from
        # there into the LLM context and message history). stderr is merged
        # without one, sudo -S reads stdin fine without one, and pagers/colors
        # stay off because the command sees no terminal.
        chan.set_combine_stderr(True)
        chan.exec_command(prefixed)
        if stdin_pw:
            chan.sendall(stdin_pw + '\n')
        chan.shutdown_write()  # nothing else arrives on stdin — don't let reads hang

        deadline = time.time() + timeout
        while True:
            if chan.recv_ready():
                data = chan.recv(4096)
                if data:
                    emit(data.decode(errors='replace'))
            if chan.exit_status_ready() and not chan.recv_ready():
                # drain
                while chan.recv_ready():
                    emit(chan.recv(4096).decode(errors='replace'))
                break
            if time.time() > deadline:
                emit('\n[timed out]\n')
                flush()
                return {'exit_code': 124, 'output': strip_terminal(''.join(buf)), 'error': 'timeout'}
            time.sleep(0.03)
        code = chan.recv_exit_status()
        flush()
        return {'exit_code': code, 'output': strip_terminal(''.join(buf)), 'error': ''}
    except (paramiko.SSHException, socket.error, OSError) as e:
        flush()
        return {'exit_code': -1, 'output': strip_terminal(''.join(buf)), 'error': _friendly(e)}
    except Exception as e:  # noqa: BLE001 — surface anything as a tool error
        flush()
        return {'exit_code': -1, 'output': strip_terminal(''.join(buf)), 'error': str(e)}
    finally:
        if client:
            client.close()


def test_connection(host, secrets):
    """Quick reachability + identity check for the Add/Edit Host modal."""
    res = run(host, secrets, 'uname -a; echo "---"; (cat /etc/os-release 2>/dev/null | grep -E "^PRETTY_NAME=" || true)',
              timeout=25)
    if res['exit_code'] == 0 or res['output']:
        os_line = ''
        for line in res['output'].splitlines():
            if line.startswith('PRETTY_NAME='):
                os_line = line.split('=', 1)[1].strip().strip('"')
        return {'ok': res['exit_code'] == 0, 'os': os_line, 'uname': res['output'].split('---')[0].strip(),
                'error': res['error']}
    return {'ok': False, 'os': '', 'uname': '', 'error': res['error'] or 'connection failed'}


def _shquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def _friendly(e):
    msg = str(e).lower()
    if 'authentication' in msg:
        return 'authentication failed (check username/password/key)'
    if 'no route' in msg or 'unreachable' in msg:
        return 'no route to host'
    if 'refused' in msg:
        return 'connection refused'
    if 'timed out' in msg or 'timeout' in msg:
        return 'connection timed out'
    if 'name or service' in msg or 'getaddrinfo' in msg:
        return 'DNS lookup failed'
    return str(e)
