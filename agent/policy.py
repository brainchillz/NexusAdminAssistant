"""Risk classifier + per-host autonomy policy.

Pure and unit-tested. classify() combines static analysis with the model's own
declared intent; when they disagree, the HIGHER level wins (fail safe). The
per-host autonomy level then decides whether a given risk level auto-runs or
requires human confirmation:

  lab      → auto-run 'safe' and 'risky'; confirm only 'critical'
  default  → auto-run 'safe'; confirm 'risky' and 'critical'   (the agreed baseline)
  prod     → confirm everything that changes state ('caution'+)

Static analysis is ALLOWLIST-FIRST for shell commands: a command rates 'safe'
only when every segment of the pipeline/chain is a known read-only invocation.
Known-dangerous patterns escalate to 'risky'/'critical'; anything unrecognized
floors at 'caution' — an unknown command is treated as state-changing, never
silently waved through. (A denylist alone is an arms race against a shell
parser; the allowlist makes evasion fail closed.)

Risk levels: safe < caution < risky < critical.
"""
import re

LEVELS = ('safe', 'caution', 'risky', 'critical')
_ORDER = {lvl: i for i, lvl in enumerate(LEVELS)}

# ─── known-dangerous patterns (escalate above the 'caution' floor) ──────────
# Matched against a quote-stripped copy of the command so `systemctl "restart"`
# can't dodge a rule. Most-dangerous first; the HIGHEST level hit wins.
_RULES = [
    ('critical', [
        r'\bmkfs\b', r'\bfdisk\b', r'\bparted\b', r'\bwipefs\b',
        r'\bdd\b[^|;&]*\b(if|of)=/dev/(?!null|zero\b[^|;&]*\bof=/(?:tmp|home|var/tmp)/)',
        r'\bdd\b[^|;&]*\bof=/dev/[a-z]',
        r'\brm\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*r[a-zA-Z]*\s+/(?:\s|$|\*)',
        r'\brm\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*r[a-zA-Z]*f?\s+/(etc|boot|usr|var|bin|sbin|lib|root|home)\b',
        r'\b(reboot|shutdown|poweroff|halt|init\s+0|init\s+6)\b',
        r'\bmdadm\b.*--(create|remove|fail|zero-superblock)',
        r'\b(pvremove|vgremove|lvremove)\b', r'\bzpool\s+(destroy|remove)\b',
        r'\bdrop\s+database\b', r'>\s*/dev/[sv]d[a-z]', r':\(\)\s*\{', r'\bnvme\s+format\b',
    ]),
    ('risky', [
        r'\bsystemctl\s+(restart|stop|disable|mask)\b', r'\bservice\s+\w+\s+(restart|stop)\b',
        r'\b(rm|rmdir)\s+-', r'\bkill(all)?\b', r'\bumount\b', r'\bdd\b',
        r'\b(iptables|nft|ufw|firewall-cmd)\b', r'\bip\s+(addr|route|link)\s+(add|del|flush|change)\b',
        r'\buserdel\b', r'\bpasswd\b', r'\busermod\b',
        r'\bch(own|mod|grp)\b[^|;&]*\s-[a-zA-Z]*R\b', r'\bchmod\b[^|;&]*\b777\b',
        r'\b(apt|apt-get|dnf|yum|zypper|pacman|apk)\b.*\b(remove|purge|erase|autoremove)\b',
        r'\bdocker\s+(rm|rmi|system\s+prune|volume\s+rm)\b', r'\btruncate\b',
        r'\bcrontab\b', r'\bssh-keygen\b.*-f', r'>\s*/etc/', r'\btee\s+(-a\s+)?/etc/',
        r'\bgrub\b', r'\bupdate-grub\b', r'\bufw\s+(enable|disable)\b',
        r'\bfind\b[^|;&]*\s(-delete|-exec|-execdir|-ok|-okdir)\b',
        r'\bmv\b[^|;&]*\s/(etc|boot|usr|bin|sbin|lib)\b',
        r'\|\s*(sudo\s+)?(bash|sh|zsh|dash|ash|ksh)\b',          # pipe-to-shell, any source
        r'\b(bash|sh|zsh|dash)\s+/(tmp|var/tmp|dev/shm)/',       # run a downloaded script
        r'\beval\b',
        r'/etc/shadow\b', r'/etc/ssl/private', r'\.ssh/id_(?!\S*\.pub)\S+',  # secret reads
    ]),
    ('caution', [
        r'\bsystemctl\s+(start|enable|reload)\b', r'\bservice\s+\w+\s+start\b',
        r'\b(apt|apt-get|dnf|yum|zypper|pacman|apk)\b.*\b(install|update|upgrade|add)\b',
        r'\bpip\d?\s+install\b', r'\bnpm\s+(install|i)\b',
        r'(^|[|;&]\s*)(sudo\s+)?mysql(admin)?\b', r'\bgit\s+clone\b',
    ]),
]
_COMPILED = [(lvl, [re.compile(p, re.IGNORECASE) for p in pats]) for lvl, pats in _RULES]

# ─── read-only allowlist ────────────────────────────────────────────────────
# Commands safe to run with NO gate at any autonomy level. A full command line
# is 'safe' only if every pipe/&&/;-segment resolves to one of these (after
# stripping sudo/env/timeout/nice prefixes) and there is no output redirection
# or command substitution anywhere.
_READONLY_SIMPLE = {
    'ls', 'dir', 'pwd', 'whoami', 'id', 'groups', 'logname', 'tty',
    'uname', 'hostname', 'uptime', 'w', 'who', 'last', 'lastlog', 'lsb_release',
    'cat', 'tac', 'head', 'tail', 'less', 'more', 'nl', 'od', 'xxd', 'hexdump',
    'strings', 'column', 'wc', 'sort', 'uniq', 'cut', 'tr', 'jq', 'awk',
    'grep', 'egrep', 'fgrep', 'zgrep', 'zcat', 'rg', 'ag', 'diff', 'cmp', 'comm',
    'file', 'stat', 'du', 'df', 'free', 'lsblk', 'blkid', 'findmnt', 'mountpoint',
    'lscpu', 'lsmem', 'lspci', 'lsusb', 'lsmod', 'lsof', 'dmesg', 'nproc', 'arch',
    'ps', 'pgrep', 'pstree', 'vmstat', 'iostat', 'mpstat', 'sar', 'getconf',
    'ss', 'netstat', 'ping', 'traceroute', 'tracepath', 'mtr', 'dig', 'nslookup',
    'host', 'getent', 'env', 'printenv', 'echo', 'printf', 'test', 'true', 'false',
    'which', 'whereis', 'type', 'locate', 'readlink', 'realpath', 'basename',
    'dirname', 'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'b2sum', 'cksum',
    'journalctl', 'apt-cache', 'ldconfig', 'ldd', 'sleep', 'cal', 'seq', 'expr',
    'apt-mark', 'needrestart', 'numfmt', 'tput',
}
# cmd → the first argument/subcommand must match this (read-only subcommands)
_READONLY_SUB = {
    'systemctl': r'(status|show|cat|get-default|show-environment|is-active|is-enabled|is-failed|is-system-running|list-\S+)\b',
    'service': r'\S+\s+status\b',
    'docker': r'(ps|images|logs|inspect|version|info|top|port|diff)\b',
    'git': r'(status|log|diff|show|branch|remote|ls-files|rev-parse|describe|blame|shortlog)\b',
    'ip': r'(-\S+\s+)*(addr|address|route|link|neigh|rule)(\s+(show|list|get)\b|\s*$)',
    'apt': r'(list|search|show|policy)\b',
    'apt-get': r'(check|clean --dry-run)\b',
    'dpkg': r'(-l|-L|-s|-S|--list|--status|--listfiles|--search|--get-selections)\b',
    'dpkg-query': r'\S+',
    'rpm': r'-q\S*\b',
    'dnf': r'(list|search|info|repolist|check-update|history)\b',
    'yum': r'(list|search|info|repolist|check-update|history)\b',
    'pacman': r'(-Q\S*|-Ss|-Si)\b',
    'apk': r'(info|list|search|policy)\b',
    'snap': r'(list|info|version|services)\b',
    'flatpak': r'(list|info)\b',
    'pip': r'(list|show|freeze|check)\b',
    'pip3': r'(list|show|freeze|check)\b',
    'npm': r'(ls|list|view|outdated|ping)\b',
    'timedatectl': r'(status\b|show\b|$)',
    'hostnamectl': r'(status\b|$)',
    'localectl': r'(status\b|$)',
    'loginctl': r'(list-\S+|show-\S+|user-status|session-status)\b',
    'resolvectl': r'(status|query|dns|domain)\b',
    'ufw': r'status\b',
    'zpool': r'(status|list|iostat|history|get)\b',
    'zfs': r'(list|get)\b',
    'lvs': r'', 'vgs': r'', 'pvs': r'',
    'smartctl': r'(-i|-H|-a|--info|--health|--all)\b',
    'virsh': r'(list|dominfo|domstate)\b',
    'crictl': r'(ps|pods|images|inspect\S*|logs|version|info)\b',
    'kubectl': r'(get|describe|logs|version|cluster-info|top|api-resources)\b',
}
# cmd → a pattern that DISQUALIFIES an otherwise read-only command
_READONLY_VETO = {
    'sed': r'(^|\s)-[a-zA-Z]*i',            # in-place edit
    'find': r'\s(-delete|-exec|-execdir|-ok|-okdir|-fprint\S*)\b',
    'date': r'(^|\s)(-s\b|--set\b)',
    'sysctl': r'(=|(^|\s)-w\b|(^|\s)-p\b|--load)',
    'ping': r'(^|\s)-f\b',                   # flood
}
# sed/find/date/sysctl are conditionally read-only: allow when the veto misses
_READONLY_SIMPLE |= {'sed', 'find', 'date', 'sysctl'}

_SEG_SPLIT = re.compile(r'\|\||&&|;|\||\n')
_PREFIX = re.compile(
    r'^(?:sudo(?:\s+-\S+)*\s+|command\s+|nice(?:\s+-n\s*-?\d+)?\s+|'
    r'timeout\s+(?:-\S+\s+)*\S+\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+')
_HARMLESS_REDIR = re.compile(r'\d?>&\d|\d?>>?\s*/dev/null')


def _is_read_only(command: str) -> bool:
    """True only when the whole command line is provably read-only."""
    cmd = (command or '').strip()
    if not cmd:
        return False
    probe = _HARMLESS_REDIR.sub('', cmd)
    # any output redirection, command/process substitution, or eval/exec → not provable
    if re.search(r'[<>]\(|\$\(|`|>>?|\beval\b|\bexec\b', probe):
        return False
    for seg in _SEG_SPLIT.split(probe):
        seg = seg.strip()
        if re.match(r'(sudo\s+)?command\s+-[vV]\s+\S+$', seg):
            continue  # `command -v X` prints a path — read-only whatever X is
        seg = _PREFIX.sub('', seg)
        if not seg:
            return False
        m = re.match(r'^([A-Za-z0-9_.+/-]+)', seg)
        if not m:
            return False
        base = m.group(1).rsplit('/', 1)[-1].lower()
        rest = seg[m.end():].lstrip()
        veto = _READONLY_VETO.get(base)
        if veto and re.search(veto, seg):
            return False
        if base in _READONLY_SUB:
            if not re.match(_READONLY_SUB[base], rest):
                return False
        elif base not in _READONLY_SIMPLE:
            return False
    return True


def classify_command(command: str) -> str:
    """Static risk level for a shell command string.

    Dangerous patterns (matched with quotes stripped, so quoting can't dodge a
    rule) escalate to caution/risky/critical; otherwise a provably read-only
    command is 'safe' and ANYTHING unrecognized floors at 'caution'.
    """
    cmd = command or ''
    stripped = re.sub(r'''['"]''', '', cmd)
    hit = 'safe'
    for lvl, pats in _COMPILED:
        if _ORDER[lvl] > _ORDER[hit] and any(p.search(stripped) for p in pats):
            hit = lvl
    if hit != 'safe':
        return hit
    return 'safe' if _is_read_only(cmd) else 'caution'


# ─── path sensitivity for the file tools ────────────────────────────────────
# Writing these can grant/deny access or brick the box — never auto-run them.
_PATH_CRITICAL = re.compile(
    r'/etc/(shadow|gshadow|passwd|group|sudoers)|sudoers\.d/|authorized_keys',
    re.IGNORECASE)
# Writing these changes security posture or boot — treat as 'risky'.
_PATH_RISKY = re.compile(
    r'/etc/(ssh/|pam\.d/|ssl/|fstab|crontab|cron\.)|/boot/|\.ssh/|/etc/systemd/',
    re.IGNORECASE)
# Reading these exposes secrets — treat as 'risky'.
_PATH_SECRET = re.compile(
    r'/etc/(shadow|gshadow)|/etc/ssl/private|\.ssh/id_(?!\S*\.pub)|secring|\.pem$',
    re.IGNORECASE)


def classify_path(path: str, write: bool = True) -> str:
    """Risk of touching `path` with the file tools."""
    p = path or ''
    if write:
        if _PATH_CRITICAL.search(p):
            return 'critical'
        if _PATH_RISKY.search(p):
            return 'risky'
        return 'caution'
    return 'risky' if _PATH_SECRET.search(p) else 'safe'


def classify(tool_name: str, args: dict, model_intent: str = 'safe',
             base_risk: str = 'safe') -> str:
    """Combine static analysis with the model's self-declared intent.

    For ssh_exec the static level comes from the command rules (allowlist-first);
    for the file tools it is path-aware; http_request downgrades to 'safe' for
    read-only methods. We take the MAX of static + declared, so the model can
    escalate but never downgrade below what's detected (fail safe).
    """
    if tool_name == 'ssh_exec':
        static = classify_command(args.get('command', ''))
    elif tool_name == 'write_remote_file':
        static = classify_path(args.get('path', ''), write=True)
    elif tool_name == 'read_remote_file':
        static = classify_path(args.get('path', ''), write=False)
    elif tool_name == 'http_request':
        static = 'safe' if (args.get('method') or 'GET').upper() in ('GET', 'HEAD', 'OPTIONS') else base_risk
    else:
        static = base_risk if base_risk in _ORDER else 'safe'
    declared = model_intent if model_intent in _ORDER else 'safe'
    return static if _ORDER[static] >= _ORDER[declared] else declared


def unattended_decision(risk: str, ceiling: str, allow_list, command: str = '') -> str:
    """For a scheduled job running with NO human present. Returns 'run' or 'defer'.

    Runs if the action's risk is at or below the job's pre-authorized ceiling, OR
    the command matches a pre-approved allow-list entry (case-insensitive
    substring). Otherwise it is deferred for later human approval — never silently
    performed. `critical` still runs only if the ceiling is explicitly 'critical'
    or the exact action is allow-listed.
    """
    r = _ORDER.get(risk, _ORDER['critical'])
    cap = _ORDER.get(ceiling, _ORDER['caution'])
    if r <= cap:
        return 'run'
    cmd = (command or '').lower()
    for entry in (allow_list or []):
        e = (entry or '').strip().lower()
        if e and e in cmd:
            return 'run'
    return 'defer'


# The highest ceiling a human can pre-authorize for a plan. Critical actions
# (reboot, mkfs, mass delete) always get their own approval — a one-line plan
# summary is not informed consent for wiping a disk. They can still be
# pre-approved individually by listing the exact command in the allow-list.
MAX_ENVELOPE_CEILING = 'risky'


def clamp_ceiling(ceiling: str) -> str:
    c = ceiling if ceiling in _ORDER else 'caution'
    return c if _ORDER[c] <= _ORDER[MAX_ENVELOPE_CEILING] else MAX_ENVELOPE_CEILING


def envelope_covers(envelope, risk: str, command: str = '', host_key=None) -> bool:
    """Does an approved plan envelope already authorize this action?

    The interactive twin of unattended_decision: the human approved a described
    plan with a risk ceiling, so work inside it proceeds without re-asking, and
    anything beyond it still stops for approval. Scoped to the hosts the plan
    named, so an envelope for one box never silently covers another.
    """
    if not envelope:
        return False
    hosts = envelope.get('hosts') or []
    if hosts and host_key is not None and host_key not in hosts:
        return False
    return unattended_decision(risk, clamp_ceiling(envelope.get('ceiling', 'caution')),
                               envelope.get('allow'), command) == 'run'


def needs_confirmation(risk: str, autonomy_level: str = 'default') -> bool:
    """Given a risk level and the host's autonomy level, must a human approve?"""
    r = _ORDER.get(risk, 0)
    if autonomy_level == 'lab':
        return r >= _ORDER['critical']
    if autonomy_level == 'prod':
        return r >= _ORDER['caution']
    # default
    return r >= _ORDER['risky']
