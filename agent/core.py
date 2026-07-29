"""The agent loop: plan → call tool → (gate) → observe → continue.

Each user turn spawns a Run in a background thread. The Run streams structured
events into a queue that the SSE endpoint drains. Risky tool calls pause the loop
on a threading.Event until the browser POSTs an approve/deny decision. A Run can
be stopped at any time.

Events emitted (all carry `type`):
  token         {text}                     — streamed assistant text
  tool_call     {call_id, tool, args, risk}
  tool_output   {call_id, chunk}           — live command output
  confirm_request {call_id, tool, command, sudo, risk, explanation}
  plan_request  {call_id, summary, steps, ceiling, allow, hosts, risk_note}
  plan_result   {call_id, approved, ceiling}
  envelope_run  {call_id, risk, ceiling}     — ran under an approved plan
  tool_result   {call_id, ok, exit_code, error}
  message       {role, content}            — a completed assistant message
  error         {message}
  done          {}
"""
import json
import queue
import secrets as _secrets
import threading
import time
from datetime import datetime, timezone

import inventory
import logs
import memory
import monitor
import scrub
import skills
from agent import llm, policy, prompts
from agent import tools as toolkit
from store import db

log = logs.get('agent')

MAX_ITERS = 40
CONFIRM_TIMEOUT = 900  # seconds a run waits for a human decision

DEFAULT_TITLE = 'New conversation'

RUNS = {}
_runs_lock = threading.Lock()


def derive_title(text, max_len=48):
    """A short, human-readable conversation title from the first user message.
    Collapses whitespace, capitalizes, and truncates on a word boundary."""
    import re
    t = re.sub(r'\s+', ' ', (text or '').strip())
    if not t:
        return DEFAULT_TITLE
    t = t[0].upper() + t[1:]
    if len(t) <= max_len:
        return t
    cut = t[:max_len].rsplit(' ', 1)[0] or t[:max_len]
    return cut.rstrip(' ,.;:!?-') + '…'


def _now():
    return datetime.now(timezone.utc).isoformat()


class Run:
    def __init__(self, conversation, host, secrets, user):
        self.id = _secrets.token_hex(8)
        self.conversation = conversation
        self.host = host                    # raw host record or None
        self.secrets = secrets              # decrypted secrets or None
        self.user = user
        self.host_public = inventory.public(host) if host else None
        self.autonomy = (host or {}).get('autonomy_level', 'default')
        self.q = queue.Queue()
        self.stop_flag = threading.Event()
        self.pending = {}                   # call_id -> {event, decision, command}
        self.pending_lock = threading.Lock()  # agent thread writes, request threads read
        self.auto_approve = False           # set by "approve for session"
        self.envelope = None                # an approved plan (see propose_plan)
        self.finished = False
        self.finished_at = 0.0
        # unattended (scheduled job) mode
        self.unattended = False
        self.job_id = None
        self.job_ceiling = 'caution'
        self.job_allow = []
        self.on_defer = None                # callback to record a deferred action
        self.report = []                    # report lines for a job run
        self.deferred_count = 0
        self.had_error = False

    def emit(self, etype, **data):
        self.q.put({'type': etype, **data})
        if self.unattended:
            self._report_line(etype, data)

    def _report_line(self, etype, data):
        if etype == 'message' and data.get('content'):
            self.report.append(data['content'])
        elif etype == 'tool_call':
            cmd = (data.get('args') or {}).get('command') or str(data.get('args'))
            self.report.append(f"• {data.get('tool')} [{data.get('risk')}]: {cmd}")
        elif etype == 'tool_result':
            self.report.append(f"  → {'ok' if data.get('ok') else 'FAILED'} "
                               f"exit={data.get('exit_code')}" +
                               (f" {data.get('error')}" if not data.get('ok') else ''))
        elif etype == 'deferred':
            self.report.append(f"  ⚠ DEFERRED (needs approval): {data.get('command')}")
        elif etype == 'error':
            self.had_error = True
            self.report.append(f"[error] {data.get('message')}")

    def audit(self, action, detail='', decision='', host_id=None):
        hid = host_id if host_id is not None else (self.host or {}).get('id', '')
        db.execute(
            'INSERT INTO audit(ts, user_id, username, host_id, action, detail, decision)'
            ' VALUES(?,?,?,?,?,?,?)',
            (_now(), (self.user or {}).get('id', ''), (self.user or {}).get('username', ''),
             hid, action, detail[:2000], decision))


# ─── public API used by the web layer ─────────────────────────────────
def start(conversation, host, secrets, user):
    _reap()
    _ensure_reaper()
    run = Run(conversation, host, secrets, user)
    with _runs_lock:
        RUNS[run.id] = run
    threading.Thread(target=_drive, args=(run,), daemon=True).start()
    return run


def get(run_id):
    with _runs_lock:
        return RUNS.get(run_id)


def active_conversation_ids():
    """Ids of conversations with an unfinished in-process run — deleting one of
    these would orphan a live agent thread, so the web layer refuses."""
    with _runs_lock:
        return {(run.conversation or {}).get('id')
                for run in RUNS.values() if not run.finished}


def cleanup(run_id):
    """Called by the stream endpoint once it has drained the run's events."""
    with _runs_lock:
        RUNS.pop(run_id, None)


def _reap(ttl=180):
    """Drop finished runs a client never connected to (buffered events retained
    until then so a late stream still gets them)."""
    now = time.time()
    with _runs_lock:
        for rid in [r for r, run in RUNS.items()
                    if run.finished and now - run.finished_at > ttl]:
            RUNS.pop(rid, None)


_reaper = None


def _ensure_reaper(interval=60):
    """Reap on a timer, not only when the next run starts — otherwise a quiet
    period leaves finished runs (and their buffered events) sitting in RUNS."""
    global _reaper
    with _runs_lock:
        if _reaper and _reaper.is_alive():
            return
        def loop():
            while True:
                time.sleep(interval)
                try:
                    _reap()
                except Exception:  # noqa: BLE001 — a reaper must never die
                    pass
        _reaper = threading.Thread(target=loop, daemon=True, name='run-reaper')
        _reaper.start()


def may_control(run, user):
    """Only the user who started a run (or an admin) may approve/deny/stop it.

    Without this any operator holding a run_id could approve a critical action
    on a host outside their own tag scope — the approval gate is the whole
    safety model, so it has to be bound to an identity.
    """
    if not run or not user:
        return False
    if user.get('role') == 'admin':
        return True
    return bool(run.user) and run.user.get('id') == user.get('id')


def confirm(run_id, call_id, decision, command=None, user=None):
    """Record a human decision for a pending gated call. Returns True if applied.

    `user` is the caller; when supplied it must own the run (see may_control).
    An EDITED command is re-classified before it executes — see _run_tool.
    """
    run = get(run_id)
    if not run:
        return False
    if user is not None and not may_control(run, user):
        return False
    with run.pending_lock:
        p = run.pending.get(call_id)
        if not p:
            return False
        p['decision'] = decision
        if command is not None:
            p['command'] = command
        if decision == 'approve_session':
            run.auto_approve = True
        p['event'].set()
    return True


def run_unattended(job, host, secrets, user, on_defer):
    """Run one scheduled job synchronously with no human present. Returns
    {status, report, deferred}."""
    cid = _secrets.token_hex(8)
    db.execute('INSERT INTO conversations(id, host_id, user_id, title, created_at, updated_at)'
               ' VALUES(?,?,?,?,?,?)',
               (cid, job.get('host_id'), (user or {}).get('id', ''),
                f"[job] {job['name']} {_now()[:16]}", _now(), _now()))
    db.execute('INSERT INTO messages(conversation_id, role, content, created_at) VALUES(?,?,?,?)',
               (cid, 'user', job.get('instruction', ''), _now()))
    convo = {'id': cid, 'host_id': job.get('host_id')}
    run = Run(convo, host, secrets, user)
    run.unattended = True
    run.job_id = job['id']
    run.job_ceiling = job.get('ceiling', 'caution')
    run.job_allow = job.get('allow', [])
    run.on_defer = on_defer
    _drive(run)  # blocks until the job's agent loop finishes
    status = 'deferred' if run.deferred_count else ('error' if run.had_error else 'ok')
    header = (f"Job: {job['name']}\nHost: {(host or {}).get('name', '(none)')}\n"
              f"Ceiling: {run.job_ceiling}\nResult: {status}"
              f"{f' — {run.deferred_count} action(s) deferred for approval' if run.deferred_count else ''}\n"
              + '─' * 40 + '\n')
    return {'status': status, 'report': header + '\n'.join(run.report), 'deferred': run.deferred_count}


def stop(run_id, user=None):
    run = get(run_id)
    if not run:
        return False
    if user is not None and not may_control(run, user):
        return False
    run.stop_flag.set()
    # release any pending confirmation so the thread can exit
    with run.pending_lock:
        for p in list(run.pending.values()):
            p.setdefault('decision', 'deny')
            p['event'].set()
    return True


# ─── the loop ─────────────────────────────────────────────────────────
def _load_history(conversation_id):
    """Prior turns as plain {role, content} (tool rows collapsed for a valid,
    provider-neutral payload across runs)."""
    rows = db.query(
        'SELECT role, content FROM messages WHERE conversation_id=? ORDER BY id',
        (conversation_id,))
    hist = []
    for r in rows:
        if r['role'] in ('user', 'assistant') and (r['content'] or '').strip():
            hist.append({'role': r['role'], 'content': r['content']})
    return hist


def _save_message(conversation_id, role, content, tool_calls=None):
    db.execute(
        'INSERT INTO messages(conversation_id, role, content, tool_calls_json, created_at)'
        ' VALUES(?,?,?,?,?)',
        (conversation_id, role, content or '', json.dumps(tool_calls) if tool_calls else '', _now()))
    db.execute('UPDATE conversations SET updated_at=? WHERE id=?', (_now(), conversation_id))


def _drive(run):
    try:
        history = _load_history(run.conversation['id'])
        try:
            scoped_hosts = inventory.list_for_user(run.user) if run.user else []
            estate_ctx = memory.estate_context(scoped_hosts)
            skill_ctx = skills.context_text()
            if skill_ctx:
                estate_ctx = (estate_ctx + '\n\n' + skill_ctx) if estate_ctx else skill_ctx
            host_mem = memory.host_context(run.host['id']) if run.host else ''
            if run.host:
                hl = monitor.health_line(run.host['id'])
                if hl:
                    host_mem = (host_mem + '\n\n' + hl) if host_mem else hl
        except Exception:  # noqa: BLE001 — memory/health are best-effort context
            estate_ctx, host_mem = '', ''
        messages = prompts.build_messages(history, run.host_public, estate_ctx, host_mem)
        tools = toolkit.all_tools()

        for _ in range(MAX_ITERS):
            if run.stop_flag.is_set():
                break
            try:
                res = llm.chat(messages, tools=tools, on_text=lambda t: run.emit('token', text=t))
            except llm.LLMError as e:
                log.error('LLM call failed (run %s): %s', run.id, e)
                run.emit('error', message=str(e))
                _save_message(run.conversation['id'], 'assistant', f'[LLM error] {e}')
                break

            content = res['content']
            calls = res['tool_calls']

            if not calls:
                if content:
                    _save_message(run.conversation['id'], 'assistant', content)
                    run.emit('message', role='assistant', content=content)
                break

            # record the assistant turn (text + the tool calls it wants)
            if content:
                run.emit('message', role='assistant', content=content)
            messages.append({'role': 'assistant', 'content': content, 'tool_calls': calls})
            _save_message(run.conversation['id'], 'assistant', content, tool_calls=[
                {'name': c['name'], 'arguments': c['arguments']} for c in calls])

            for call in calls:
                if run.stop_flag.is_set():
                    break
                result = _run_tool(run, call)
                messages.append({'role': 'tool', 'tool_call_id': call['id'],
                                 'name': call['name'],
                                 'content': prompts.wrap_tool_result(
                                     call['name'], json.dumps(result))})
                _save_message(run.conversation['id'], 'tool',
                              _result_summary(call, result))
        else:
            run.emit('error', message=f'Reached the step limit ({MAX_ITERS}).')
    except Exception as e:  # noqa: BLE001
        log.exception('agent run %s failed', run.id)
        run.emit('error', message=f'Agent error: {e}')
    finally:
        run.finished = True
        run.finished_at = time.time()
        # the run may linger in RUNS until a client drains it — don't keep
        # decrypted host credentials in memory that whole time
        run.secrets = None
        run.emit('done')
        # run stays in RUNS (with buffered events) until the stream drains it
        # via cleanup(), or _reap() collects it after a TTL.


# tools whose optional `host` arg selects a DIFFERENT managed host (telnet's
# `host` means the telnet target address, so it is excluded).
_HOST_TARGETABLE = {'ssh_exec', 'write_remote_file', 'read_remote_file',
                    'host_health', 'write_host_doc'}


def _resolve_target(run, name, args):
    """Return (host_record, secrets, error). Defaults to the active host; if a
    host-targetable tool names another in-scope host, resolve to it."""
    if name not in _HOST_TARGETABLE:
        return run.host, run.secrets, None
    hname = (args or {}).get('host')
    if not hname:
        return run.host, run.secrets, None
    if run.host and (run.host.get('name') == hname or run.host.get('id') == hname):
        return run.host, run.secrets, None
    hosts = inventory.list_for_user(run.user) if run.user else []
    match = next((h for h in hosts if h['id'] == hname or h['name'] == hname), None)
    if not match:
        return None, None, f"host '{hname}' not found or not in your scope"
    rec = inventory.get_raw(match['id'])
    return rec, inventory.secrets_for(rec), None


def _run_tool(run, call):
    name = call['name']
    args = call['arguments'] or {}
    tool = toolkit.get(name)
    if not tool:
        return {'ok': False, 'error': f'unknown tool: {name}'}

    # multi-host: a host-targetable tool may name a DIFFERENT in-scope host to act
    # on. Resolve it; the effective host drives autonomy, confirm card, audit, and
    # the change journal.
    eff_host, eff_secrets, herr = _resolve_target(run, name, args)
    if herr:
        run.emit('tool_call', call_id=call['id'], tool=name, args=_safe_args(args),
                 risk='safe', host=args.get('host') or '')
        run.emit('tool_result', call_id=call['id'], ok=False, exit_code=None, error=herr)
        return {'ok': False, 'error': herr}
    eff_autonomy = (eff_host or {}).get('autonomy_level', 'default')
    eff_id = (eff_host or {}).get('id', '')
    eff_name = (eff_host or {}).get('name', '')

    if name == 'propose_plan':
        return _propose_plan(run, call, args, eff_host)

    risk = policy.classify(name, args, args.get('intent', 'safe'), base_risk=tool.risk_hint)
    run.emit('tool_call', call_id=call['id'], tool=name, args=_safe_args(args),
             risk=risk, host=eff_name)

    command = args.get('command', '')

    if run.unattended:
        # scheduled run, no human: pre-approved envelope decides run vs defer
        decision = policy.unattended_decision(risk, run.job_ceiling, run.job_allow, command)
        if decision == 'defer':
            run.deferred_count += 1
            run.audit(f'tool:{name}', command, decision='deferred', host_id=eff_id)
            if run.on_defer:
                try:
                    run.on_defer(run.job_id, eff_id, name, _safe_args(args), command, risk)
                except Exception:  # noqa: BLE001 — the defer is already recorded
                    log.exception('defer callback failed for job %s', run.job_id)
            run.emit('deferred', call_id=call['id'], tool=name, command=command, risk=risk)
            run.emit('tool_result', call_id=call['id'], ok=False, exit_code=None, error='deferred')
            return {'ok': False, 'error':
                    'This action is outside the job\'s pre-approved envelope and was '
                    'deferred for human approval. Do not retry it; continue with other steps.'}
        run.audit(f'tool:{name}', command or name, decision='auto', host_id=eff_id)
    else:
        # The operator may EDIT the command in the approval card, so re-classify
        # what they actually approved: an edit from `ls` to `rm -rf /` must not
        # execute under the original card's risk level. A higher-risk edit that
        # still needs approval re-prompts (bounded, so a pathological edit loop
        # can't spin forever).
        for _ in range(3):
            gate = policy.needs_confirmation(risk, eff_autonomy) and not run.auto_approve
            if gate and policy.envelope_covers(run.envelope, risk, command,
                                               host_key=eff_name or eff_id):
                # the human approved a plan that already covers this
                gate = False
                run.emit('envelope_run', call_id=call['id'], risk=risk,
                         ceiling=run.envelope.get('ceiling'))
                run.audit(f'tool:{name}', command or json.dumps(_safe_args(args)),
                          decision='envelope', host_id=eff_id)
                break
            if not gate:
                run.audit(f'tool:{name}', command or json.dumps(_safe_args(args)),
                          decision='auto', host_id=eff_id)
                break
            gdecision, edited = _await_confirmation(run, call, args, risk, eff_name)
            if gdecision in ('deny', None):
                run.audit(f'tool:{name}', command, decision='denied', host_id=eff_id)
                run.emit('tool_result', call_id=call['id'], ok=False, exit_code=None,
                         error='denied by user')
                return {'ok': False, 'error': 'The user denied this action.'}
            if edited != command:
                command = edited
                args = dict(args, command=command)
                new_risk = policy.classify(name, args, args.get('intent', 'safe'),
                                           base_risk=tool.risk_hint)
                if new_risk != risk:
                    run.emit('tool_call', call_id=call['id'], tool=name,
                             args=_safe_args(args), risk=new_risk, host=eff_name)
                    risk = new_risk
                    if policy.needs_confirmation(risk, eff_autonomy) and not run.auto_approve:
                        continue  # the edit raised the risk — approve the real thing
            else:
                args = dict(args, command=command)
            run.audit(f'tool:{name}', command, decision='approved', host_id=eff_id)
            break
        else:
            run.emit('tool_result', call_id=call['id'], ok=False, exit_code=None,
                     error='too many command edits')
            return {'ok': False, 'error': 'Too many re-approvals; action abandoned.'}

    ctx = toolkit.ToolContext(
        host=eff_host, secrets=eff_secrets, user=run.user,
        conversation_id=run.conversation['id'],
        on_output=lambda chunk: run.emit('tool_output', call_id=call['id'], chunk=chunk),
        audit=run.audit)
    try:
        result = tool.run(ctx, args)
    except Exception as e:  # noqa: BLE001
        result = {'ok': False, 'error': str(e)}
    # redact secrets from the stored / LLM-bound copy (live stream stays real)
    result = scrub.scrub_result(result)
    # journal risky/critical commands (non-reversible note) for the Changes panel
    if name == 'ssh_exec' and risk in ('risky', 'critical') and eff_host and result.get('ok'):
        try:
            import changes
            changes.record_command(eff_id, run.user, run.conversation['id'],
                                   args.get('command', ''), risk)
        except Exception:  # noqa: BLE001
            pass
    run.emit('tool_result', call_id=call['id'], ok=result.get('ok', False),
             exit_code=result.get('exit_code'), error=result.get('error', ''))
    return result


def _propose_plan(run, call, args, eff_host):
    """Put a plan in front of the human once; on approval it becomes the run's
    envelope and the per-step gate stops interrupting inside it."""
    ceiling = policy.clamp_ceiling(args.get('ceiling', 'caution'))
    steps = [str(s) for s in (args.get('steps') or [])][:40]
    hosts = [str(h) for h in (args.get('hosts') or []) if str(h).strip()]
    if not hosts:
        hosts = [(eff_host or {}).get('name') or (eff_host or {}).get('id')] if eff_host else []
    hosts = [h for h in hosts if h]
    allow = [str(a) for a in (args.get('allow') or []) if str(a).strip()][:20]
    plan = {'summary': args.get('summary', ''), 'steps': steps, 'ceiling': ceiling,
            'allow': allow, 'hosts': hosts, 'risk_note': args.get('risk_note', '')}

    if run.unattended:
        # a scheduled job has no human to approve a plan; its envelope was
        # pre-authorized at creation time and is the only authority that counts
        return {'ok': True, 'approved': False, 'note':
                'No human is present (scheduled job) — the job\'s pre-approved envelope '
                f'(ceiling {run.job_ceiling}) already governs this run. Proceed within it; '
                'anything outside is deferred for approval.'}

    # register BEFORE emitting: the decision can come back faster than this
    # thread resumes, and an early answer must not land on a missing entry
    ev = threading.Event()
    with run.pending_lock:
        run.pending[call['id']] = {'event': ev, 'decision': None, 'command': ''}
    run.emit('plan_request', call_id=call['id'], **plan)
    answered = ev.wait(timeout=CONFIRM_TIMEOUT)
    with run.pending_lock:
        p = run.pending.pop(call['id'], {})
    decision = p.get('decision') or 'deny'

    if not answered:
        run.emit('error', message=(
            f'No decision on the plan within {CONFIRM_TIMEOUT // 60} minutes — treating as declined.'))
    if decision == 'deny':
        run.audit('plan', plan['summary'][:500], decision='denied',
                  host_id=(eff_host or {}).get('id', ''))
        run.emit('plan_result', call_id=call['id'], approved=False)
        return {'ok': True, 'approved': False, 'note':
                'The user declined this plan. Do NOT start the work — ask them what they '
                'would prefer, or propose a smaller plan.'}

    run.envelope = plan
    run.audit('plan', f"{plan['summary'][:400]} [ceiling={ceiling}"
                      f"{', allow=' + '; '.join(allow) if allow else ''}]",
              decision='approved', host_id=(eff_host or {}).get('id', ''))
    log.info('plan approved run=%s ceiling=%s hosts=%s steps=%d',
             run.id, ceiling, ','.join(hosts) or '-', len(steps))
    run.emit('plan_result', call_id=call['id'], approved=True, ceiling=ceiling)
    return {'ok': True, 'approved': True, 'ceiling': ceiling, 'note':
            f'Plan approved. Actions up to "{ceiling}" now run without asking again'
            + (f' on {", ".join(hosts)}' if hosts else '')
            + '. Critical actions, and anything above the ceiling, will still stop for '
              'approval — so stay inside what you described. Get on with it.'}


def _await_confirmation(run, call, args, risk, host_name=''):
    ev = threading.Event()
    with run.pending_lock:
        run.pending[call['id']] = {'event': ev, 'decision': None,
                                   'command': args.get('command', '')}
    run.emit('confirm_request', call_id=call['id'], tool=call['name'],
             command=args.get('command', ''), sudo=bool(args.get('sudo')), risk=risk,
             host=host_name, explanation=_explain(call, args, risk))
    answered = ev.wait(timeout=CONFIRM_TIMEOUT)
    with run.pending_lock:
        p = run.pending.pop(call['id'], {})
    if not answered:
        # nobody answered in time — treat as denied, but say so distinctly:
        # a silent timeout that looks like a deny is confusing after the fact
        run.emit('error', message=(
            f'No decision within {CONFIRM_TIMEOUT // 60} minutes — treating as denied.'))
    return p.get('decision') or 'deny', p.get('command', args.get('command', ''))


def _explain(call, args, risk):
    if call['name'] == 'ssh_exec':
        verb = {'critical': 'This is a HIGH-RISK action', 'risky': 'This may cause downtime',
                'caution': 'This will change the system'}.get(risk, 'This runs a command')
        sudo = ' (as root)' if args.get('sudo') else ''
        return f'{verb}{sudo}. Review the command before approving.'
    return 'Review before approving.'


def _safe_args(args):
    """Args for the UI/audit — ssh_exec is fine to show; strip nothing sensitive
    here because secrets never live in tool args (they come from the vault)."""
    return {k: v for k, v in args.items() if k != 'intent'}


def _result_summary(call, result):
    if call['name'] == 'ssh_exec':
        code = result.get('exit_code')
        out = (result.get('output') or '')[:1500]
        return f'$ {call["arguments"].get("command", "")}\n[exit {code}]\n{out}'
    return json.dumps(result)[:1500]
