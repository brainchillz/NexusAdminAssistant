"""Agent-facing skill tools: skill_save + skill_search.

The agent captures a reusable procedure once it has one working, and looks up its
playbooks before tackling a familiar task. Saved skills are DRAFTS until the user
approves them in the Skills UI.
"""
import skills as skillstore


def _save_run(ctx, args):
    name = (args.get('name') or '').strip()
    if not name:
        return {'ok': False, 'error': 'name required (short kebab-case id, e.g. install-lamp)'}
    body = (args.get('body') or '').strip()
    warnings = skillstore.lint(body)
    try:
        sid = skillstore.save(name, description=(args.get('description') or '').strip(),
                              body=body, params=args.get('params') or {})
    except ValueError as e:
        return {'ok': False, 'error': str(e)}
    if ctx.audit:
        ctx.audit('skill:save', name, 'auto')
    out = {'ok': True, 'id': sid, 'name': name,
           'note': 'Saved as a draft. The user reviews and approves it in the Skills panel.'}
    if warnings:
        # Surface blocking-step warnings back to the agent so it revises the draft
        # NOW rather than leaving a playbook that will hang when next executed.
        out['lint_warnings'] = warnings
        out['note'] = ('Saved as a draft, but it has steps that would BLOCK an '
                       'unattended run — fix these and call skill_save again with '
                       'the same name to overwrite: ' + '; '.join(warnings))
    return out


def _search_run(ctx, args):
    query = (args.get('query') or '').strip()
    if not query:
        return {'ok': False, 'error': 'query required'}
    hits = skillstore.search(query, limit=int(args.get('limit', 6)))
    return {'ok': True, 'results': [
        {'name': s['name'], 'description': s['description'], 'approved': s['approved'],
         'params': s['params'], 'body': s['body']} for s in hits]}


def register_all(register, Tool):
    register(Tool(
        name='skill_save', needs_host=False, risk_hint='safe',
        description='Save a reusable procedure (playbook) so you can repeat it reliably '
                    'later — e.g. "install-lamp". A skill is REPLAYED unattended by you '
                    'over ssh_exec — there is no human at a keyboard. Rules: capture only '
                    'the commands you ACTUALLY RAN in this task that SUCCEEDED (exit 0) — '
                    'not an idealized tutorial. Every step must be non-interactive and '
                    'terminate: NO foreground servers/daemons (define a systemd unit and '
                    'start it instead), NO "press Ctrl+C" / manual waits, NO tail -f / '
                    'journalctl -f / watch, NO interactive installers (mysql_secure_'
                    'installation). Use `-y` + `DEBIAN_FRONTEND=noninteractive` for apt, '
                    '`--no-pager` for systemctl/journalctl, and end with a polling check. '
                    'Make it idempotent (safe to re-run). Give a short kebab-case name, a '
                    'one-line description, the body, and any params. Saved as a draft for '
                    'the user to approve; if it reports lint_warnings, fix them and save again.',
        parameters={'type': 'object', 'properties': {
            'name': {'type': 'string', 'description': 'short kebab-case id'},
            'description': {'type': 'string', 'description': 'one line'},
            'body': {'type': 'string', 'description': 'the step-by-step procedure'},
            'params': {'type': 'object', 'description': 'named parameters the playbook needs'}},
            'required': ['name', 'body']},
        run=_save_run))
    register(Tool(
        name='skill_search', needs_host=False, risk_hint='safe',
        description='Search your saved playbooks and read their full steps before doing a '
                    'familiar task, so you follow a known-good procedure instead of improvising.',
        parameters={'type': 'object', 'properties': {
            'query': {'type': 'string'}, 'limit': {'type': 'integer'}},
            'required': ['query']},
        run=_search_run))
