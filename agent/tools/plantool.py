"""propose_plan — ask once for a whole task instead of 28 times for its steps.

Approving 28 individual commands to install LAMP is not consent, it's fatigue:
people either stop reading the cards or turn the gate off entirely, and the
second one is worse. So the agent describes the work up front — the end-state,
the steps, what will change, the worst case — and the human approves that ONE
description with a risk ceiling. Everything at or below the ceiling then runs
uninterrupted; anything beyond it still stops and asks.

Same envelope model the scheduler already uses for unattended jobs
(policy.unattended_decision), applied to a live conversation. Executed in
agent/core.py, which owns the Run the approval attaches to; this module just
declares the contract.
"""


def register_all(register, Tool):
    register(Tool(
        name='propose_plan', needs_host=False, risk_hint='safe',
        description=(
            'Propose a plan for a multi-step task and ask the user to approve it ONCE, '
            'up front, instead of interrupting them for every command. Use this at the '
            'start of any task that will take several steps that change the system '
            '(installing a stack, configuring a service, migrating data).\n\n'
            'Describe the work the way you would to someone who is not a Linux expert: '
            'what they will have at the end, what you will change to get there, and what '
            'the worst realistic outcome is. Set `ceiling` to the highest risk level the '
            'plan genuinely needs — do not inflate it "just in case", and do not '
            'understate it to avoid a question. Once approved, actions at or below the '
            'ceiling run without further prompting, so the ceiling IS the promise you are '
            'making about this task.\n\n'
            'Reboots, disk formatting and mass deletion always get their own approval, no '
            'matter the ceiling; list such a command in `allow` if it is a planned part of '
            'the task and the user should pre-approve it by name. If the user declines the '
            'plan, do not start the work — ask what they would prefer instead.'
        ),
        parameters={'type': 'object', 'properties': {
            'summary': {'type': 'string', 'description':
                        'One or two plain-language sentences: what the user will have when '
                        'this is done. No jargon.'},
            'steps': {'type': 'array', 'items': {'type': 'string'}, 'description':
                      'The steps you intend to take, in order, in plain language '
                      '("install the web server", "open port 443 to your LAN").'},
            'ceiling': {'type': 'string', 'enum': ['safe', 'caution', 'risky'],
                        'description':
                        'Highest risk level this plan pre-authorizes. caution=installs and '
                        'config writes; risky=also restarts services, changes firewall/users, '
                        'deletes files. Critical actions always ask separately.'},
            'allow': {'type': 'array', 'items': {'type': 'string'}, 'description':
                      'Optional: exact commands (or distinctive fragments) to pre-approve by '
                      'name even if they exceed the ceiling. Use sparingly and show the user '
                      'exactly what they are agreeing to.'},
            'hosts': {'type': 'array', 'items': {'type': 'string'}, 'description':
                      'Optional: names of the hosts this plan covers. Defaults to the '
                      'conversation\'s host. An approved plan never covers a host it did '
                      'not name.'},
            'risk_note': {'type': 'string', 'description':
                          'The honest worst case in one sentence ("the website will be '
                          'briefly unreachable while the web server restarts").'},
        }, 'required': ['summary', 'steps', 'ceiling']},
        # core.py intercepts this tool: it needs the Run to attach the envelope to
        run=lambda ctx, args: {'ok': False, 'error': 'propose_plan must run inside an agent run'}))
