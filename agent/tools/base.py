"""Tool contract + execution context.

A Tool self-describes: name, human summary, JSON-schema parameters (for the LLM's
tool-calling), and a risk hint. run(ctx, args) does the work and returns a result
dict. New tools = a new module + one register() call (mirrors NexusController's
adapter registry).
"""
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class ToolContext:
    """Everything a tool needs at execution time — injected by the agent loop."""
    host: Optional[dict] = None          # raw host record (may hold enc secrets)
    secrets: Optional[dict] = None       # decrypted secrets (never serialized)
    on_output: Optional[Callable] = None # stream a chunk of live output to the UI
    audit: Optional[Callable] = None     # audit(action, detail, decision)
    user: Optional[dict] = None          # the acting user record (for scope/ownership)
    conversation_id: Optional[str] = None  # for the change journal


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict                     # JSON Schema for the arguments object
    run: Callable                        # (ctx: ToolContext, args: dict) -> dict
    risk_hint: str = 'safe'
    needs_host: bool = True

    def schema_openai(self):
        return {'type': 'function', 'function': {
            'name': self.name, 'description': self.description,
            'parameters': self.parameters}}

    def schema_anthropic(self):
        return {'name': self.name, 'description': self.description,
                'input_schema': self.parameters}


_REGISTRY = {}


def register(tool: Tool):
    _REGISTRY[tool.name] = tool
    return tool


def get(name):
    return _REGISTRY.get(name)


def all_tools():
    return list(_REGISTRY.values())
