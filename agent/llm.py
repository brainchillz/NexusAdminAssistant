"""Provider-agnostic LLM client.

One `chat()` entry point the agent loop calls. Two backends behind it:
  - openai_compat: works with Ollama, vLLM, LM Studio, llama.cpp server, OpenAI —
    POST {base_url}/chat/completions.
  - anthropic: POST https://api.anthropic.com/v1/messages (Claude).
Both normalize to the same result shape so the loop is provider-neutral:
  {content: str, tool_calls: [{id, name, arguments: dict}], finish_reason: str}
Streaming text is delivered via on_text(chunk); tool calls are assembled and
returned at the end.
"""
import json

import requests

from store import settings

ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages'
ANTHROPIC_VERSION = '2023-06-01'
OPENAI_COMPAT_PROVIDERS = {'openai_compat', 'openai', 'ollama', 'vllm', 'lmstudio', 'llamacpp'}


class LLMError(Exception):
    pass


def _cfg():
    c = settings.get_llm()
    if not c.get('base_url') and c.get('provider') != 'anthropic':
        raise LLMError('LLM endpoint not configured — set it in Settings')
    if not c.get('model'):
        raise LLMError('LLM model not configured — set it in Settings')
    return c


def chat(messages, tools=None, on_text=None, stream=True):
    c = _cfg()
    if c['provider'] == 'anthropic':
        return _anthropic_chat(c, messages, tools, on_text, stream)
    return _openai_chat(c, messages, tools, on_text, stream)


def test_connection():
    """Round-trip a tiny completion; return {ok, detail}."""
    try:
        res = chat([{'role': 'user', 'content': 'Reply with the single word: ready'}],
                   tools=None, on_text=None, stream=False)
        txt = (res.get('content') or '').strip()
        return {'ok': True, 'detail': txt[:120] or '(empty reply)'}
    except Exception as e:  # noqa: BLE001
        return {'ok': False, 'detail': str(e)}


# ─── OpenAI-compatible ────────────────────────────────────────────────
def _openai_messages(messages):
    """Convert internal messages → OpenAI wire format. Internal assistant
    tool_calls are {id,name,arguments(dict)}; OpenAI needs
    {id,type:'function',function:{name,arguments:JSON-string}}."""
    out = []
    for m in messages:
        if m['role'] == 'assistant' and m.get('tool_calls'):
            out.append({
                'role': 'assistant', 'content': m.get('content') or '',
                'tool_calls': [{
                    'id': tc['id'], 'type': 'function',
                    'function': {'name': tc['name'],
                                 'arguments': json.dumps(tc['arguments'])},
                } for tc in m['tool_calls']],
            })
        elif m['role'] == 'tool':
            out.append({'role': 'tool', 'tool_call_id': m['tool_call_id'],
                        'content': m['content']})
        else:
            out.append({'role': m['role'], 'content': m.get('content') or ''})
    return out


def _openai_chat(c, messages, tools, on_text, stream):
    url = c['base_url'].rstrip('/') + '/chat/completions'
    headers = {'Content-Type': 'application/json'}
    if c.get('api_key'):
        headers['Authorization'] = f'Bearer {c["api_key"]}'
    payload = {
        'model': c['model'], 'messages': _openai_messages(messages),
        'temperature': c['temperature'], 'max_tokens': c['max_tokens'],
        'stream': stream,
    }
    if tools:
        payload['tools'] = [t.schema_openai() for t in tools]
    try:
        if not stream:
            r = requests.post(url, headers=headers, json=payload, timeout=c['timeout'])
            r.raise_for_status()
            msg = r.json()['choices'][0]['message']
            return _openai_normalize(msg, on_text)
        return _openai_stream(url, headers, payload, on_text, c['timeout'])
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else '?'
        body = e.response.text[:300] if e.response is not None else ''
        raise LLMError(f'LLM HTTP {code}: {body or e}')
    except requests.RequestException as e:
        raise LLMError(f'LLM request failed: {type(e).__name__}: {e}')


def _openai_normalize(msg, on_text):
    content = msg.get('content') or ''
    if content and on_text:
        on_text(content)
    tool_calls = []
    for tc in msg.get('tool_calls') or []:
        fn = tc.get('function', {})
        try:
            args = json.loads(fn.get('arguments') or '{}')
        except ValueError:
            args = {}
        tool_calls.append({'id': tc.get('id') or f'call_{len(tool_calls)}',
                           'name': fn.get('name'), 'arguments': args})
    return {'content': content, 'tool_calls': tool_calls,
            'finish_reason': 'tool_calls' if tool_calls else 'stop'}


def _openai_stream(url, headers, payload, on_text, timeout):
    content = ''
    tc_acc = {}  # index -> {id, name, args_str}
    with requests.post(url, headers=headers, json=payload, timeout=timeout, stream=True) as r:
        r.raise_for_status()
        # Force UTF-8: requests falls back to ISO-8859-1 when the server omits a
        # charset (llama.cpp does), which mojibakes emoji/arrows in the stream.
        r.encoding = 'utf-8'
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith('data:'):
                continue
            data = line[5:].strip()
            if data == '[DONE]':
                break
            try:
                delta = json.loads(data)['choices'][0]['delta']
            except (ValueError, KeyError, IndexError):
                continue
            if delta.get('content'):
                content += delta['content']
                if on_text:
                    on_text(delta['content'])
            for tc in delta.get('tool_calls') or []:
                idx = tc.get('index', 0)
                acc = tc_acc.setdefault(idx, {'id': None, 'name': None, 'args': ''})
                if tc.get('id'):
                    acc['id'] = tc['id']
                fn = tc.get('function', {})
                if fn.get('name'):
                    acc['name'] = fn['name']
                if fn.get('arguments'):
                    acc['args'] += fn['arguments']
    tool_calls = []
    for idx in sorted(tc_acc):
        acc = tc_acc[idx]
        try:
            args = json.loads(acc['args'] or '{}')
        except ValueError:
            args = {}
        tool_calls.append({'id': acc['id'] or f'call_{idx}', 'name': acc['name'], 'arguments': args})
    return {'content': content, 'tool_calls': tool_calls,
            'finish_reason': 'tool_calls' if tool_calls else 'stop'}


# ─── Anthropic (Claude) ───────────────────────────────────────────────
def _anthropic_chat(c, messages, tools, on_text, stream):
    if not c.get('api_key'):
        raise LLMError('Anthropic API key not set in Settings')
    headers = {
        'x-api-key': c['api_key'], 'anthropic-version': ANTHROPIC_VERSION,
        'Content-Type': 'application/json',
    }
    system, conv = _anthropic_messages(messages)
    payload = {
        'model': c['model'], 'max_tokens': c['max_tokens'],
        'temperature': c['temperature'], 'messages': conv, 'stream': stream,
    }
    if system:
        payload['system'] = system
    if tools:
        payload['tools'] = [t.schema_anthropic() for t in tools]
    try:
        if not stream:
            r = requests.post(ANTHROPIC_URL, headers=headers, json=payload, timeout=c['timeout'])
            r.raise_for_status()
            return _anthropic_normalize(r.json(), on_text)
        return _anthropic_stream(headers, payload, on_text, c['timeout'])
    except requests.HTTPError as e:
        body = e.response.text[:300] if e.response is not None else ''
        raise LLMError(f'Anthropic HTTP {e.response.status_code if e.response else "?"}: {body}')
    except requests.RequestException as e:
        raise LLMError(f'Anthropic request failed: {e}')


def _anthropic_messages(messages):
    """Convert internal messages → (system_str, anthropic messages list)."""
    system_parts, conv = [], []
    for m in messages:
        role = m['role']
        if role == 'system':
            system_parts.append(m['content'])
        elif role == 'tool':
            conv.append({'role': 'user', 'content': [{
                'type': 'tool_result', 'tool_use_id': m['tool_call_id'],
                'content': m['content']}]})
        elif role == 'assistant' and m.get('tool_calls'):
            blocks = []
            if m.get('content'):
                blocks.append({'type': 'text', 'text': m['content']})
            for tc in m['tool_calls']:
                blocks.append({'type': 'tool_use', 'id': tc['id'],
                               'name': tc['name'], 'input': tc['arguments']})
            conv.append({'role': 'assistant', 'content': blocks})
        else:
            conv.append({'role': role, 'content': m['content']})
    return '\n\n'.join(system_parts), conv


def _anthropic_normalize(data, on_text):
    content, tool_calls = '', []
    for block in data.get('content', []):
        if block['type'] == 'text':
            content += block['text']
            if on_text:
                on_text(block['text'])
        elif block['type'] == 'tool_use':
            tool_calls.append({'id': block['id'], 'name': block['name'],
                               'arguments': block.get('input', {})})
    return {'content': content, 'tool_calls': tool_calls,
            'finish_reason': data.get('stop_reason', 'stop')}


def _anthropic_stream(headers, payload, on_text, timeout):
    content, tool_calls = '', []
    cur_tool = None
    cur_json = ''
    with requests.post(ANTHROPIC_URL, headers=headers, json=payload, timeout=timeout, stream=True) as r:
        r.raise_for_status()
        r.encoding = 'utf-8'  # never let requests guess ISO-8859-1 (see _openai_stream)
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith('data:'):
                continue
            try:
                ev = json.loads(line[5:].strip())
            except ValueError:
                continue
            t = ev.get('type')
            if t == 'content_block_start':
                blk = ev.get('content_block', {})
                if blk.get('type') == 'tool_use':
                    cur_tool = {'id': blk['id'], 'name': blk['name'], 'arguments': {}}
                    cur_json = ''
            elif t == 'content_block_delta':
                d = ev.get('delta', {})
                if d.get('type') == 'text_delta':
                    content += d['text']
                    if on_text:
                        on_text(d['text'])
                elif d.get('type') == 'input_json_delta':
                    cur_json += d.get('partial_json', '')
            elif t == 'content_block_stop':
                if cur_tool is not None:
                    try:
                        cur_tool['arguments'] = json.loads(cur_json or '{}')
                    except ValueError:
                        cur_tool['arguments'] = {}
                    tool_calls.append(cur_tool)
                    cur_tool = None
    return {'content': content, 'tool_calls': tool_calls,
            'finish_reason': 'tool_calls' if tool_calls else 'stop'}
