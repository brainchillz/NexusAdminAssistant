"""Singleton app settings (row id=1). Holds the LLM endpoint config.

The LLM api_key is stored Fernet-encrypted under `llm.api_key_enc`; `public()`
strips it so it never reaches the browser.
"""
import json

from store import crypto, db


def _load():
    row = db.query_one('SELECT data_json FROM settings WHERE id=1')
    return json.loads(row['data_json']) if row and row['data_json'] else {}


def _save(data):
    db.execute('UPDATE settings SET data_json=? WHERE id=1', (json.dumps(data),))


def get_llm():
    """Full LLM config incl. decrypted api_key (server-side use only)."""
    llm = _load().get('llm', {})
    return {
        'provider': llm.get('provider', 'openai_compat'),
        'base_url': llm.get('base_url', ''),
        'model': llm.get('model', ''),
        'api_key': crypto.decrypt(llm.get('api_key_enc', '')) or '',
        'temperature': llm.get('temperature', 0.2),
        'max_tokens': llm.get('max_tokens', 2048),
        'timeout': llm.get('timeout', 120),
    }


def set_llm(cfg, keep_key_if_blank=True):
    data = _load()
    cur = data.get('llm', {})
    new = {
        'provider': cfg.get('provider', 'openai_compat'),
        'base_url': (cfg.get('base_url') or '').rstrip('/'),
        'model': cfg.get('model', ''),
        'temperature': float(cfg.get('temperature', 0.2)),
        'max_tokens': int(cfg.get('max_tokens', 2048)),
        'timeout': int(cfg.get('timeout', 120)),
    }
    api_key = cfg.get('api_key')
    if api_key:
        new['api_key_enc'] = crypto.encrypt(api_key)
    elif keep_key_if_blank:
        new['api_key_enc'] = cur.get('api_key_enc', '')
    else:
        new['api_key_enc'] = ''
    data['llm'] = new
    _save(data)


def public_llm():
    """LLM config for the browser — api_key replaced by a has_key flag."""
    llm = _load().get('llm', {})
    return {
        'provider': llm.get('provider', 'openai_compat'),
        'base_url': llm.get('base_url', ''),
        'model': llm.get('model', ''),
        'has_key': bool(llm.get('api_key_enc')),
        'temperature': llm.get('temperature', 0.2),
        'max_tokens': llm.get('max_tokens', 2048),
        'timeout': llm.get('timeout', 120),
    }


# ─── web search (SearXNG / OpenAI-compat-agnostic provider) ────────────
def get_search():
    s = _load().get('search', {})
    return {'provider': s.get('provider', 'searxng'),
            'base_url': s.get('base_url', ''),
            'api_key': crypto.decrypt(s.get('api_key_enc', '')) or ''}


def set_search(cfg, keep_key_if_blank=True):
    data = _load()
    cur = data.get('search', {})
    new = {'provider': cfg.get('provider', 'searxng'),
           'base_url': (cfg.get('base_url') or '').rstrip('/')}
    key = cfg.get('api_key')
    if key:
        new['api_key_enc'] = crypto.encrypt(key)
    elif keep_key_if_blank:
        new['api_key_enc'] = cur.get('api_key_enc', '')
    else:
        new['api_key_enc'] = ''
    data['search'] = new
    _save(data)


def public_search():
    s = _load().get('search', {})
    return {'provider': s.get('provider', 'searxng'),
            'base_url': s.get('base_url', ''), 'has_key': bool(s.get('api_key_enc'))}


# ─── notifications (monitoring alerts + job reports) ──────────────────
def get_notify():
    return {'url': _load().get('notify', {}).get('url', '')}


def set_notify(cfg):
    data = _load()
    data['notify'] = {'url': (cfg.get('url') or '').strip()}
    _save(data)


def public_notify():
    return get_notify()


# ─── Telegram bridge ──────────────────────────────────────────────────
def get_telegram():
    t = _load().get('telegram', {})
    return {'enabled': bool(t.get('enabled')), 'token': crypto.decrypt(t.get('token_enc', '')) or '',
            'whitelist': t.get('whitelist', []), 'act_as': t.get('act_as', '')}


def set_telegram(cfg, keep_token_if_blank=True):
    data = _load()
    cur = data.get('telegram', {})
    new = {'enabled': bool(cfg.get('enabled')),
           'whitelist': cfg.get('whitelist', cur.get('whitelist', [])),
           'act_as': cfg.get('act_as', cur.get('act_as', ''))}
    tok = cfg.get('token')
    if tok:
        new['token_enc'] = crypto.encrypt(tok.strip())
    elif keep_token_if_blank:
        new['token_enc'] = cur.get('token_enc', '')
    else:
        new['token_enc'] = ''
    data['telegram'] = new
    _save(data)


def public_telegram():
    t = _load().get('telegram', {})
    return {'enabled': bool(t.get('enabled')), 'has_token': bool(t.get('token_enc')),
            'whitelist': t.get('whitelist', []), 'act_as': t.get('act_as', '')}
