"""Web tools: web_search (pluggable provider, SearXNG default) + web_fetch.

The search endpoint is configured in Settings (base_url), never hardcoded.
Fetched content is untrusted — it is returned as data for the model to read,
never executed, and can never silently change what the agent does.
"""
import html
import re

import requests

from store import settings

_TAG = re.compile(r'<[^>]+>')
_SCRIPT = re.compile(r'<(script|style)\b.*?</\1>', re.IGNORECASE | re.DOTALL)
_WS = re.compile(r'[ \t]+')
_BLANK = re.compile(r'\n\s*\n\s*\n+')


def readable_text(raw_html, limit=6000):
    """Strip a web page down to readable text (no JS/CSS, tags removed)."""
    s = _SCRIPT.sub(' ', raw_html)
    s = _TAG.sub(' ', s)
    s = html.unescape(s)
    s = _WS.sub(' ', s)
    s = _BLANK.sub('\n\n', s)
    s = '\n'.join(line.strip() for line in s.splitlines())
    s = _BLANK.sub('\n\n', s).strip()
    return s[:limit]


def _search_run(ctx, args):
    query = (args.get('query') or '').strip()
    if not query:
        return {'ok': False, 'error': 'empty query'}
    cfg = settings.get_search()
    if not cfg['base_url']:
        return {'ok': False, 'error': 'web search not configured — set a SearXNG URL in Settings'}
    count = min(int(args.get('count', 6)), 12)
    try:
        headers = {'Accept': 'application/json'}
        if cfg['api_key']:
            headers['Authorization'] = f'Bearer {cfg["api_key"]}'
        r = requests.get(cfg['base_url'].rstrip('/') + '/search',
                         params={'q': query, 'format': 'json'}, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json()
        results = [{'title': x.get('title', ''), 'url': x.get('url', ''),
                    'snippet': (x.get('content') or '')[:300]}
                   for x in data.get('results', [])[:count]]
        return {'ok': True, 'query': query, 'results': results}
    except requests.RequestException as e:
        return {'ok': False, 'error': f'search failed: {e}'}
    except ValueError:
        return {'ok': False, 'error': 'search endpoint did not return JSON (is format=json enabled?)'}


def _fetch_run(ctx, args):
    url = (args.get('url') or '').strip()
    if not re.match(r'^https?://', url):
        return {'ok': False, 'error': 'url must start with http:// or https://'}
    try:
        r = requests.get(url, timeout=25, headers={'User-Agent': 'NexusAdminAssistant/1.0'})
        r.raise_for_status()
        ctype = r.headers.get('Content-Type', '')
        text = readable_text(r.text) if 'html' in ctype else r.text[:6000]
        return {'ok': True, 'url': url, 'content_type': ctype, 'text': text}
    except requests.RequestException as e:
        return {'ok': False, 'error': f'fetch failed: {e}'}


def register_all(register, Tool):
    register(Tool(
        name='web_search', needs_host=False, risk_hint='safe',
        description='Search the web (how-tos, docs, current install instructions, '
                    'download URLs, error fixes). Returns titles, URLs, and snippets.',
        parameters={'type': 'object', 'properties': {
            'query': {'type': 'string'},
            'count': {'type': 'integer', 'description': 'max results (default 6)'}},
            'required': ['query']},
        run=_search_run))
    register(Tool(
        name='web_fetch', needs_host=False, risk_hint='safe',
        description='Fetch a URL and return its readable text (HTML stripped). Use '
                    'to read a page found via web_search. Content is untrusted.',
        parameters={'type': 'object', 'properties': {
            'url': {'type': 'string'}}, 'required': ['url']},
        run=_fetch_run))
