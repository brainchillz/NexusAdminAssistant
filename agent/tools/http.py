"""http_request tool — arbitrary HTTP/HTTPS/REST calls (device APIs, registries,
health checks). GET/HEAD are safe; other methods are caution (may change remote
state) and the model should declare intent accordingly.
"""

import requests

SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}


def _run(ctx, args):
    method = (args.get('method') or 'GET').upper()
    url = (args.get('url') or '').strip()
    if not url.startswith(('http://', 'https://')):
        return {'ok': False, 'error': 'url must start with http:// or https://'}
    headers = args.get('headers') or {}
    body = args.get('body')
    try:
        kwargs = {'headers': headers, 'verify': args.get('verify_tls', True)}
        if body is not None:
            if isinstance(body, (dict, list)):
                kwargs['json'] = body
            else:
                kwargs['data'] = body
        # timeout passed explicitly: a hung request would wedge an agent thread
        # for good (gunicorn runs with --timeout 0 for SSE, so nothing reaps it)
        r = requests.request(method, url, timeout=30, **kwargs)
        text = r.text
        return {'ok': r.ok, 'status': r.status_code,
                'headers': dict(list(r.headers.items())[:20]),
                'body': text[:6000]}
    except requests.RequestException as e:
        return {'ok': False, 'error': f'request failed: {e}'}


def register_all(register, Tool):
    register(Tool(
        name='http_request', needs_host=False, risk_hint='caution',
        description='Make an HTTP/HTTPS request to any URL or API (methods, headers, '
                    'JSON/text body). Use for device APIs, package registries, health '
                    'checks. GET is read-only; other methods may change remote state.',
        parameters={'type': 'object', 'properties': {
            'method': {'type': 'string', 'enum': ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']},
            'url': {'type': 'string'},
            'headers': {'type': 'object', 'description': 'header name -> value'},
            'body': {'description': 'request body (object -> JSON, string -> raw)'},
            'verify_tls': {'type': 'boolean', 'description': 'verify TLS cert (default true)'},
            'intent': {'type': 'string', 'enum': ['safe', 'caution', 'risky', 'critical']}},
            'required': ['url']},
        run=_run))
