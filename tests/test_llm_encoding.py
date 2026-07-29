"""Regression: streamed LLM output must be decoded as UTF-8.

`requests` defaults to ISO-8859-1 when the server's Content-Type carries no
charset — which is exactly what an SSE `text/event-stream` from llama.cpp looks
like. Left alone, `iter_lines(decode_unicode=True)` then mojibakes emoji/arrows
("→" -> "â†'", "⚠️" -> "â\xa0ï¸"). `_openai_stream`/`_anthropic_stream` pin the
encoding to utf-8; this proves the multibyte characters round-trip.
"""
import io
import json

from requests.models import Response
from requests.utils import get_encoding_from_headers
from urllib3 import HTTPResponse

from agent import llm


def _fake_sse(deltas, content_type='text/event-stream'):
    """A requests.Response streaming UTF-8 SSE bytes, mimicking llama.cpp."""
    lines = []
    for d in deltas:
        chunk = {'choices': [{'delta': d}]}
        lines.append('data: ' + json.dumps(chunk, ensure_ascii=False))
    body = ('\n\n'.join(lines) + '\n\ndata: [DONE]\n\n').encode('utf-8')
    r = Response()
    r.status_code = 200
    r.headers['Content-Type'] = content_type  # no charset -> requests guesses latin-1
    # reproduce exactly what requests does on a real response: derive .encoding
    # from the headers (text/event-stream -> ISO-8859-1), so the un-fixed path
    # mojibakes rather than merely erroring on a None encoding.
    r.encoding = get_encoding_from_headers(r.headers)
    r.raw = HTTPResponse(body=io.BytesIO(body), preload_content=False,
                         headers={'Content-Type': content_type})
    return r


def test_stream_preserves_utf8_emoji_and_arrows(monkeypatch):
    text = 'Apache2 is down → the web server is not serving ⚠️'
    monkeypatch.setattr(llm.requests, 'post',
                        lambda *a, **k: _fake_sse([{'content': text}]))
    out = llm._openai_stream('http://x/v1/chat/completions', {}, {}, None, 5)
    assert out['content'] == text
    assert 'â' not in out['content']  # no mojibake


def test_stream_on_text_callback_gets_clean_utf8(monkeypatch):
    parts = ['Minecraft is the biggest ', 'memory consumer → 1.3 GB ⚠️']
    monkeypatch.setattr(llm.requests, 'post',
                        lambda *a, **k: _fake_sse([{'content': p} for p in parts]))
    seen = []
    out = llm._openai_stream('http://x/v1/chat/completions', {}, {}, seen.append, 5)
    assert ''.join(seen) == ''.join(parts)
    assert out['content'] == ''.join(parts)
    assert '→' in out['content'] and '⚠️' in out['content']
