"""Regression: PTY-driven command output must be stripped of ANSI/control codes.

Running over a pseudo-terminal makes jq/ls/grep emit color escape sequences.
The chat tool-card renders plain text (not a terminal), so the raw ESC bytes
showed as tofu boxes, and the codes also polluted the LLM context. `strip_terminal`
removes them. Sample below is the shape of real `jq` colorized JSON output.
"""
from agent.tools.ssh import strip_terminal

E = '\x1b'  # ESC


def test_strips_jq_color_codes_keeps_json():
    # {"id":132,"channel":"STABLE"} as jq -C would emit it over a PTY
    raw = (f'{E}[1;39m{{\r\n'
           f'  {E}[0m{E}[1;34m"id"{E}[0m{E}[1;39m: {E}[0;39m132{E}[0m{E}[1;39m,\r\n'
           f'  {E}[0m{E}[1;34m"channel"{E}[0m{E}[1;39m: {E}[0;32m"STABLE"{E}[0m{E}[1;39m\r\n'
           f'{E}[1;39m}}{E}[0m\r\n')
    out = strip_terminal(raw)
    assert E not in out                 # no raw ESC bytes (the tofu box)
    assert '[1;34m' not in out          # no leftover code text
    assert '[0m' not in out
    assert '"channel": "STABLE"' in out  # payload intact
    assert '"id": 132' in out
    assert '\r' not in out               # CRLF normalized to LF


def test_preserves_plain_text_and_tabs_and_newlines():
    s = 'total 4\n-rw-r--r-- 1 root root 0 file\tname\n'
    assert strip_terminal(s) == s


def test_strips_osc_title_and_bel():
    raw = f'{E}]0;my terminal title{chr(7)}hello world'
    assert strip_terminal(raw) == 'hello world'


def test_strips_cursor_moves_and_clear():
    raw = f'progress{E}[2K{E}[1Gdone'
    assert strip_terminal(raw) == 'progressdone'
