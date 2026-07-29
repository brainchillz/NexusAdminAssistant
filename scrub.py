"""Redact secrets from tool output before it is stored or sent to the LLM.

Command output can contain passwords, keys, and tokens (e.g. `cat wp-config.php`,
`mysql -e "CREATE USER ... IDENTIFIED BY '...'"`). That text otherwise flows into
the LLM context (and, for hosted APIs, a third party), the conversation history,
memory, and the audit log. This scrubs the common, high-value cases before any of
that. It is best-effort: a secret echoed with no surrounding label can't be
detected. Live output streamed to the operator's own terminal is NOT scrubbed —
only the stored / LLM-bound copy.

Pure + unit-tested (mirrors policy.py).
"""
import re

R = '[REDACTED]'

_RULES = [
    # PEM private keys (any type) — whole block
    (re.compile(r'-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----', re.DOTALL),
     '[REDACTED PRIVATE KEY]'),
    # SQL: IDENTIFIED BY 'pw'  /  "pw"
    (re.compile(r"(IDENTIFIED\s+BY\s+)(['\"]).*?\2", re.IGNORECASE), r"\1'" + R + "'"),
    # named secret fields in configs/env/yaml/json: password=..., api_key: "...", token=...
    (re.compile(r'(?i)((?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)'
                r'\s*[:=]\s*)(["\']?)([^\s"\'#,}]+)(["\']?)'), r'\1\2' + R + r'\4'),
    # quoted-key, quoted-value style: define('DB_PASSWORD', 'pw'), "api_key" => "pw"
    (re.compile(r'(?i)(["\'][A-Za-z0-9_]*(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|token)'
                r'[A-Za-z0-9_]*["\']\s*(?:,|=>)\s*)(["\'])([^"\']*)(["\'])'), r'\1\2' + R + r'\4'),
    # HTTP auth headers
    (re.compile(r'(?i)(Authorization:\s*(?:Bearer|Basic|token)\s+)\S+'), r'\1' + R),
    (re.compile(r'(?i)(\bBearer\s+)[A-Za-z0-9._\-]{12,}'), r'\1' + R),
    # known token shapes (GitHub, OpenAI, Slack, AWS access key id)
    (re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}'
                r'|AKIA[0-9A-Z]{16})\b'), R),
    # mysql/mariadb command-line password:  mysql ... -p'pw'  /  -pSECRET
    (re.compile(r'(?i)((?:mysql|mysqldump|mariadb)\b[^\n]*?\s-p)(["\']?)([^\s"\']+)(["\']?)'),
     r'\1\2' + R + r'\4'),
    # connection-string credentials:  scheme://user:pass@host
    (re.compile(r'(://[^:/@\s]+:)([^@/\s]+)(@)'), r'\1' + R + r'\3'),
    # /etc/shadow style password hashes:  user:$6$salt$hash:...
    (re.compile(r'(?m)^([^:\s]+:)(\$[0-9a-zA-Z]\$[^:\s]+)(:)'), r'\1' + R + r'\3'),
]

# fields in a tool-result dict that may carry raw output
_TEXT_FIELDS = ('output', 'content', 'body', 'transcript', 'text', 'error')


def redact(text):
    if not text or not isinstance(text, str):
        return text
    for pat, repl in _RULES:
        text = pat.sub(repl, text)
    return text


def scrub_result(result):
    """Redact secrets from the text-bearing fields of a tool result dict."""
    if not isinstance(result, dict):
        return result
    for k in _TEXT_FIELDS:
        if isinstance(result.get(k), str):
            result[k] = redact(result[k])
    return result
