"""Server-side logging.

The app had none: failed logins, approvals, SSH failures, LLM errors and
scheduler activity left no trace anywhere, so nothing could be diagnosed or
noticed after the fact. The `audit` table records agent tool calls for the UI;
this is the operational log for the operator's terminal / journalctl.

Level is NAA_LOG_LEVEL (default INFO). Everything goes to stderr, which is what
systemd and `docker logs` capture.
"""
import logging
import os
import sys

_configured = False


def setup():
    global _configured
    if _configured:
        return
    level = os.environ.get('NAA_LOG_LEVEL', 'INFO').upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)-7s %(name)-12s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'))
    root = logging.getLogger('naa')
    root.setLevel(getattr(logging, level, logging.INFO))
    root.handlers[:] = [handler]
    root.propagate = False
    # paramiko logs every packet at DEBUG — keep it at WARNING regardless
    logging.getLogger('paramiko').setLevel(logging.WARNING)
    _configured = True


def get(name):
    """A logger under the 'naa' namespace, e.g. logs.get('agent')."""
    setup()
    return logging.getLogger(f'naa.{name}')
