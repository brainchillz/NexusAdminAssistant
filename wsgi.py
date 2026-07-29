"""WSGI entrypoint — `gunicorn wsgi:app`.

Importing `app` is deliberately side-effect free (so tests can import it), so
the server entrypoint is the thing that calls boot(): configure storage, ensure
the admin user, and start the scheduler / monitor / Telegram pollers.
"""
from app import app, boot

boot()

# `app` is re-exported deliberately: it is the WSGI callable gunicorn loads.
__all__ = ['app']
