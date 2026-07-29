#!/bin/sh
# Start gunicorn, enabling HTTPS when NAA_TLS=1. When TLS is on we make sure a
# usable cert+key exist first (generating a self-signed pair only if BOTH are
# missing — an operator-supplied cert in the volume is never overwritten), then
# hand gunicorn the --certfile/--keyfile it needs. HTTP otherwise.
set -e

PORT="${NAA_PORT:-8080}"
set -- -k gthread -w 1 --threads "${NAA_THREADS:-16}" --timeout 0 -b "0.0.0.0:${PORT}"

if [ "${NAA_TLS}" = "1" ]; then
    if ! python -c "import sys, tls; ok, e = tls.ensure_tls_cert(); \
        (sys.stderr.write(e + '\n'), sys.exit(1)) if not ok else None"; then
        echo "NAA_TLS=1 but no usable certificate could be prepared — refusing to start." >&2
        exit 1
    fi
    CERT="${NAA_TLS_CERT:-/data/tls/cert.pem}"
    KEY="${NAA_TLS_KEY:-/data/tls/key.pem}"
    set -- "$@" --certfile "$CERT" --keyfile "$KEY"
    echo "nexus-admin-assistant: serving HTTPS on :${PORT}"
else
    echo "nexus-admin-assistant: serving HTTP on :${PORT} (set NAA_TLS=1 for HTTPS)"
fi

exec gunicorn "$@" wsgi:app
