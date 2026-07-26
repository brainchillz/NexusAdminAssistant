#!/usr/bin/env bash
# Nexus Admin Assistant — systemd installer.
# Installs as a dedicated unprivileged system service that survives reboots.
#   code   -> /opt/nexus-admin-assistant        (this repo, + a venv)
#   state  -> /var/lib/nexus-admin-assistant     (config.json + naa.db; NOT a user dir)
#   user   -> nexusadmin (system account, no login)
#   served -> gunicorn (1 gthread worker; in-process agent state) on :PORT
# Idempotent: re-running upgrades the code in place and preserves all state.
set -euo pipefail

NAA_USER="${NAA_USER:-nexusadmin}"
NAA_DIR="${NAA_DIR:-/opt/nexus-admin-assistant}"
NAA_STATE="${NAA_STATE:-/var/lib/nexus-admin-assistant}"
NAA_SERVICE="${NAA_SERVICE:-nexus-admin-assistant}"
NAA_PORT="${NAA_PORT:-8080}"
NAA_TLS="${NAA_TLS:-0}"
NAA_THREADS="${NAA_THREADS:-16}"
UNIT="/etc/systemd/system/${NAA_SERVICE}.service"
SRC="$(cd "$(dirname "$0")" && pwd)"

# ─── preflight ────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo $0)"; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || { echo "Python 3.9+ is required (found $(python3 -V 2>&1))"; exit 1; }

echo "==> Nexus Admin Assistant installer"
echo "    code=$NAA_DIR  state=$NAA_STATE  user=$NAA_USER  port=$NAA_PORT  tls=$NAA_TLS"

# 1. service user (system, no login, no shell)
if ! id "$NAA_USER" >/dev/null 2>&1; then
  echo "==> Creating system user $NAA_USER"
  useradd --system --no-create-home --home-dir "$NAA_STATE" --shell /usr/sbin/nologin "$NAA_USER"
fi

# 2. code -> /opt  (never copy venv, state, git, caches, docs-only bits)
echo "==> Installing code to $NAA_DIR"
mkdir -p "$NAA_DIR"
if command -v rsync >/dev/null; then
  rsync -a --delete \
    --exclude venv --exclude .git --exclude __pycache__ --exclude '*.pyc' \
    --exclude data --exclude .pytest_cache \
    "$SRC"/ "$NAA_DIR"/
else
  cp -r "$SRC"/wsgi.py "$SRC"/app.py "$SRC"/config.py "$SRC"/auth.py "$SRC"/logs.py "$SRC"/inventory.py \
        "$SRC"/memory.py "$SRC"/skills.py "$SRC"/schedule.py "$SRC"/services.py "$SRC"/monitor.py \
        "$SRC"/scrub.py "$SRC"/changes.py "$SRC"/provision.py "$SRC"/backup.py "$SRC"/tls.py "$SRC"/telegrambot.py "$SRC"/requirements.txt \
        "$SRC"/agent "$SRC"/store "$SRC"/static "$SRC"/templates "$NAA_DIR"/
fi

# 3. venv + deps (+ gunicorn)
echo "==> Building venv + installing dependencies"
if ! python3 -m venv "$NAA_DIR/venv" 2>/tmp/naa-venv.err; then
  echo "✗ Could not create the virtualenv:"; cat /tmp/naa-venv.err
  echo "  On Debian/Ubuntu install it first:  sudo apt-get install -y python3-venv"
  exit 1
fi
"$NAA_DIR/venv/bin/pip" install -q --upgrade pip
"$NAA_DIR/venv/bin/pip" install -q -r "$NAA_DIR/requirements.txt"

# 4. state dir (outside any user home), owned by the service user
mkdir -p "$NAA_STATE"
chown -R "$NAA_USER:$NAA_USER" "$NAA_STATE" "$NAA_DIR"
chmod 750 "$NAA_STATE"

# 4b. self-signed TLS cert (only if TLS is on and none exists yet)
if [ "$NAA_TLS" = "1" ] && [ ! -f "$NAA_STATE/tls/cert.pem" ]; then
  echo "==> Generating a self-signed TLS certificate"
  mkdir -p "$NAA_STATE/tls"
  if command -v openssl >/dev/null; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
      -keyout "$NAA_STATE/tls/key.pem" -out "$NAA_STATE/tls/cert.pem" \
      -subj "/CN=$(hostname -f 2>/dev/null || hostname)" >/dev/null 2>&1
  else
    "$NAA_DIR/venv/bin/python" - "$NAA_STATE/tls" <<'PY'
import sys, os, socket, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
d = sys.argv[1]; os.makedirs(d, exist_ok=True)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .sign(key, hashes.SHA256()))
open(d + '/key.pem', 'wb').write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
open(d + '/cert.pem', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
PY
  fi
  chown -R "$NAA_USER:$NAA_USER" "$NAA_STATE/tls"
  chmod 600 "$NAA_STATE/tls/key.pem"
fi

# 5. first-run admin bootstrap (only if the DB has no users yet) — keeps the
#    password OUT of the persistent unit file.
FIRST_RUN=0
if [ ! -f "$NAA_STATE/naa.db" ]; then
  FIRST_RUN=1
  ADMIN_PW="${NAA_ADMIN_PASSWORD:-$(head -c 9 /dev/urandom | base64 | tr -d '/+=' | head -c 12)}"
  echo "==> Bootstrapping admin account"
  # run from $NAA_DIR so the service user can import the code (it can't read the
  # build source dir) and so cwd is on sys.path
  ( cd "$NAA_DIR" && sudo -u "$NAA_USER" env NAA_DATA_DIR="$NAA_STATE" NAA_ADMIN_PASSWORD="$ADMIN_PW" \
      "$NAA_DIR/venv/bin/python" -c \
      "import config, auth; from store import db; config.load(); db.configure(config.DB_FILE); auth.ensure_admin()" )
fi

# 6. gunicorn command (1 worker = in-process agent/run state; timeout 0 for SSE)
EXEC="$NAA_DIR/venv/bin/gunicorn -k gthread -w 1 --threads $NAA_THREADS --timeout 0 -b 0.0.0.0:$NAA_PORT wsgi:app"
if [ "$NAA_TLS" = "1" ]; then
  EXEC="$EXEC --certfile $NAA_STATE/tls/cert.pem --keyfile $NAA_STATE/tls/key.pem"
fi

# 7. systemd unit — sandboxed. App stores its own creds encrypted in its DB, so
#    ProtectHome/ProtectSystem are safe; it needs outbound network (SSH/HTTP).
echo "==> Writing $UNIT"
cat > "$UNIT" <<EOF
[Unit]
Description=Nexus Admin Assistant (AI homelab admin)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$NAA_USER
Group=$NAA_USER
WorkingDirectory=$NAA_DIR
Environment=NAA_DATA_DIR=$NAA_STATE
Environment=NAA_TLS=$NAA_TLS
ExecStart=$EXEC
Restart=on-failure
RestartSec=3

# hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ReadWritePaths=$NAA_STATE

[Install]
WantedBy=multi-user.target
EOF

# 8. enable + (re)start
echo "==> Enabling + starting $NAA_SERVICE"
systemctl daemon-reload
systemctl enable "$NAA_SERVICE" >/dev/null 2>&1
systemctl restart "$NAA_SERVICE"
sleep 2

if systemctl is-active --quiet "$NAA_SERVICE"; then
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; IP="${IP:-localhost}"
  SCHEME=$([ "$NAA_TLS" = "1" ] && echo https || echo http)
  echo
  echo "✓ Installed and running (survives reboots)."
  echo
  echo "  Created / ensured:"
  echo "    • system user   $NAA_USER (no login)"
  echo "    • code + venv    $NAA_DIR"
  echo "    • state + DB     $NAA_STATE   ($([ "$FIRST_RUN" = "1" ] && echo "fresh database" || echo "existing state preserved"))"
  echo "    • systemd unit   $UNIT (enabled)"
  [ "$NAA_TLS" = "1" ] && echo "    • TLS cert       $NAA_STATE/tls/"
  echo
  echo "  URL:   $SCHEME://$IP:$NAA_PORT"
  [ "$FIRST_RUN" = "1" ] && echo "  Login: admin / $ADMIN_PW   (you'll be asked to change it)"
  echo "  Logs:  journalctl -u $NAA_SERVICE -f"
  echo "  Stop:  systemctl stop $NAA_SERVICE   ·   Upgrade: re-run this script"
else
  echo "✗ Service failed to start. Check: journalctl -u $NAA_SERVICE -n 40"
  exit 1
fi
