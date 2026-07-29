FROM python:3.12-slim

# runtime deps kept minimal; paramiko needs libffi/openssl (in slim already)
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY wsgi.py app.py config.py auth.py logs.py inventory.py memory.py skills.py schedule.py services.py monitor.py scrub.py changes.py provision.py backup.py tls.py telegrambot.py ./
COPY agent ./agent
COPY store ./store
COPY static ./static
COPY templates ./templates
COPY --chmod=0755 docker-entrypoint.sh /docker-entrypoint.sh

# non-root; state lives in a mounted volume at /data. A real home dir is needed
# so gunicorn's control socket ($HOME/.gunicorn) is writable.
RUN useradd --system --uid 10001 --create-home --home-dir /home/nexusadmin nexusadmin \
    && mkdir -p /data && chown nexusadmin /data
USER nexusadmin

ENV HOME=/home/nexusadmin NAA_DATA_DIR=/data NAA_PORT=8080 NAA_TLS=0
EXPOSE 8080
VOLUME ["/data"]

# entrypoint enables HTTPS when NAA_TLS=1 (else HTTP). 1 worker: the agent run
# manager + streaming hold in-process state, so never raise the worker count.
ENTRYPOINT ["/docker-entrypoint.sh"]
