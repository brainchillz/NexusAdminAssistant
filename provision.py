"""SSH key provisioning — onboard a host from password auth to key auth.

Generates an Ed25519 keypair in-app, deploys the public key to the host over its
current credentials, and (the caller) stores the private key so future access is
key-based. Optionally installs a passwordless-sudo drop-in.
"""
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.tools import ssh


def gen_ed25519(comment='nexus-admin-assistant'):
    """Return (private_key_openssh_pem, public_key_openssh_line)."""
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.OpenSSH,
                           serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                      serialization.PublicFormat.OpenSSH).decode()
    return priv, f'{pub} {comment}'


def derive_pubkey(private_key_str, comment=''):
    """Derive the authorized_keys line from a private key string.
    Raises ValueError (from ssh._pkey_from_str) when the key is unusable."""
    k = ssh._pkey_from_str(private_key_str)
    if k is None:
        raise ValueError('no private key supplied')
    line = f'{k.get_name()} {k.get_base64()}'
    return f'{line} {comment}' if comment else line


def _q(s):
    return "'" + s.replace("'", "'\\''") + "'"


def deploy_pubkey(host, secrets, pub):
    """Append the public key to the login user's authorized_keys (idempotent)."""
    q = _q(pub)
    cmd = ('mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && '
           'chmod 600 ~/.ssh/authorized_keys && '
           f'(grep -qxF {q} ~/.ssh/authorized_keys || echo {q} >> ~/.ssh/authorized_keys) && '
           'echo KEY_INSTALLED')
    return ssh.run(host, secrets, cmd)


def setup_nopasswd_sudo(host, secrets, username):
    """Install a passwordless-sudo drop-in for the user (needs current sudo)."""
    user = ''.join(c for c in (username or '') if c.isalnum() or c in '-_')
    if not user:
        return {'exit_code': 1, 'error': 'no username'}
    line = f'{user} ALL=(ALL) NOPASSWD:ALL\\n'
    cmd = (f'printf %b {_q(line)} | tee /etc/sudoers.d/90-nexus-{user} > /dev/null && '
           f'chmod 440 /etc/sudoers.d/90-nexus-{user} && '
           f'visudo -cf /etc/sudoers.d/90-nexus-{user} && echo SUDO_OK')
    return ssh.run(host, secrets, cmd, use_sudo=True)
