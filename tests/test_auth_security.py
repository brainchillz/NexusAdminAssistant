"""Regression test for the 2026-07-29 login-timing fix.

An unknown username and a known username with a wrong password must each cost
exactly one password hash, so response time cannot reveal whether an account
exists. (The autouse db fixture seeds an 'admin' user.)
"""


def test_authenticate_hashes_once_per_path(monkeypatch):
    import auth
    calls = {'n': 0}
    real = auth.check_password_hash
    monkeypatch.setattr(auth, 'check_password_hash',
                        lambda h, p: (calls.__setitem__('n', calls['n'] + 1), real(h, p))[1])

    calls['n'] = 0
    assert auth.authenticate('ghost-nobody', 'x') is None
    assert calls['n'] == 1        # unknown user: one dummy hash

    calls['n'] = 0
    assert auth.authenticate('admin', 'definitely-wrong') is None
    assert calls['n'] == 1        # known user, wrong password: one real hash
