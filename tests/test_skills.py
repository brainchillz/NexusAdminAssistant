import skills


def test_save_creates_draft_and_upserts():
    sid = skills.save('install-lamp', 'Install a LAMP stack', 'step 1...\nstep 2...')
    s = skills.get(sid)
    assert s['name'] == 'install-lamp' and s['approved'] is False
    # saving the same name updates in place, does not duplicate or auto-approve
    sid2 = skills.save('install-lamp', 'Install LAMP + WordPress', 'better steps')
    assert sid2 == sid
    assert skills.get(sid)['description'] == 'Install LAMP + WordPress'
    assert skills.get(sid)['approved'] is False


def test_approve_gates_context_and_list():
    sid = skills.save('prune-docker', 'Prune dangling images', 'docker image prune -f')
    assert 'prune-docker' not in skills.context_text()   # draft not offered
    skills.set_approved(sid, True)
    assert 'prune-docker' in skills.context_text()       # approved is offered
    assert any(s['name'] == 'prune-docker' for s in skills.list_approved())


def test_search():
    skills.save('setup-nginx', 'Install and enable nginx', 'apt install nginx')
    res = skills.search('nginx')
    assert any(s['name'] == 'setup-nginx' for s in res)


def test_refining_approved_keeps_approval():
    sid = skills.save('backup-db', 'DB backup', 'mysqldump ...', approved=True)
    assert skills.get(sid)['approved'] is True
    skills.save('backup-db', 'DB backup v2', 'mysqldump --single-transaction ...')
    assert skills.get(sid)['approved'] is True  # refine doesn't un-approve
