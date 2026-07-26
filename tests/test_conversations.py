"""Active-run guard for conversation deletion.

active_conversation_ids() is what the delete/clear endpoints consult to refuse
removing a conversation whose agent run is still live in-process (which would
orphan the run thread). Pure-ish: it just scans core.RUNS.
"""
from types import SimpleNamespace

from agent import core


def _fake_run(conv_id, finished):
    return SimpleNamespace(conversation={'id': conv_id}, finished=finished)


def test_active_ids_lists_only_unfinished_runs():
    core.RUNS.clear()
    core.RUNS['r1'] = _fake_run('conv-live', finished=False)
    core.RUNS['r2'] = _fake_run('conv-done', finished=True)
    ids = core.active_conversation_ids()
    assert 'conv-live' in ids
    assert 'conv-done' not in ids
    core.RUNS.clear()


def test_active_ids_empty_when_no_runs():
    core.RUNS.clear()
    assert core.active_conversation_ids() == set()


def test_active_ids_tolerates_run_without_conversation():
    core.RUNS.clear()
    core.RUNS['r3'] = SimpleNamespace(conversation=None, finished=False)
    # should not raise; a run with no conversation contributes a None id
    assert core.active_conversation_ids() == {None}
    core.RUNS.clear()
