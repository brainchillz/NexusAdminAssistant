"""Conversation auto-titling: derive_title() + the backfill migration."""
import os

from agent import core


def test_short_message_capitalized():
    assert core.derive_title('check disk usage on lamp1') == 'Check disk usage on lamp1'


def test_already_capitalized_preserved():
    assert core.derive_title('Install nginx') == 'Install nginx'


def test_collapses_whitespace_and_newlines():
    assert core.derive_title('  restart\n\n  the   web    server  ') == 'Restart the web server'


def test_empty_falls_back_to_default():
    assert core.derive_title('') == core.DEFAULT_TITLE
    assert core.derive_title('   \n\t ') == core.DEFAULT_TITLE


def test_long_message_truncated_on_word_boundary():
    msg = 'please set up a full LAMP stack with WordPress and configure the virtual host too'
    t = core.derive_title(msg)
    assert len(t) <= 49          # 48 + the ellipsis
    assert t.endswith('…')
    assert not t[:-1].endswith(' ')          # no trailing space before the ellipsis
    assert msg.lower().startswith(t[:-1].lower())  # a real prefix (modulo the capital)


def test_backfill_migration_names_old_conversations():
    from store import db
    now = '2026-01-01T00:00:00+00:00'
    uid = db.query_one('SELECT id FROM users LIMIT 1')['id']
    db.execute("INSERT INTO conversations(id, host_id, user_id, title, created_at, updated_at)"
               " VALUES('bf01', NULL, ?, 'New conversation', ?, ?)", (uid, now, now))
    db.execute("INSERT INTO messages(conversation_id, role, content, created_at)"
               " VALUES('bf01','user','  how do I check\nfree memory  ', ?)", (now,))
    # an untitled conversation with NO messages must stay as-is
    db.execute("INSERT INTO conversations(id, host_id, user_id, title, created_at, updated_at)"
               " VALUES('bf02', NULL, ?, 'New conversation', ?, ?)", (uid, now, now))

    with open(os.path.join('store', 'migrations', '0007_convo_titles.sql')) as fh:
        sql = fh.read()
    with db.connect() as conn:
        conn.executescript(sql)
        conn.commit()

    assert db.query_one("SELECT title FROM conversations WHERE id='bf01'")['title'] == 'how do I check free memory'
    assert db.query_one("SELECT title FROM conversations WHERE id='bf02'")['title'] == 'New conversation'
