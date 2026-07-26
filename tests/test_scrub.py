import scrub


def test_private_key_block():
    txt = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\nxyz\n-----END OPENSSH PRIVATE KEY-----"
    out = scrub.redact(txt)
    assert 'abc123' not in out and '[REDACTED PRIVATE KEY]' in out


def test_sql_identified_by():
    out = scrub.redact("CREATE USER 'wp'@'localhost' IDENTIFIED BY 'Sup3rS3cret!';")
    assert 'Sup3rS3cret' not in out and 'IDENTIFIED BY' in out


def test_named_secret_fields():
    for line, secret in [("password=hunter2", "hunter2"),
                         ('api_key: "sk_live_abc123def"', "sk_live_abc123def"),
                         ("DB_PASSWORD=topsecret", "topsecret"),
                         ("token = ghs_notreal", "ghs_notreal"),
                         # PHP define / wp-config.php style (the LAMP scenario)
                         ("define('DB_PASSWORD', 'Sup3rSecret!');", "Sup3rSecret"),
                         ('"api_key" => "livekey123"', "livekey123")]:
        out = scrub.redact(line)
        assert secret not in out, line
        assert '[REDACTED]' in out


def test_auth_headers_and_tokens():
    assert 'abcdef123456' not in scrub.redact('Authorization: Bearer abcdef123456ghijkl')
    # a known token shape is redacted entirely (prefix included)
    assert '0123456789abcdefghij' not in scrub.redact('token ghp_0123456789abcdefghij')
    assert scrub.redact('ghp_0123456789abcdefghij') == '[REDACTED]'


def test_connection_string():
    out = scrub.redact("mysql://wpuser:s3cr3tp@ss@db.local/wordpress")
    assert 's3cr3tp' not in out and 'wpuser' in out


def test_shadow_hash():
    out = scrub.redact("root:$6$abcd$hashvalue1234:20639:0:99999:7:::")
    assert 'hashvalue1234' not in out and 'root:' in out


def test_scrub_result_only_text_fields():
    r = scrub.scrub_result({'ok': True, 'exit_code': 0,
                            'output': "IDENTIFIED BY 'letmein'", 'error': ''})
    assert 'letmein' not in r['output']
    assert r['ok'] is True and r['exit_code'] == 0  # non-text fields untouched


def test_benign_text_unchanged():
    txt = "apache2 is running on port 80; disk 32% used"
    assert scrub.redact(txt) == txt
