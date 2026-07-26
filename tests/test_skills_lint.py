"""skills.lint() — flags playbook steps that block an unattended ssh_exec run.

Pure helper, mirrors test_policy / test_scrub. The real-world fixtures are the
actual skills from the docker instance: the Minecraft one that hung must warn;
the WordPress and chrony ones that ran clean must not.
"""
import skills


def test_flags_foreground_java_server():
    w = skills.lint("sudo -u minecraft java -Xmx2G -jar /opt/minecraft/server.jar nogui")
    assert any('foreground' in m for m in w)


def test_foreground_java_ok_inside_systemd_execstart():
    # The same launch is fine as a systemd ExecStart line.
    w = skills.lint("ExecStart=/usr/bin/java -Xmx2G -jar /opt/minecraft/server.jar nogui")
    assert not any('foreground' in m for m in w)


def test_flags_press_ctrl_c():
    assert skills.lint('Wait for "Done!" then press Ctrl+C to stop.')


def test_flags_tail_and_journalctl_follow():
    assert skills.lint("tail -f /var/log/syslog")
    assert skills.lint("journalctl -u nginx -f")
    assert skills.lint("watch systemctl status nginx")


def test_journalctl_bounded_is_ok():
    assert skills.lint("journalctl -u nginx -n 50 --no-pager") == []


def test_flags_interactive_installer_and_read():
    assert skills.lint("sudo mysql_secure_installation")
    assert skills.lint('read -p "DB password: " pw')


def test_flags_ufw_enable_without_force():
    assert skills.lint("sudo ufw enable")
    assert skills.lint("sudo ufw --force enable") == []
    # a plain allow rule never prompts
    assert skills.lint("sudo ufw allow from 10.0.0.0/24 to any port 123 proto udp") == []


def test_flags_apt_install_without_yes():
    assert skills.lint("apt-get install nginx")
    assert skills.lint("sudo apt-get install -y nginx") == []
    assert skills.lint("DEBIAN_FRONTEND=noninteractive apt-get install openjdk-25-jre-headless") == []


def test_real_minecraft_skill_body_warns():
    body = (
        "5. Generate config files\n"
        "   sudo -u minecraft java -Xmx2G -Xms1G -jar /opt/minecraft/server.jar nogui\n"
        "   Wait for \"Done!\" then press Ctrl+C to stop.\n"
    )
    w = skills.lint(body)
    assert len(w) >= 2   # both the foreground launch and the ctrl-c step


def test_clean_playbook_no_warnings():
    body = (
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y chrony\n"
        "sudo tee /etc/chrony/conf.d/allow.conf <<'EOF'\nallow 10.0.0.0/24\nEOF\n"
        "sudo systemctl restart chrony\n"
        "ss -tulpn | grep ':123'\n"
        "sudo ufw allow from 10.0.0.0/24 to any port 123 proto udp\n"
    )
    assert skills.lint(body) == []
