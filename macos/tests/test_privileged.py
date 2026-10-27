import os
import shutil
import subprocess
import sys
import types

import pytest

from proton.vpn.macos import privileged


@pytest.fixture
def helper(tmp_path, monkeypatch):
    monkeypatch.setattr(privileged, "HELPER", tmp_path / "libexec" / "helper")
    monkeypatch.setattr(privileged, "SUDOERS", tmp_path / "sudoers.d" / "rule")
    (tmp_path / "sudoers.d").mkdir()
    return privileged.HELPER


def test_command_runs_the_helper_through_sudo(helper):
    assert privileged.command("pf-load") == ["/usr/bin/sudo", "-n", str(helper), "pf-load"]


def test_run_passes_stdin_and_captures_output(helper, monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    privileged.run("up", stdin="config")
    (command, kwargs), = calls
    assert command[-1] == "up"
    assert kwargs["input"] == "config"
    assert kwargs["capture_output"] and not kwargs["check"]


def test_bundled_version_matches_the_helper_script():
    assert privileged.bundled_version() == "1"  # helper.sh's VERSION=


def test_bundled_version_without_a_version_line(tmp_path, monkeypatch):
    script = tmp_path / "helper.sh"
    script.write_text("#!/bin/bash\n")
    monkeypatch.setattr(privileged, "SOURCE", script)
    assert privileged.bundled_version() == ""


def test_is_set_up(helper, monkeypatch):
    assert not privileged.is_set_up()

    helper.parent.mkdir()
    helper.write_text("")
    version = privileged.bundled_version()
    monkeypatch.setattr(privileged, "run", lambda *a: types.SimpleNamespace(returncode=0, stdout=version + "\n"))
    assert privileged.is_set_up()

    monkeypatch.setattr(privileged, "run", lambda *a: types.SimpleNamespace(returncode=0, stdout="0\n"))
    assert not privileged.is_set_up()
    monkeypatch.setattr(privileged, "run", lambda *a: types.SimpleNamespace(returncode=1, stdout=version))
    assert not privileged.is_set_up()


def test_setup_reruns_itself_with_sudo_when_not_root(helper, monkeypatch):
    ran = []
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(privileged, "is_set_up", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda cmd, check: ran.append(cmd) or types.SimpleNamespace(returncode=0))
    privileged.setup("wade")
    assert ran == [["/usr/bin/sudo", sys.executable, "-m", "proton.vpn.macos.vpn", "setup", "--user", "wade"]]


def test_setup_stops_when_sudo_fails(helper, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(privileged, "is_set_up", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda cmd, check: types.SimpleNamespace(returncode=1))
    with pytest.raises(SystemExit) as exit:
        privileged.setup("wade")
    assert exit.value.code == 1


def test_setup_skips_sudo_when_already_set_up(helper, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(privileged, "is_set_up", lambda: True)
    privileged.setup("wade")
    assert capsys.readouterr().out == "Already set up: connecting doesn't need your password.\n"


def test_ensure_set_up_sets_up_in_a_terminal(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(privileged, "setup", lambda: calls.append("setup"))
    monkeypatch.setattr(privileged, "is_set_up", lambda: True)
    privileged.ensure_set_up()
    assert calls == []

    monkeypatch.setattr(privileged, "is_set_up", lambda: False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    privileged.ensure_set_up()
    assert calls == ["setup"]
    assert "one-time setup first" in capsys.readouterr().out


def test_ensure_set_up_without_a_terminal(monkeypatch):
    monkeypatch.setattr(privileged, "is_set_up", lambda: False)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: False))
    with pytest.raises(SystemExit, match="run `protonvpn setup`"):
        privileged.ensure_set_up()


def root_setup(monkeypatch, valid=True, tools=("wg-quick", "wireguard-go")):
    """Runs setup as root without changing owners, with visudo faked."""
    chowns = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: chowns.append((path, uid, gid)))
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: types.SimpleNamespace(returncode=0 if valid else 1))
    monkeypatch.setattr(shutil, "which", lambda tool, path=None: "/bin/" + tool if tool in tools else None)
    return chowns


def test_setup_installs_the_helper_and_sudo_rule(helper, monkeypatch, capsys):
    chowns = root_setup(monkeypatch)
    privileged.setup("wade")
    assert helper.read_text() == privileged.SOURCE.read_text()
    assert helper.stat().st_mode & 0o777 == 0o755
    rule = privileged.SUDOERS
    assert rule.read_text() == f"wade ALL=(root) NOPASSWD: {helper}\n"
    assert rule.stat().st_mode & 0o777 == 0o440
    assert len(chowns) == 2
    assert capsys.readouterr().out == "Set up: wade can now connect without a password.\n"


def test_setup_says_which_tools_are_missing(helper, monkeypatch, capsys):
    root_setup(monkeypatch, tools=())
    monkeypatch.setenv("SUDO_USER", "wade")
    privileged.setup()
    assert "missing wg-quick, wireguard-go" in capsys.readouterr().out


def test_setup_changes_nothing_when_the_rule_is_invalid(helper, monkeypatch):
    root_setup(monkeypatch, valid=False)
    with pytest.raises(SystemExit, match="didn't validate"):
        privileged.setup("wade")
    assert not privileged.SUDOERS.exists()
