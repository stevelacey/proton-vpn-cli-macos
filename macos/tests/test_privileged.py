import json
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
    assert privileged.bundled_version() == "2"  # helper.sh's VERSION=


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
    monkeypatch.setattr(privileged, "outdated_tools", lambda: [])
    privileged.setup("wade")
    assert capsys.readouterr().out == "Already set up: connecting doesn't need your password.\n"


def test_setup_runs_again_when_the_tools_are_out_of_date(helper, monkeypatch):
    ran = []
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(privileged, "is_set_up", lambda: True)
    monkeypatch.setattr(privileged, "outdated_tools", lambda: ["bash"])
    monkeypatch.setattr(subprocess, "run", lambda cmd, check: ran.append(cmd) or types.SimpleNamespace(returncode=0))
    privileged.setup("wade")
    assert ran[0][:2] == ["/usr/bin/sudo", sys.executable]


def test_outdated_tools(tmp_path, monkeypatch):
    import json
    brew = tmp_path / "Cellar"
    for name in ("bash-5.3", "bash-5.4", "wg-1"):
        (brew / name).mkdir(parents=True)
        (brew / name / "tool").touch()
    assert privileged.outdated_tools() == []
    privileged.TOOLS.mkdir()
    (privileged.TOOLS / "sources.json").write_text(json.dumps({
        "bash": str(brew / "bash-5.3" / "tool"), "wg": str(brew / "wg-1" / "tool"), "wireguard-go": "/gone"}))
    links = {"bash": str(brew / "bash-5.4" / "tool"), "wg": str(brew / "wg-1" / "tool")}
    monkeypatch.setattr(shutil, "which", lambda tool, path=None: links.get(tool))
    # Upgraded, but not uninstalled.
    assert privileged.outdated_tools() == ["bash"]


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


def root_setup(monkeypatch, valid=True, tools=("wg-quick", "wg", "wireguard-go", "bash")):
    """Runs setup as root without changing owners or copying tools, with visudo faked."""
    chowns = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: chowns.append((path, uid, gid)))
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: types.SimpleNamespace(returncode=0 if valid else 1))
    monkeypatch.setattr(shutil, "which", lambda tool, path=None: "/bin/" + tool if tool in tools else None)
    monkeypatch.setattr(privileged, "writable_by_others", lambda path: None)
    monkeypatch.setattr(privileged, "install_tools", lambda found: chowns.append(("tools", found)))
    return chowns


def test_setup_installs_the_tools_helper_and_sudo_rule(helper, monkeypatch, capsys):
    chowns = root_setup(monkeypatch)
    privileged.setup("wade")
    assert chowns[0] == ("tools", {tool: "/bin/" + tool for tool in ("wg-quick", "wg", "wireguard-go", "bash")})
    assert helper.read_text() == privileged.SOURCE.read_text()
    assert helper.stat().st_mode & 0o777 == 0o755
    rule = privileged.SUDOERS
    assert rule.read_text() == f"wade ALL=(root) NOPASSWD: {helper}\n"
    assert rule.stat().st_mode & 0o777 == 0o440
    assert len(chowns) == 3
    assert capsys.readouterr().out == "Set up: wade can now connect without a password.\n"


def test_setup_needs_the_tools(helper, monkeypatch):
    root_setup(monkeypatch, tools=("wg-quick",))
    monkeypatch.setenv("SUDO_USER", "wade")
    with pytest.raises(SystemExit, match="brew install wireguard-tools wireguard-go bash"):
        privileged.setup()
    assert not helper.exists()


def test_setup_refuses_a_folder_others_can_change(helper, monkeypatch):
    root_setup(monkeypatch)
    monkeypatch.setattr(privileged, "writable_by_others", lambda path: path)
    with pytest.raises(SystemExit, match="can be changed by users other than root"):
        privileged.setup("wade")
    assert not helper.exists()


def test_setup_changes_nothing_when_the_rule_is_invalid(helper, monkeypatch):
    root_setup(monkeypatch, valid=False)
    with pytest.raises(SystemExit, match="didn't validate"):
        privileged.setup("wade")
    assert not privileged.SUDOERS.exists()


def test_writable_by_others(monkeypatch):
    from pathlib import Path
    stats = {
        "/": (0, 0o755), "/usr": (0, 0o755), "/usr/local": (501, 0o755), "/usr/local/libexec": (0, 0o775),
        "/opt": (0, 0o755), "/opt/safe": (0, 0o755),
    }
    monkeypatch.setattr(Path, "stat", lambda self, **kw: types.SimpleNamespace(
        st_uid=stats[str(self)][0], st_mode=stats[str(self)][1]))
    assert privileged.writable_by_others(Path("/usr/local/libexec")) == Path("/usr/local/libexec")
    stats["/usr/local/libexec"] = (0, 0o755)
    assert privileged.writable_by_others(Path("/usr/local/libexec")) == Path("/usr/local")
    assert privileged.writable_by_others(Path("/opt/safe")) is None


def test_linked_libraries_leaves_out_macos_and_its_own(monkeypatch):
    outputs = {
        "-D": "/hb/lib/libreadline.8.3.dylib:\n/hb/opt/readline/lib/libreadline.8.dylib\n",
        "-L": "/hb/lib/libreadline.8.3.dylib:\n\t/hb/opt/readline/lib/libreadline.8.dylib (compatibility)\n"
              "\t/hb/opt/ncurses/lib/libncursesw.6.dylib (compatibility)\n\t/usr/lib/libSystem.B.dylib (x)\n"
              "\t/System/Library/Frameworks/CoreFoundation (x)\n\t@rpath/libx.dylib (x)\n",
    }
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: types.SimpleNamespace(stdout=outputs[cmd[1]]))
    assert privileged.linked_libraries("/hb/lib/libreadline.8.3.dylib") == ["/hb/opt/ncurses/lib/libncursesw.6.dylib"]


def test_install_tools_copies_them_with_bashs_libraries(tmp_path, monkeypatch):
    brew = tmp_path / "brew"
    brew.mkdir()
    for name in ("wg-quick", "wg", "wireguard-go", "bash", "libreadline.8.dylib", "libncursesw.6.dylib"):
        (brew / name).write_text(name)
    tools = tmp_path / "tools"
    monkeypatch.setattr(privileged, "TOOLS", tools)
    # A previous copy, replaced.
    (tools / "old").mkdir(parents=True)
    links = {"bash": [f"{brew}/libreadline.8.dylib", f"{brew}/libncursesw.6.dylib"],
             "libreadline.8.dylib": [f"{brew}/libncursesw.6.dylib"]}
    monkeypatch.setattr(privileged, "linked_libraries", lambda binary: links.get(binary.name, []))
    calls, chowns = [], []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append([os.path.basename(cmd[0]), *(
        os.path.relpath(arg, tmp_path) if str(arg).startswith(str(tmp_path)) else arg for arg in cmd[1:])]))
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: chowns.append((uid, gid)))
    privileged.install_tools({tool: str(brew / tool) for tool in ("wg-quick", "wg", "wireguard-go", "bash")})

    assert sorted(os.listdir(tools)) == ["bash", "lib", "sources.json", "wg", "wg-quick", "wireguard-go"]
    assert json.loads((tools / "sources.json").read_text())["bash"] == str(brew / "bash")
    assert (tools / "sources.json").stat().st_mode & 0o777 == 0o644
    assert sorted(os.listdir(tools / "lib")) == ["libncursesw.6.dylib", "libreadline.8.dylib"]
    assert (tools / "lib" / "libreadline.8.dylib").read_text() == "libreadline.8.dylib"
    assert not tools.with_name("tools.new").exists()
    lib = "tools.new/lib/"
    assert calls == [
        ["install_name_tool", "-id", "@executable_path/lib/libreadline.8.dylib", lib + "libreadline.8.dylib"],
        ["install_name_tool", "-change", "brew/libreadline.8.dylib", "@executable_path/lib/libreadline.8.dylib",
         "tools.new/bash"],
        ["install_name_tool", "-id", "@executable_path/lib/libncursesw.6.dylib", lib + "libncursesw.6.dylib"],
        ["install_name_tool", "-change", "brew/libncursesw.6.dylib", "@executable_path/lib/libncursesw.6.dylib",
         "tools.new/bash"],
        ["install_name_tool", "-change", "brew/libncursesw.6.dylib", "@executable_path/lib/libncursesw.6.dylib",
         lib + "libreadline.8.dylib"],
        ["codesign", "--force", "--sign", "-", lib + "libreadline.8.dylib"],
        ["codesign", "--force", "--sign", "-", lib + "libncursesw.6.dylib"],
        ["codesign", "--force", "--sign", "-", "tools.new/bash"],
    ]
    assert set(chowns) == {(0, 0)} and len(chowns) == 9
    assert (tools / "bash").stat().st_mode & 0o777 == 0o755
    assert (tools / "lib" / "libreadline.8.dylib").stat().st_mode & 0o777 == 0o644
