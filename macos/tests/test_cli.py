import contextlib
import os
import sys

import pytest

from proton.vpn.macos import cli, wireguard, privileged


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv(cli.LOCK_HELD, raising=False)
    (tmp_path / ".cache" / "Proton" / "VPN").mkdir(parents=True)
    return tmp_path


def test_runtime_dirs_are_under_the_home_directory(home, monkeypatch):
    import tempfile
    monkeypatch.setattr(tempfile, "gettempdir", lambda: "/tmp/x")
    assert cli._get_dir_paths(None) == (str(home / ".config"), str(home / ".cache"), "/tmp/x")


def test_create_registry_registers_the_macos_backend(monkeypatch):
    # The backend is only valid where wg-quick and the root helper are installed, unlike on CI.
    monkeypatch.setattr(wireguard.WgQuickWireguard, "validate", classmethod(lambda cls: True))
    registry = cli.create_registry()
    assert registry.get("wireguard").backend == "wgquick"


def test_install_plugs_in_the_macos_backends(monkeypatch):
    registered = {}
    monkeypatch.setattr(cli.Loader, "set_all", lambda kind, backends: registered.update({kind: backends}))
    monkeypatch.setattr(cli.ProtonVPNAPI, "create_registry", cli.ProtonVPNAPI.create_registry)
    from proton.vpn.cli.commands import server
    monkeypatch.setattr(server, "wait_for_current_tasks", server.wait_for_current_tasks)
    cli.install()
    assert registered["killswitch"] == {"pf": cli.PfKillSwitch}
    assert registered["keyring"]["keychain"] is cli.KeychainKeyring
    assert registered["split_tunneling"] == {}
    assert cli.ProtonVPNAPI.create_registry() is not None


def test_wait_for_current_tasks_ignores_cancelled_tasks(monkeypatch, capsys):
    import asyncio
    from proton.vpn.cli.commands import server
    monkeypatch.setattr(server, "wait_for_current_tasks", server.wait_for_current_tasks)
    cli._wait_for_current_tasks_ignoring_cancelled()

    async def main():
        async def cancelled():
            raise asyncio.CancelledError

        async def slow():
            await asyncio.sleep(10)

        task = asyncio.ensure_future(cancelled())
        await asyncio.sleep(0)
        await server.wait_for_current_tasks()
        assert task.cancelled()
        slow_task = asyncio.ensure_future(slow())
        await server.wait_for_current_tasks(timeout=0.01)
        slow_task.cancel()

    asyncio.run(main())
    assert "Timed out after 0.01s" in capsys.readouterr().out


def test_locked_sets_and_clears_the_marker(home):
    with cli.locked():
        assert os.environ[cli.LOCK_HELD] == "1"
        assert (home / ".cache" / "Proton" / "VPN" / ".lock").exists()
    assert cli.LOCK_HELD not in os.environ


def test_locked_lets_children_through(home, monkeypatch):
    monkeypatch.setenv(cli.LOCK_HELD, "1")
    with cli.locked():
        pass
    assert os.environ[cli.LOCK_HELD] == "1"
    assert not (home / ".cache" / "Proton" / "VPN" / ".lock").exists()


@pytest.fixture
def proton_main(home, monkeypatch):
    import proton.vpn.cli
    calls = []
    monkeypatch.setattr(cli, "install", lambda: calls.append("install"))
    monkeypatch.setattr(proton.vpn.cli, "main", lambda **kw: calls.append(kw))
    monkeypatch.setattr(cli, "locked", lambda: contextlib.nullcontext(calls.append("locked")))
    monkeypatch.setattr(privileged, "is_set_up", lambda: True)
    return calls


def test_main_locks_commands_that_change_things(proton_main, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["protonvpn", "connect", "--p2p"])
    cli.main()
    assert proton_main == ["install", "locked", {"allow_concurrency": True}]


def test_main_does_not_lock_read_only_commands(proton_main, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["protonvpn", "--json", "status"])
    cli.main()
    assert proton_main == ["install", {"allow_concurrency": True}]


def test_main_refuses_to_connect_before_setup(proton_main, monkeypatch):
    monkeypatch.setattr(privileged, "is_set_up", lambda: False)
    monkeypatch.setattr(sys, "argv", ["protonvpn", "connect"])
    with pytest.raises(SystemExit, match="run `protonvpn setup`"):
        cli.main()


def test_main_shows_connects_help_before_setup(proton_main, monkeypatch):
    monkeypatch.setattr(privileged, "is_set_up", lambda: False)
    monkeypatch.setattr(sys, "argv", ["protonvpn", "connect", "--help"])
    cli.main()
    assert proton_main[-1] == {"allow_concurrency": True}
