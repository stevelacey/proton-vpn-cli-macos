import io
import json
import socket
import struct
import sys
import types

import pytest

from proton.vpn.macos import privileged, vpn


@pytest.fixture
def proton(monkeypatch):
    """Records the calls to Proton's CLI instead of making them."""
    calls = []
    monkeypatch.setattr(vpn, "protonvpn", lambda *args: calls.append(args))
    monkeypatch.setattr(vpn, "run_protonvpn", lambda *args: calls.append(("run", *args)))
    return calls


@pytest.fixture
def lock(monkeypatch):
    import contextlib
    from proton.vpn.macos import cli
    monkeypatch.setattr(cli, "locked", contextlib.nullcontext)


def connected(code="CH", server="CH#1"):
    return {"state": "Connected", "server": server, "code": code, "country": "Switzerland"}


def test_connect_fastest(server_list, proton):
    vpn.connect([])
    vpn.connect(["any"])
    vpn.connect(["p2p"])
    assert proton == [("connect",), ("connect",), ("connect", "--p2p")]


def test_connect_to_a_server_by_name(server_list, proton):
    vpn.connect(["ch#10"])
    vpn.connect(["sc", "IS-CH#1"])
    assert proton == [("connect", "CH#10"), ("connect", "IS-CH#1", "--securecore")]


def test_connect_to_a_country(server_list, proton):
    vpn.connect(["swiss"])
    vpn.connect(["tor sweden"])  # Alfred passes one argument
    assert proton == [("connect", "--country", "CH"), ("connect", "--country", "SE", "--tor")]


def test_connect_skips_when_already_there(server_list, proton, monkeypatch, capsys):
    monkeypatch.setattr(vpn, "status", connected)
    vpn.connect(["swiss"])
    assert proton == []
    assert capsys.readouterr().out == "Already connected to CH#1 (Switzerland)\n"

    monkeypatch.setattr(vpn, "status", lambda: connected(server="IS-CH#1"))
    vpn.connect(["swiss"])
    assert proton == [("connect", "--country", "CH")]


def test_connect_with_an_unknown_country(server_list, proton):
    with pytest.raises(SystemExit, match="no country matches 'atlantis'"):
        vpn.connect(["atlantis"])
    assert proton == []


def test_connect_without_a_server_list_leaves_it_to_proton(files, proton):
    vpn.connect(["japan"])
    assert proton == [("connect", "--country", "japan")]


def test_main_off(files, proton, capsys, monkeypatch):
    vpn.main(["off"])
    assert capsys.readouterr().out == "Already disconnected\n"
    monkeypatch.setattr(vpn, "status", connected)
    vpn.main(["disconnect"])
    assert proton == [("disconnect",)]


def test_main_status_text(files, capsys):
    vpn.main([])
    vpn.main(["status"])
    assert capsys.readouterr().out == "Disconnected\nDisconnected\n"


def test_main_connect_variants(server_list, proton):
    vpn.main(["fastest", "p2p"])
    vpn.main(["swiss"])
    vpn.main(["city", "p2p", "new", "york"])
    vpn.main(["signout"])
    assert proton == [("connect", "--p2p"), ("connect", "--country", "CH"),
                      ("connect", "--city", "new york", "--p2p"), ("signout",)]


def test_main_setup(monkeypatch):
    monkeypatch.setattr(privileged, "is_set_up", lambda: True)
    with pytest.raises(SystemExit) as exit:
        vpn.main(["setup", "--check"])
    assert exit.value.code == 0

    monkeypatch.setattr(privileged, "is_set_up", lambda: False)
    with pytest.raises(SystemExit) as exit:
        vpn.main(["setup", "--check"])
    assert exit.value.code == 1

    calls = []
    monkeypatch.setattr(privileged, "setup", calls.append)
    vpn.main(["setup"])
    vpn.main(["setup", "--user", "wade"])
    assert calls == [None, "wade"]


def test_main_account(monkeypatch, capsys):
    monkeypatch.setattr(vpn, "account", lambda: {"username": "steve", "plan": "Plus", "tier": 2})
    vpn.main(["account"])
    vpn.main(["account", "--json"])
    monkeypatch.setattr(vpn, "account", lambda: None)
    vpn.main(["account"])
    assert capsys.readouterr().out.splitlines() == [
        "steve (Plus)", '{"username": "steve", "plan": "Plus", "tier": 2}', "Signed out"]


def test_main_settings_json(files, capsys):
    vpn.main(["settings", "--json"])
    assert json.loads(capsys.readouterr().out)["netshield"] == 1


def test_main_settings_text(files, capsys):
    vpn.main(["settings"])
    assert capsys.readouterr().out.splitlines() == [
        "netshield: 1", "kill_switch: 0", "port_forwarding: False", "dns: proton"]


def test_main_help(capsys):
    vpn.main(["help"])
    assert capsys.readouterr().out.startswith("Proton VPN, the short way.")


def test_main_dispatches_set_dns_and_forward(monkeypatch):
    calls = []
    monkeypatch.setattr(vpn, "set_dns", lambda choice: calls.append(("dns", choice)))
    monkeypatch.setattr(vpn, "set_setting", lambda name, value: calls.append((name, value)))
    monkeypatch.setattr(vpn, "forward", lambda: calls.append("forward"))
    monkeypatch.setattr(vpn, "signin_from_stdin", lambda: calls.append("signin"))
    vpn.main(["dns", "Google"])
    vpn.main(["set", "netshield", "off"])
    vpn.main(["forward"])
    vpn.main(["signin", "--stdin"])
    assert calls == [("dns", "google"), ("netshield", "off"), "forward", "signin"]


def test_main_servers(server_list, capsys):
    vpn.main(["servers", "swiss"])
    assert capsys.readouterr().out.splitlines() == [
        "Zurich", "  CH#1        10%  ", "  CH#2        10%  p2p streaming"]

    vpn.main(["servers", "--json", "sc", "swiss"])
    (city,) = json.loads(capsys.readouterr().out)
    assert [s["name"] for s in city["servers"]] == ["IS-CH#1"]

    vpn.main(["servers", "--json", "atlantis"])
    assert json.loads(capsys.readouterr().out) == []


def test_main_list(server_list, capsys):
    vpn.main(["list", "swe"])
    assert capsys.readouterr().out == "SE  Sweden  (1 servers)\n"

    vpn.main(["ls", "--json", "swiss"])
    assert json.loads(capsys.readouterr().out)[0]["code"] == "CH"

    vpn.main(["list", "--alfred", "swiss"])
    assert json.loads(capsys.readouterr().out)["items"][0]["arg"] == "CH"


def test_main_reads_sys_argv(files, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["vpn", "status"])
    vpn.main()
    assert capsys.readouterr().out == "Disconnected\n"


def test_set_dns_provider_while_connected(files, lock, proton, monkeypatch):
    monkeypatch.setattr(vpn, "status", connected)
    vpn.set_dns("cloudflare")
    assert proton == [("run", "disconnect"),
                      ("run", "config", "set", "custom-dns", "on", "--dns", "1.1.1.1,1.0.0.1"),
                      ("connect", "CH#1")]


def test_set_dns_proton_while_disconnected(files, lock, proton):
    vpn.set_dns("proton")
    assert proton == [("run", "config", "set", "custom-dns", "off")]


def test_set_dns_rejects_unknown_choices(files, lock, proton):
    with pytest.raises(SystemExit, match="unknown DNS 'bing'"):
        vpn.set_dns("bing")
    assert proton == []


def test_set_setting(files, lock, proton, monkeypatch):
    vpn.set_setting("netshield", "off")
    assert proton == [("config", "set", "netshield", "off")]


def test_set_kill_switch_reconnects_when_connected(files, lock, proton, monkeypatch):
    monkeypatch.setattr(vpn, "status", connected)
    vpn.set_setting("kill-switch", "standard")
    assert proton == [("run", "disconnect"), ("run", "config", "set", "kill-switch", "standard"),
                      ("connect", "CH#1")]

    proton.clear()
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Disconnected"})
    vpn.set_setting("kill-switch", "off")
    assert proton == [("config", "set", "kill-switch", "off")]


def test_run_protonvpn(monkeypatch):
    import subprocess
    ran = []
    codes = iter([0, 3])
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: ran.append(cmd) or types.SimpleNamespace(
        returncode=next(codes)))
    vpn.run_protonvpn("disconnect")
    assert ran == [[sys.executable, "-m", "proton.vpn.macos.cli", "disconnect"]]
    with pytest.raises(SystemExit) as exit:
        vpn.run_protonvpn("disconnect")
    assert exit.value.code == 3


def test_protonvpn_refuses_to_connect_before_setup(monkeypatch):
    monkeypatch.setattr(privileged, "is_set_up", lambda: False)
    with pytest.raises(SystemExit, match="vpn setup"):
        vpn.protonvpn("connect")


def test_protonvpn_runs_proton_cli_locked(monkeypatch):
    import contextlib
    import proton.vpn.cli
    from proton.vpn.macos import cli
    events = []
    monkeypatch.setattr(privileged, "is_set_up", lambda: True)
    monkeypatch.setattr(cli, "install", lambda: events.append("install"))
    monkeypatch.setattr(cli, "locked", lambda: contextlib.nullcontext(events.append("locked")))
    monkeypatch.setattr(proton.vpn.cli, "main", lambda **kw: events.append(kw))
    monkeypatch.setattr(sys, "argv", ["vpn"])
    vpn.protonvpn("connect", "--p2p")
    assert events == ["install", "locked", {"allow_concurrency": True, "cli_args": ["connect", "--p2p"]}]
    assert sys.argv[0] == "protonvpn"


def test_account(monkeypatch):
    import proton.vpn.core.api as api
    from proton.vpn.macos import cli
    monkeypatch.setattr(cli, "install", lambda: None)

    class FakeAPI:
        logged_in = True
        account_name = "steve"
        account_data = types.SimpleNamespace(plan_title="Plus", max_tier=2)

        def __init__(self, _metadata):
            pass

        def is_user_logged_in(self):
            return FakeAPI.logged_in

    monkeypatch.setattr(api, "ProtonVPNAPI", FakeAPI)
    monkeypatch.setattr(api, "ClientTypeMetadata", lambda **kw: kw)
    assert vpn.account() == {"username": "steve", "plan": "Plus", "tier": 2}
    FakeAPI.logged_in = False
    assert vpn.account() is None


class FakeSocket:
    reply = struct.pack("!BBHIHHI", 0, 129, 0, 0, 0, 4242, 60)
    sent = []

    def __init__(self, *args):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, _timeout):
        pass

    def sendto(self, data, address):
        FakeSocket.sent.append((data, address))

    def recvfrom(self, _size):
        return FakeSocket.reply, (vpn.NAT_PMP_GATEWAY, 5351)


def test_nat_pmp_map(monkeypatch):
    monkeypatch.setattr(socket, "socket", FakeSocket)
    assert vpn.nat_pmp_map("udp") == 4242
    data, address = FakeSocket.sent[-1]
    assert struct.unpack("!BBHHHI", data) == (0, 1, 0, 0, 0, 60)
    assert address == ("10.2.0.1", 5351)
    vpn.nat_pmp_map("tcp")
    assert struct.unpack("!BBHHHI", FakeSocket.sent[-1][0])[1] == 2


def test_nat_pmp_map_error(monkeypatch):
    monkeypatch.setattr(socket, "socket", FakeSocket)
    monkeypatch.setattr(FakeSocket, "reply", struct.pack("!BBHIHHI", 0, 129, 2, 0, 0, 0, 0))
    with pytest.raises(OSError, match="NAT-PMP error 2"):
        vpn.nat_pmp_map("udp")


class StopLoop(Exception):
    pass


def test_forward_writes_the_port_and_keeps_renewing(files, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected"})
    monkeypatch.setattr(vpn, "settings", lambda: {"port_forwarding": True})
    monkeypatch.setattr(vpn, "nat_pmp_map", lambda protocol: 4242)
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise StopLoop

    monkeypatch.setattr(vpn.time, "sleep", sleep)
    with pytest.raises(StopLoop):
        vpn.forward()
    assert (tmp_path / "forwarded_port").read_text() == "4242"
    assert capsys.readouterr().out == "Forwarded port 4242\n"


def test_forward_reports_errors_and_stops_when_disconnected(files, monkeypatch, capsys):
    states = iter([{"state": "Connected"}, {"state": "Dropped"}])
    monkeypatch.setattr(vpn, "status", lambda: next(states))
    monkeypatch.setattr(vpn, "settings", lambda: {"port_forwarding": True})

    def refuse(protocol):
        raise OSError("timed out")

    monkeypatch.setattr(vpn, "nat_pmp_map", refuse)
    monkeypatch.setattr(vpn.time, "sleep", lambda _seconds: None)
    vpn.forward()
    assert "couldn't renew the forwarded port: timed out" in capsys.readouterr().err


def test_forwarded_port_path_is_under_the_temp_dir(monkeypatch, tmp_path):
    import tempfile
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    assert vpn.forwarded_port_path() == tmp_path / "Proton" / "VPN" / "forwarded_port"


def fake_pty(monkeypatch, chunks, status=0):
    """A signin process that prints the given chunks, recording what's written to it."""
    import os
    import pty
    import select
    written = []
    remaining = iter(chunks)

    def read(_fd, _size):
        try:
            return next(remaining).encode()
        except StopIteration:
            raise OSError from None

    monkeypatch.setattr(pty, "fork", lambda: (123, 5))
    monkeypatch.setattr(select, "select", lambda *args: ([5], [], []))
    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "write", lambda _fd, data: written.append(data.decode()))
    monkeypatch.setattr(os, "waitpid", lambda pid, _flags: (pid, status))
    return written


def test_signin_from_stdin(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("steve\nsecret\n123456\n"))
    written = fake_pty(monkeypatch, ["Password:", "2FA Token:", "Successfully signed in as 'steve@proton.me'\n"])
    vpn.signin_from_stdin()
    assert written == ["secret\n", "123456\n"]
    assert capsys.readouterr().out.splitlines() == ["2fa", "ok steve@proton.me"]


def test_signin_from_stdin_reports_errors(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("steve\nwrong\n111111\n"))
    fake_pty(monkeypatch, ["Password:", "Invalid two-factor code\n2FA Token:", "Error: Invalid credentials\n"], status=1)
    vpn.signin_from_stdin()
    assert capsys.readouterr().out.splitlines() == ["2fa invalid", "error Invalid credentials"]


def test_signin_from_stdin_without_output(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("steve\nwrong\n"))
    fake_pty(monkeypatch, [], status=1)
    vpn.signin_from_stdin()
    assert capsys.readouterr().out == "error Sign in failed\n"


def test_country_codes_loads_proton_module():
    names = vpn._country_codes()
    assert names.get_country_name_by_code("CH") == "Switzerland"


def test_main_splits_alfreds_single_argument(monkeypatch):
    chosen = []
    monkeypatch.setattr(vpn, "set_dns", chosen.append)
    vpn.main(["dns cloudflare"])
    assert chosen == ["cloudflare"]
