import io
import json
import os
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


@pytest.mark.parametrize("argv", [["help"], ["--help"], ["-h"]])
def test_main_help(capsys, argv):
    vpn.main(argv)
    assert capsys.readouterr().out.startswith("Proton VPN on macOS: Proton's CLI, plus short commands")


def test_main_dispatches_set_dns_and_watch(monkeypatch):
    calls = []
    monkeypatch.setattr(vpn, "set_dns", lambda choice: calls.append(("dns", choice)))
    monkeypatch.setattr(vpn, "set_setting", lambda name, value: calls.append((name, value)))
    monkeypatch.setattr(vpn, "watch", lambda: calls.append("watch"))
    monkeypatch.setattr(vpn, "signin_from_stdin", lambda: calls.append("signin"))
    vpn.main(["dns", "Google"])
    vpn.main(["set", "netshield", "off"])
    vpn.main(["watch"])
    vpn.main(["signin", "--stdin"])
    assert calls == [("dns", "google"), ("netshield", "off"), "watch", "signin"]


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
    monkeypatch.setattr(vpn, "keep_watching", lambda: events.append("watch"))
    monkeypatch.setattr(vpn, "drop_dead_tunnel", lambda: events.append("drop"))
    vpn.protonvpn("connect", "--p2p")
    assert events == ["install", "locked", "drop", {"allow_concurrency": True, "cli_args": ["connect", "--p2p"]},
                      "watch"]
    events.clear()
    vpn.protonvpn("signout")
    assert "watch" not in events and "drop" not in events
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
        return FakeSocket.reply, (vpn.TUNNEL_GATEWAY, 5351)


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


@pytest.fixture
def watching(files, monkeypatch):
    """A connection to watch: alive, with port forwarding on, and sleeps recorded."""
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected", "server": "CH#1"})
    monkeypatch.setattr(vpn, "settings", lambda: {"port_forwarding": True})
    monkeypatch.setattr(vpn, "tunnel_alive", lambda: True)
    monkeypatch.setattr(vpn, "nat_pmp_map", lambda protocol: 4242)
    sleeps = []
    monkeypatch.setattr(vpn.time, "sleep", sleeps.append)
    return sleeps


def stop_after(monkeypatch, count, sleeps):
    """Has sleep stop watch's loop after it's slept count times."""
    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == count:
            raise StopLoop
    monkeypatch.setattr(vpn.time, "sleep", sleep)


def test_watch_writes_the_port_and_renews_it_well_inside_the_minute(watching, monkeypatch, tmp_path, capsys):
    clock = iter([0, 0, 5, 10, 45, 45])
    monkeypatch.setattr(vpn.time, "time", lambda: next(clock))
    renewals = []
    monkeypatch.setattr(vpn, "forward_port", lambda: renewals.append("renew") or 45)
    stop_after(monkeypatch, 4, watching)
    with pytest.raises(StopLoop):
        vpn.watch()
    assert renewals == ["renew", "renew"]
    assert watching == [5, 5, 5, 5]
    assert (tmp_path / "watching").exists()


def test_watch_stops_when_disconnected_and_clears_its_files(watching, monkeypatch, tmp_path):
    states = iter([{"state": "Connected", "server": "CH#1"}, {"state": "Disconnected"}])
    monkeypatch.setattr(vpn, "status", lambda: next(states))
    vpn.watch()
    assert watching == [5]
    assert not (tmp_path / "forwarded_port").exists()
    assert not (tmp_path / "watching").exists()


def test_watch_clears_the_port_when_forwarding_stops(watching, monkeypatch, tmp_path):
    states = iter([{"state": "Connected", "server": "CH#1", "p2p": False}, {"state": "Disconnected"}])
    monkeypatch.setattr(vpn, "status", lambda: next(states))
    monkeypatch.setattr(vpn, "forward_port", lambda: pytest.fail("not a P2P server"))
    (tmp_path / "forwarded_port").write_text("4242")
    vpn.watch()
    assert not (tmp_path / "forwarded_port").exists()


def test_watch_reconnects_after_three_failed_checks(watching, monkeypatch):
    monkeypatch.setattr(vpn, "tunnel_alive", lambda: False)
    monkeypatch.setattr(vpn, "settings", lambda: {"port_forwarding": False})
    monkeypatch.setattr(vpn, "network_up", lambda: True)
    reconnects = []
    monkeypatch.setattr(vpn, "reconnect", reconnects.append)
    stop_after(monkeypatch, 4, watching)
    with pytest.raises(StopLoop):
        vpn.watch()
    # Fails twice, reconnects on the third, then counts again from nothing.
    assert reconnects == [{"state": "Connected", "server": "CH#1"}]


def test_watch_reconnects_a_dropped_tunnel_and_waits_for_a_network(watching, monkeypatch):
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Dropped", "server": "CH#1"})
    monkeypatch.setattr(vpn, "tunnel_alive", lambda: pytest.fail("no tunnel to check"))
    networks = iter([False, True])
    monkeypatch.setattr(vpn, "network_up", lambda: next(networks))
    reconnects = []
    monkeypatch.setattr(vpn, "reconnect", reconnects.append)
    stop_after(monkeypatch, 4, watching)
    with pytest.raises(StopLoop):
        vpn.watch()
    assert len(reconnects) == 1


def test_forward_port_writes_a_new_port(files, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(vpn, "nat_pmp_map", lambda protocol: 4242)
    assert vpn.forward_port() == 45
    assert (tmp_path / "forwarded_port").read_text() == "4242"
    assert capsys.readouterr().out == "Forwarded port 4242\n"


def test_forward_port_touches_the_same_port(files, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(vpn, "nat_pmp_map", lambda protocol: 4242)
    port = tmp_path / "forwarded_port"
    port.write_text("4242")
    os.utime(port, (0, 0))
    vpn.forward_port()
    assert port.stat().st_mtime > 0
    assert capsys.readouterr().out == ""


def test_forward_port_tries_again_soon_after_an_error(files, monkeypatch, capsys):
    def refuse(protocol):
        raise OSError("timed out")

    monkeypatch.setattr(vpn, "nat_pmp_map", refuse)
    assert vpn.forward_port() == 2
    assert "couldn't renew the forwarded port: timed out" in capsys.readouterr().err


class FakeDNS(FakeSocket):
    replies = []

    def recvfrom(self, _size):
        reply = FakeDNS.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply, (vpn.TUNNEL_GATEWAY, 53)


def test_tunnel_alive_asks_protons_dns_at_the_far_end(monkeypatch):
    monkeypatch.setattr(socket, "socket", FakeDNS)
    FakeDNS.replies = [TimeoutError(), b"answer"]
    assert vpn.tunnel_alive()
    data, address = FakeSocket.sent[-1]
    assert address == ("10.2.0.1", 53)
    assert b"\x06proton\x02me\x00" in data
    FakeDNS.replies = [TimeoutError(), TimeoutError()]
    assert not vpn.tunnel_alive()


def test_drop_dead_tunnel(dead_tunnel_check, monkeypatch):
    calls = []
    monkeypatch.setattr(vpn, "run_protonvpn", lambda *args: calls.append(args))
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected"})
    monkeypatch.setattr(vpn, "tunnel_alive", lambda: True)
    vpn.drop_dead_tunnel()
    assert calls == []
    monkeypatch.setattr(vpn, "tunnel_alive", lambda: False)
    vpn.drop_dead_tunnel()
    assert calls == [("disconnect",)]
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Disconnected"})
    vpn.drop_dead_tunnel()
    assert calls == [("disconnect",)]


def test_similar_server(server_list):
    servers = json.loads((server_list / "serverlist.json").read_text())
    servers["LogicalServers"] += [
        {"Name": "CH#4", "ExitCountry": "CH", "Features": 0, "City": "Geneva", "Status": 1, "Tier": 2, "Score": 1},
        {"Name": "CH#5", "ExitCountry": "CH", "Features": 0, "City": "Zurich", "Status": 0, "Tier": 2, "Score": 1},
        {"Name": "CH#6", "ExitCountry": "CH", "Features": 0, "City": "Zurich", "Status": 1, "Tier": 2, "Score": 3},
        {"Name": "CH#7", "ExitCountry": "CH", "Features": 0, "City": "Zurich", "Status": 1, "Tier": 2, "Score": 2},
        {"Name": "CH#8", "ExitCountry": "CH", "Features": 4, "City": "Zurich", "Status": 1, "Tier": 2, "Score": 1},
        {"Name": "CH-FREE#1", "ExitCountry": "CH", "Features": 0, "City": "Zurich", "Status": 1, "Tier": 0, "Score": 5},
    ]
    (server_list / "serverlist.json").write_text(json.dumps(servers))
    # Same city and modes first, least busy first, never one that's down.
    assert vpn.similar_server("CH#1") == "CH#7"
    assert vpn.similar_server("CH#7") == "CH#1"
    assert vpn.similar_server("CH#4") == "CH#1"
    # Free servers only get other free servers.
    assert vpn.similar_server("CH-FREE#1") is None
    assert vpn.similar_server("CH#2") == "CH#8"
    assert vpn.similar_server("CH#3") is None
    assert vpn.similar_server("XX#1") is None


def test_network_up(monkeypatch):
    import subprocess
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: calls.append(args) or types.SimpleNamespace(returncode=0))
    assert vpn.network_up()
    assert calls == [["/sbin/route", "-n", "get", "default"]]


@pytest.fixture
def reconnecting(monkeypatch):
    import contextlib
    from proton.vpn.macos import cli
    calls = []
    monkeypatch.setattr(cli, "locked", lambda: contextlib.nullcontext(calls.append("locked")))
    monkeypatch.setattr(vpn, "run_protonvpn", lambda *args: calls.append(args))
    monkeypatch.setattr(vpn, "tunnel_alive", lambda: False)
    return calls


def test_reconnect_to_a_similar_server(reconnecting, monkeypatch, capsys):
    current = {"state": "Connected", "server": "CH#1", "code": "CH", "country": "Switzerland"}
    monkeypatch.setattr(vpn, "status", lambda: dict(current, load=50))
    monkeypatch.setattr(vpn, "similar_server", lambda name: "CH#4")
    vpn.reconnect(current)
    assert reconnecting == ["locked", ("connect", "CH#4")]
    assert capsys.readouterr().out == "The connection to CH#1 stopped working; connecting to CH#4\n"


def test_reconnect_to_the_country_without_a_similar_server(reconnecting, monkeypatch, capsys):
    current = {"state": "Dropped", "server": "CH#1", "code": "CH", "country": "Switzerland"}
    monkeypatch.setattr(vpn, "status", lambda: current)
    monkeypatch.setattr(vpn, "similar_server", lambda name: None)
    vpn.reconnect(current)
    assert reconnecting[1:] == [("connect", "--country", "CH")]
    assert capsys.readouterr().out.endswith("connecting to Switzerland\n")
    reconnecting.clear()
    vpn.reconnect({"state": "Dropped", "server": "CH#1"})
    assert reconnecting[1:] == [("connect",)]


@pytest.mark.parametrize("latest, alive", [
    ({"state": "Disconnected"}, False),
    ({"state": "Connected", "server": "SE#1"}, False),
    ({"state": "Connected", "server": "CH#1"}, True),
])
def test_reconnect_leaves_a_connection_that_changed_or_came_back(reconnecting, monkeypatch, latest, alive):
    monkeypatch.setattr(vpn, "status", lambda: latest)
    monkeypatch.setattr(vpn, "tunnel_alive", lambda: alive)
    vpn.reconnect({"state": "Connected", "server": "CH#1"})
    assert reconnecting == ["locked"]


def test_forwarding_needs_a_p2p_connection_with_port_forwarding_on(monkeypatch):
    monkeypatch.setattr(vpn, "settings", lambda: {"port_forwarding": True})
    assert vpn.forwarding({"state": "Connected", "p2p": True})
    assert vpn.forwarding({"state": "Connected"})
    assert not vpn.forwarding({"state": "Connected", "p2p": False})
    assert not vpn.forwarding({"state": "Dropped", "p2p": True})
    monkeypatch.setattr(vpn, "settings", lambda: {"port_forwarding": False})
    assert not vpn.forwarding({"state": "Connected", "p2p": True})


@pytest.fixture
def launchctl(monkeypatch, tmp_path):
    """Records launchctl, with the LaunchAgent under tmp_path."""
    import subprocess
    calls = []
    monkeypatch.setattr(vpn.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: calls.append(args[1:]))
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected"})
    return calls


def agent(tmp_path):
    import plistlib
    return plistlib.loads((tmp_path / "Library" / "LaunchAgents" / f"{vpn.WATCHER}.plist").read_bytes())


def test_keep_watching_adds_the_launch_agent_and_starts_it(launchctl, watcher, monkeypatch, tmp_path):
    command = tmp_path / "bin" / "protonvpn"
    command.parent.mkdir()
    command.touch()
    monkeypatch.setattr(vpn, "COMMAND", str(command))
    domain = f"gui/{os.getuid()}"
    watcher()
    assert agent(tmp_path) == {"Label": vpn.WATCHER, "ProgramArguments": [str(command), "watch"]}
    assert launchctl == [["bootout", f"{domain}/{vpn.WATCHER}"],
                         ["bootstrap", domain, str(tmp_path / "Library" / "LaunchAgents" / f"{vpn.WATCHER}.plist")],
                         ["kickstart", f"{domain}/{vpn.WATCHER}"]]

    # Then it only starts it, while the command it runs is there.
    launchctl.clear()
    monkeypatch.setattr(vpn, "COMMAND", "/elsewhere/protonvpn")
    watcher()
    assert agent(tmp_path)["ProgramArguments"][0] == str(command)
    assert [call[0] for call in launchctl] == ["bootstrap", "kickstart"]


def test_keep_watching_runs_the_module_without_a_protonvpn_command(launchctl, watcher, monkeypatch, tmp_path):
    monkeypatch.setattr(vpn, "COMMAND", "/src/vpn.py")
    watcher()
    assert agent(tmp_path)["ProgramArguments"] == [sys.executable, "-m", "proton.vpn.macos.vpn", "watch"]


def test_keep_watching_only_while_connected(launchctl, watcher, monkeypatch):
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Disconnected"})
    watcher()
    assert launchctl == []


def test_report_forwarded_port_waits_for_it(files, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected"})
    monkeypatch.setattr(vpn, "settings", lambda: {"port_forwarding": True})
    port = tmp_path / "forwarded_port"
    monkeypatch.setattr(vpn.time, "sleep", lambda seconds: port.write_text("4242"))
    vpn.report_forwarded_port()
    assert capsys.readouterr().out == "Forwarded port 4242\n"


def test_report_forwarded_port_gives_up(files, monkeypatch, capsys):
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected"})
    monkeypatch.setattr(vpn, "settings", lambda: {"port_forwarding": True})
    clock = iter(range(0, 100, 10))
    monkeypatch.setattr(vpn.time, "time", lambda: next(clock))
    monkeypatch.setattr(vpn.time, "sleep", lambda seconds: None)
    vpn.report_forwarded_port()
    assert capsys.readouterr().out.startswith("protonvpn: no forwarded port yet")


def test_report_forwarded_port_only_when_forwarding(files, monkeypatch, capsys):
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Disconnected"})
    vpn.report_forwarded_port()
    assert capsys.readouterr().out == ""


def test_renew_stalled_watching(files, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(vpn, "keep_watching", lambda: calls.append("keep"))
    current = {"state": "Connected"}
    vpn.renew_stalled_watching(current)
    heartbeat = tmp_path / "watching"
    heartbeat.touch()
    vpn.renew_stalled_watching(current)
    os.utime(heartbeat, (0, 0))
    vpn.renew_stalled_watching(current)
    vpn.renew_stalled_watching({"state": "Disconnected"})
    assert calls == ["keep", "keep"]


def test_main_ip(monkeypatch, capsys):
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected", "ip": "1.2.3.4"})
    vpn.main(["ip"])
    assert capsys.readouterr().out == "1.2.3.4\n"
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Disconnected"})
    with pytest.raises(SystemExit, match="not connected"):
        vpn.main(["ip"])


def test_main_port(monkeypatch, capsys):
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected", "port": 39020})
    vpn.main(["port"])
    assert capsys.readouterr().out == "39020\n"
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Connected"})
    with pytest.raises(SystemExit, match="no forwarded port"):
        vpn.main(["port"])


def test_main_status_restarts_stalled_forwarding(files, monkeypatch):
    calls = []
    monkeypatch.setattr(vpn, "renew_stalled_watching", calls.append)
    vpn.main(["status"])
    assert calls == [{"state": "Disconnected"}]


def test_set_port_forwarding_on_reports_the_port(files, lock, proton, monkeypatch):
    calls = []
    monkeypatch.setattr(vpn, "report_forwarded_port", lambda: calls.append("report"))
    vpn.set_setting("port-forwarding", "on")
    vpn.set_setting("port-forwarding", "off")
    assert calls == ["report"]


def test_watchers_files_are_under_the_temp_dir(monkeypatch, tmp_path):
    import tempfile
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    assert vpn.forwarded_port_path() == tmp_path / "Proton" / "VPN" / "forwarded_port"
    assert vpn.watched_path() == tmp_path / "Proton" / "VPN" / "watching"


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


def test_country_codes_needs_protons_module(monkeypatch, tmp_path):
    import proton.vpn
    monkeypatch.setattr(proton.vpn, "__path__", [str(tmp_path)])
    with pytest.raises(RuntimeError, match="country_codes module is missing"):
        vpn._country_codes()


def test_in_terminal_runs_a_protonvpn_command_in_terminal(monkeypatch):
    ran = []
    monkeypatch.setattr("shutil.which", lambda name: "/opt/homebrew/bin/protonvpn")
    monkeypatch.setattr("subprocess.run", lambda args, check: ran.append(args))
    vpn.in_terminal('read -p "Proton username: " username && {protonvpn} signin "$username"')
    (args,) = ran
    assert args[:2] == ["/usr/bin/osascript", "-e"]
    assert args[2] == ('tell application "Terminal" to do script '
                       '"read -p \\"Proton username: \\" username && /opt/homebrew/bin/protonvpn signin \\"$username\\""')
    assert args[3:] == ["-e", 'tell application "Terminal" to activate']


def test_in_terminal_finds_protonvpn_beside_vpn(monkeypatch):
    ran = []
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr(sys, "argv", ["/opt/vpn tools/bin/vpn"])
    monkeypatch.setattr("subprocess.run", lambda args, check: ran.append(args))
    vpn.in_terminal("{protonvpn} setup")
    assert "'/opt/vpn tools/bin/protonvpn' setup" in ran[0][2]


def test_main_opens_terminal_for_alfred_to_sign_in(monkeypatch):
    opened = []
    monkeypatch.setattr(vpn, "in_terminal", opened.append)
    vpn.main(["signin --terminal"])
    assert opened == ['read -p "Proton username: " username && {protonvpn} signin "$username"']


def test_main_sets_up_in_a_dialog_for_alfred(monkeypatch):
    from proton.vpn.macos import privileged
    calls = []
    monkeypatch.setattr(privileged, "setup_in_dialog", lambda: calls.append("dialog"))
    vpn.main(["setup --dialog"])
    assert calls == ["dialog"]


def test_main_status_says_when_the_tools_are_out_of_date(files, monkeypatch, capsys):
    from proton.vpn.macos import privileged
    monkeypatch.setattr(privileged, "outdated_tools", lambda: ["bash", "wg"])
    vpn.main(["status"])
    assert capsys.readouterr().out == "Disconnected\nHomebrew has newer bash, wg: run protonvpn setup to use them\n"
    vpn.main(["status", "--json"])
    assert json.loads(capsys.readouterr().out) == {"state": "Disconnected", "outdated_tools": ["bash", "wg"]}


def test_alfred_offers_to_refresh_out_of_date_tools(files, monkeypatch, capsys):
    from proton.vpn.macos import privileged
    monkeypatch.setattr(privileged, "outdated_tools", lambda: ["bash"])
    strong, _ = vpn.commands("", {"state": "Disconnected"})
    assert strong[0]["title"] == "Refresh WireGuard tools"
    assert strong[0]["arg"] == "setup --dialog"
    assert strong[0]["autocomplete"] == "refresh"
    assert strong[0]["variables"] == {"notice": "Refreshing WireGuard tools…"}
    monkeypatch.setattr(vpn, "status", lambda: {"state": "Disconnected"})
    vpn.alfred([], "")
    assert [item["title"] for item in json.loads(capsys.readouterr().out)["items"]][:2] == [
        "Disconnected", "Refresh WireGuard tools"]
    monkeypatch.setattr(privileged, "outdated_tools", lambda: [])
    strong, _ = vpn.commands("", {"state": "Disconnected"})
    assert strong[0]["title"] != "Refresh WireGuard tools"


@pytest.mark.parametrize("argv", [
    ["connect", "--country", "CH"], ["config", "set", "netshield", "off"], ["info"], ["countries"],
    ["signin", "steve"], ["servers"], ["status", "--verbose"], ["-v"],
])
def test_main_passes_protons_commands_to_its_cli(monkeypatch, argv):
    from proton.vpn.macos import cli
    ran = []
    monkeypatch.setattr(cli, "main", lambda: ran.append(list(sys.argv)))
    vpn.main(argv)
    assert ran == [["protonvpn", *argv]]


def test_main_keeps_its_own_commands(monkeypatch):
    assert not vpn.is_protons([], [])
    assert not vpn.is_protons(["swiss"], [])
    assert not vpn.is_protons(["servers", "ch"], ["--json"])
    assert not vpn.is_protons(["signin"], ["--stdin"])
    assert not vpn.is_protons(["setup", "wade"], ["--user"])
    assert vpn.is_protons(["connect"], ["--help"])


def test_main_setup_signs_in_from_a_terminal(monkeypatch):
    calls = []
    monkeypatch.setattr(privileged, "setup", lambda user: calls.append(("setup", user)))
    monkeypatch.setattr(vpn, "protonvpn", lambda *args: calls.append(args))
    monkeypatch.setattr(vpn.os, "geteuid", lambda: 501)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(vpn, "account", lambda: None)
    monkeypatch.setattr("builtins.input", lambda prompt: " steve ")
    vpn.main(["setup"])
    assert calls == [("setup", None), ("signin", "steve")]

    calls.clear()
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    vpn.main(["setup"])
    assert calls == [("setup", None)]

    calls.clear()
    monkeypatch.setattr(vpn, "account", lambda: {"username": "steve"})
    vpn.main(["setup"])
    assert calls == [("setup", None)]


def test_signin_from_stdin_runs_protons_signin_in_the_child(monkeypatch):
    import os
    import pty
    monkeypatch.setattr(sys, "stdin", io.StringIO("steve\nsecret\n"))
    monkeypatch.setattr(pty, "fork", lambda: (0, 5))
    execs = []

    class Execed(Exception):
        pass

    def execv(path, args):
        execs.append(args)
        raise Execed

    monkeypatch.setattr(os, "execv", execv)
    with pytest.raises(Execed):
        vpn.signin_from_stdin()
    assert execs == [[sys.executable, "-m", "proton.vpn.macos.cli", "signin", "steve", "--totp"]]
