import json
import os
import time

import pytest

from proton.vpn.macos import vpn


def persist(files, server="CH#1", connection_id="abc"):
    (files / "connection" / "connection_persistence.json").write_text(json.dumps(
        {"connection_id": connection_id, "server": {"server_name": server, "server_ip": "185.1.2.3"}}))


def test_status_disconnected_without_files(files):
    assert vpn.status() == {"state": "Disconnected"}


def test_status_connected(server_list, monkeypatch):
    persist(server_list)
    (server_list / "connection" / "exit_ip").write_text("1.2.3.4\n")
    monkeypatch.setattr(vpn, "tunnel_device", lambda: "utun4")
    assert vpn.status() == {"state": "Connected", "server": "CH#1", "entry_ip": "185.1.2.3", "interface": "utun4",
                            "code": "CH", "country": "Switzerland", "city": "Zurich", "load": 10, "p2p": False,
                            "ip": "1.2.3.4"}


def test_status_dropped_when_the_tunnel_is_gone(server_list):
    persist(server_list)
    status = vpn.status()
    assert status["state"] == "Dropped"
    assert "ip" not in status


def test_status_reports_the_forwarded_port(server_list, monkeypatch, tmp_path):
    persist(server_list)
    vpn.SETTINGS.write_text(json.dumps({"features": {"port_forwarding": True}}))
    (tmp_path / "forwarded_port").write_text("5555\n")
    monkeypatch.setattr(vpn, "tunnel_device", lambda: "utun4")
    assert vpn.status()["port"] == 5555


def test_status_ignores_a_missing_forwarded_port(server_list, monkeypatch):
    persist(server_list)
    vpn.SETTINGS.write_text(json.dumps({"features": {"port_forwarding": True}}))
    monkeypatch.setattr(vpn, "tunnel_device", lambda: "utun4")
    assert "port" not in vpn.status()


def test_status_connecting_when_a_fresh_config_is_for_another_connection(files):
    persist(files, connection_id="old")
    (files / "connection" / "proton.conf").write_text("# Connection new\n# Server CH#9\n[Interface]\n")
    assert vpn.status() == {"state": "Connecting", "server": "CH#9"}


def test_status_connecting_says_where(server_list):
    persist(server_list, connection_id="old")
    (server_list / "connection" / "proton.conf").write_text("# Connection new\n# Server SE#1\n[Interface]\n")
    assert vpn.status() == {"state": "Connecting", "server": "SE#1", "code": "SE", "country": "Sweden",
                            "city": "Stockholm", "load": 10, "p2p": False}


def test_status_not_connecting_when_the_config_is_old_or_matches(files):
    persist(files, connection_id="old")
    config = files / "connection" / "proton.conf"
    config.write_text("# Connection new\n# Server CH#9\n")
    stale = time.time() - 600
    os.utime(config, (stale, stale))
    assert vpn.status()["state"] == "Dropped"

    config.write_text("# Connection old\n# Server CH#1\n")
    assert vpn.status()["state"] == "Dropped"


def test_logicals_survive_a_corrupt_server_list(files):
    assert vpn.logicals() == []
    vpn.SERVER_LIST.write_text("{nope")
    assert vpn.logicals() == []


def test_countries_summarize_servers_and_features(server_list):
    found = {c["code"]: c for c in vpn.countries()}
    assert set(found) == {"CH", "SE", "US"}
    assert found["CH"]["servers"] == 2
    assert found["CH"]["name"] == "Switzerland"
    assert found["CH"]["aliases"] == ["swiss", "schweiz", "suisse"]
    assert found["CH"]["features"] == ["p2p", "securecore", "streaming", "tor"]
    assert ["p2p", "streaming"] in found["CH"]["combos"]
    assert found["SE"]["features"] == ["smartrouting"]


def test_countries_only_count_servers_on_the_accounts_plan(files):
    (files / "serverlist.json").write_text(json.dumps({"MaxTier": 0, "LogicalServers": [
        {"Name": "CH-FREE#1", "ExitCountry": "CH", "Features": 0, "Tier": 0},
        {"Name": "CH#1", "ExitCountry": "CH", "Features": 0, "Tier": 2},
        {"Name": "US#1", "ExitCountry": "US", "Features": 0, "Tier": 2},
    ]}))
    assert [(c["code"], c["servers"]) for c in vpn.countries()] == [("CH", 1)]


def test_country_name_falls_back_to_the_code(files):
    assert vpn.country_name("CH") == "Switzerland"
    assert vpn.country_name("ZZ") == "ZZ"


def test_servers_without_a_server_list(files):
    assert vpn.servers("CH") == []


def test_describe():
    assert vpn.describe({"state": "Disconnected"}) == "Disconnected"
    assert vpn.describe({"state": "Connecting", "server": "CH#1"}) == "Connecting to CH#1…"
    connected = {"state": "Connected", "server": "CH#1", "city": "Zurich", "country": "Switzerland",
                 "ip": "1.2.3.4", "port": 5555}
    assert vpn.describe(connected) == "Connected to CH#1 (Zurich, Switzerland), IP 1.2.3.4, port 5555"
    dropped = {"state": "Dropped", "server": "CH#1", "ip": "1.2.3.4"}
    assert vpn.describe(dropped) == "Dropped connection to CH#1"


def test_settings_defaults_and_values(files):
    assert vpn.settings() == {"netshield": 1, "kill_switch": 0, "port_forwarding": False, "dns": "proton"}
    vpn.SETTINGS.write_text(json.dumps({
        "killswitch": 2, "features": {"netshield": 0, "port_forwarding": True},
        "custom_dns": {"enabled": True, "ip_list": [{"ip": "1.1.1.1"}, "1.0.0.1"]}}))
    assert vpn.settings() == {"netshield": 0, "kill_switch": 2, "port_forwarding": True, "dns": "cloudflare"}


def test_dns_choice():
    assert vpn.dns_choice({}) == "proton"
    assert vpn.dns_choice({"enabled": True, "ip_list": ["8.8.8.8", "8.8.4.4"]}) == "google"
    assert vpn.dns_choice({"enabled": True, "ip_list": ["10.0.0.1"]}) == "custom"


@pytest.mark.parametrize("argv, expected", [
    (["--json"], {"state": "Disconnected"}),
    (["status", "--json"], {"state": "Disconnected"}),
])
def test_main_status_json(files, capsys, argv, expected):
    vpn.main(argv)
    assert json.loads(capsys.readouterr().out) == expected


