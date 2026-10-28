import asyncio
import json
import subprocess
import types

import pytest

# Imported up front, before the guard below: Proton's modules run a command or two at import time.
from proton.vpn.macos import cli, vpn, wireguard  # noqa: F401


@pytest.fixture(autouse=True)
def no_real_commands(monkeypatch):
    """Anything that would run a real command (sudo, pfctl, security...) fails unless a test fakes it."""
    def refuse(*args, **kwargs):
        raise AssertionError(f"unexpected real command: {args!r}")

    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", refuse)
    monkeypatch.setattr("os.execv", refuse)


KEEP_WATCHING = vpn.keep_watching
DROP_DEAD_TUNNEL = vpn.drop_dead_tunnel


@pytest.fixture(autouse=True)
def no_watching(monkeypatch):
    """
    Commands that connect or change settings don't start watching, or check the tunnel first,
    unless a test asks; see watcher and dead_tunnel_check.
    """
    monkeypatch.setattr(vpn, "keep_watching", lambda: None)
    monkeypatch.setattr(vpn, "drop_dead_tunnel", lambda: None)


@pytest.fixture
def watcher(monkeypatch):
    """The real keep_watching."""
    monkeypatch.setattr(vpn, "keep_watching", KEEP_WATCHING)
    return KEEP_WATCHING


@pytest.fixture
def dead_tunnel_check(monkeypatch):
    """The real drop_dead_tunnel."""
    monkeypatch.setattr(vpn, "drop_dead_tunnel", DROP_DEAD_TUNNEL)
    return DROP_DEAD_TUNNEL


@pytest.fixture
def files(tmp_path, monkeypatch):
    """The files `vpn` reads, redirected to tmp_path; returns the cache directory."""
    cache = tmp_path / "cache"
    (cache / "connection").mkdir(parents=True)
    monkeypatch.setattr(vpn, "SERVER_LIST", cache / "serverlist.json")
    monkeypatch.setattr(vpn, "CONNECTION", cache / "connection" / "connection_persistence.json")
    monkeypatch.setattr(vpn, "EXIT_IP", cache / "connection" / "exit_ip")
    monkeypatch.setattr(vpn, "WG_CONFIG", cache / "connection" / "proton.conf")
    monkeypatch.setattr(vpn, "SETTINGS", tmp_path / "settings.json")
    monkeypatch.setattr(vpn, "FLAGS", None)
    monkeypatch.setattr(vpn, "forwarded_port_path", lambda: tmp_path / "forwarded_port")
    monkeypatch.setattr(vpn, "watched_path", lambda: tmp_path / "watching")
    monkeypatch.setattr(vpn, "tunnel_device", lambda: None)
    names = {"CH": "Switzerland", "SE": "Sweden", "US": "United States"}
    monkeypatch.setattr(vpn, "_country_codes", lambda: types.SimpleNamespace(
        get_country_name_by_code=lambda code: names.get(code)))
    return cache


@pytest.fixture
def server_list(files):
    def logical(name, country="CH", features=0, city="Zurich", **extra):
        return {"Name": name, "ExitCountry": country, "Features": features, "City": city, "Status": 1,
                "Load": 10, "Tier": 2, **extra}

    (files / "serverlist.json").write_text(json.dumps({"MaxTier": 2, "LogicalServers": [
        logical("CH#1"),
        logical("CH#2", features=4 | 8),
        logical("CH#3", features=2),
        logical("IS-CH#1", features=1),
        logical("SE#1", country="SE", city="Stockholm", HostCountry="DK"),
        logical("US#1", country="US", city="Miami"),
    ]}))
    return files
