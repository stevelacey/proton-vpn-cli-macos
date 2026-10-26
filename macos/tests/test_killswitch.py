from proton.vpn.macos.killswitch import rules


def test_rules_let_the_tunnel_and_server_out_and_block_the_rest():
    lines = rules("185.1.2.3").splitlines()
    assert "pass out quick inet from 10.2.0.2 to any" in lines
    assert "pass out quick to 185.1.2.3" in lines
    assert lines[-1] == "block drop out quick all"


def test_rules_without_a_server():
    assert not [line for line in rules(None).splitlines() if line.startswith("pass out quick to ") and "{" not in line]


import asyncio
import types

import pytest

from proton.vpn.macos import killswitch, privileged
from proton.vpn.macos.killswitch import PfKillSwitch


@pytest.fixture
def helper(tmp_path, monkeypatch):
    """Fakes the root helper, recording its calls; the pf token lives in tmp_path."""
    class Calls(list):
        results = {}

    calls = Calls()
    results = calls.results
    results.update({"pf-load": types.SimpleNamespace(returncode=0, stderr="", stdout=""),
               "pf-enable": types.SimpleNamespace(returncode=0, stderr="pf enabled\nToken : 12345\n", stdout="")})
    monkeypatch.setattr(privileged, "run", lambda *args, stdin=None: calls.append((args, stdin)) or results.get(
        args[0], types.SimpleNamespace(returncode=0, stderr="", stdout="")))
    monkeypatch.setattr(killswitch, "_token_path", lambda: tmp_path / "pf-token")
    monkeypatch.setattr(killswitch, "_endpoint_from_config", lambda: None)
    return calls


def test_enable_loads_rules_and_keeps_the_token(helper, tmp_path):
    server = types.SimpleNamespace(server_ip="185.1.2.3")
    asyncio.run(PfKillSwitch().enable(server))
    assert [call[0] for call in helper] == [("pf-load",), ("pf-enable",)]
    assert "pass out quick to 185.1.2.3" in helper[0][1]
    assert (tmp_path / "pf-token").read_text() == "12345"
    assert killswitch.is_enabled()


def test_enable_again_only_reloads_the_rules(helper, tmp_path):
    (tmp_path / "pf-token").write_text("12345")
    asyncio.run(PfKillSwitch().enable(types.SimpleNamespace(server_ip="185.1.2.3"), permanent=True))
    assert [call[0] for call in helper] == [("pf-load",)]


def test_enable_without_a_server_uses_the_tunnel_config(helper, monkeypatch):
    monkeypatch.setattr(killswitch, "_endpoint_from_config", lambda: "9.9.9.9")
    asyncio.run(PfKillSwitch().enable())
    assert "pass out quick to 9.9.9.9" in helper[0][1]


def test_enable_fails_when_the_rules_wont_load(helper, tmp_path):
    helper.results["pf-load"] = types.SimpleNamespace(returncode=1, stderr="syntax error\n", stdout="")
    with pytest.raises(RuntimeError, match="syntax error"):
        asyncio.run(PfKillSwitch().enable())
    assert not killswitch.is_enabled()


def test_enable_without_a_token_in_the_output(helper, tmp_path):
    helper.results["pf-enable"] = types.SimpleNamespace(returncode=0, stderr="", stdout="")
    asyncio.run(PfKillSwitch().enable())
    assert (tmp_path / "pf-token").read_text() == ""


def test_disable_flushes_and_releases(helper, tmp_path):
    (tmp_path / "pf-token").write_text("12345\n")
    asyncio.run(PfKillSwitch().disable())
    assert [call[0] for call in helper] == [("pf-flush",), ("pf-release", "12345")]
    assert not killswitch.is_enabled()


def test_disable_without_a_reference_only_flushes(helper, tmp_path):
    (tmp_path / "pf-token").write_text("")
    asyncio.run(PfKillSwitch().disable())
    assert [call[0] for call in helper] == [("pf-flush",)]
    assert not (tmp_path / "pf-token").exists()


def test_disable_is_free_when_off(helper):
    asyncio.run(PfKillSwitch().disable())
    assert helper == []


def test_ipv6_leak_protection_is_a_no_op_and_backend_is_valid():
    switch = PfKillSwitch()
    asyncio.run(switch.enable_ipv6_leak_protection())
    asyncio.run(switch.disable_ipv6_leak_protection())
    assert PfKillSwitch._get_priority() == 100
    assert PfKillSwitch._validate()


def test_paths_live_under_protons_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(killswitch, "VPNExecutionEnvironment",
                        lambda: types.SimpleNamespace(path_cache=str(tmp_path)))
    assert killswitch._token_path() == tmp_path / "connection" / "pf-token"
    assert killswitch._endpoint_from_config() is None
    (tmp_path / "connection").mkdir()
    (tmp_path / "connection" / "proton.conf").write_text("[Peer]\nEndpoint = 1.2.3.4:51820\n")
    assert killswitch._endpoint_from_config() == "1.2.3.4"
    (tmp_path / "connection" / "proton.conf").write_text("[Peer]\n")
    assert killswitch._endpoint_from_config() is None
