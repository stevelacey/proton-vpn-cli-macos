import asyncio
import types
from ipaddress import IPv4Address, IPv6Address

import pytest
from proton.vpn.connection import events, states

from proton.vpn.macos import wireguard
from proton.vpn.macos.wireguard import WgQuickWireguard


class Dns:
    def __init__(self, ip, enabled=True):
        self.ip, self.enabled = ip, enabled

    @property
    def exploded(self):
        return self.ip.exploded


class CustomDns:
    def __init__(self, enabled=False, ips=()):
        self.enabled = enabled
        self.ip_list = [Dns(IPv4Address(ip) if "." in ip else IPv6Address(ip)) for ip in ips]

    def get_enabled_dns_list_based_on_ip_version(self, version):
        return [dns.ip for dns in self.ip_list if dns.enabled and isinstance(dns.ip, version)]


def connection(ipv6=False, server_ipv6=False, custom_dns=None):
    """A WgQuickWireguard without Proton's connection machinery, with stand-ins for what it reads."""
    wg = WgQuickWireguard.__new__(WgQuickWireguard)
    wg._unique_id = "abc"
    wg._vpnserver = types.SimpleNamespace(
        server_name="CH#1", server_ip="185.1.2.3", x25519pk="PUBKEY", has_ipv6_support=server_ipv6,
        wireguard_ports=types.SimpleNamespace(udp=[51820]), openvpn_ports=types.SimpleNamespace(tcp=[443]))
    wg._vpncredentials = types.SimpleNamespace(
        pubkey_credentials=types.SimpleNamespace(wg_private_key="PRIVATEKEY"))
    wg._settings = types.SimpleNamespace(ipv6=ipv6, custom_dns=custom_dns or CustomDns(),
                                         features="features")
    return wg


def test_generate_config_with_protons_dns():
    assert connection()._generate_config().splitlines() == [
        "# Connection abc", "# Server CH#1", "[Interface]", "PrivateKey = PRIVATEKEY",
        "Address = 10.2.0.2/32", "DNS = 10.2.0.1", "", "[Peer]", "PublicKey = PUBKEY",
        "AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = 185.1.2.3:51820"]


def test_generate_config_with_ipv6():
    config = connection(ipv6=True, server_ipv6=True)._generate_config()
    assert "Address = 10.2.0.2/32, 2a07:b944::2:2/128" in config
    assert "DNS = 10.2.0.1, 2a07:b944::2:1" in config


def test_ipv6_needs_the_server_and_the_setting():
    assert connection(ipv6=True, server_ipv6=True).enable_ipv6_support
    assert not connection(ipv6=True, server_ipv6=False).enable_ipv6_support
    assert not connection(ipv6=False, server_ipv6=True).enable_ipv6_support


def test_custom_dns_replaces_protons_without_adding_ipv6_dns():
    wg = connection(ipv6=True, server_ipv6=True, custom_dns=CustomDns(True, ["1.1.1.1", "1.0.0.1"]))
    config = wg._generate_config()
    assert "DNS = 1.1.1.1, 1.0.0.1\n" in config
    assert "2a07:b944::2:1" not in config


def test_dns_servers_ignores_custom_dns_when_off_or_empty():
    off = connection(custom_dns=CustomDns(False, ["1.1.1.1"]))
    assert off._dns_servers(IPv4Address, "10.2.0.1") == ["10.2.0.1"]
    empty = connection(custom_dns=CustomDns(True, []))
    assert empty._dns_servers(IPv4Address, "10.2.0.1") == ["10.2.0.1"]


def test_dns_servers_by_ip_version():
    wg = connection(custom_dns=CustomDns(True, ["1.1.1.1", "2606:4700:4700::1111"]))
    assert wg._dns_servers(IPv4Address, "x") == ["1.1.1.1"]
    assert wg._dns_servers(IPv6Address, "x") == ["2606:4700:4700:0000:0000:0000:0000:1111"]


def test_class_metadata():
    assert WgQuickWireguard.get_key() == "wireguard"
    assert WgQuickWireguard.get_priority() == 1
    assert WgQuickWireguard.get_protocol_group() == "generic"
    registered = []
    wireguard.register(types.SimpleNamespace(register=registered.append))
    assert registered == [WgQuickWireguard]


def test_validate_needs_the_tools_and_the_helper(tmp_path, monkeypatch):
    helper = tmp_path / "helper"
    monkeypatch.setattr(wireguard.privileged, "HELPER", helper)
    monkeypatch.setattr(wireguard, "_which", lambda name: "/bin/" + name)
    assert not WgQuickWireguard.validate()
    helper.touch()
    assert WgQuickWireguard.validate()
    monkeypatch.setattr(wireguard, "_which", lambda name: None if name == "wg" else "/bin/" + name)
    assert not WgQuickWireguard.validate()


def test_which_searches_homebrew(monkeypatch):
    seen = []
    monkeypatch.setattr(wireguard.shutil, "which", lambda name, path: seen.append(path) or "/x")
    assert wireguard._which("wg") == "/x"
    assert seen[0].startswith("/opt/homebrew/bin:")


@pytest.fixture
def paths(tmp_path, monkeypatch):
    path = tmp_path / "connection" / "proton.conf"
    monkeypatch.setattr(wireguard, "config_path", lambda: path)
    path.parent.mkdir()
    return path


def test_config_path_creates_a_private_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, "VPNExecutionEnvironment", lambda: types.SimpleNamespace(path_cache=str(tmp_path)))
    path = wireguard.config_path()
    assert path == tmp_path / "connection" / "proton.conf"
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert wireguard.exit_ip_path() == tmp_path / "connection" / "exit_ip"


def test_persisted_connection_id(paths):
    assert WgQuickWireguard._persisted_connection_id() is None
    paths.write_text("# Connection abc\n# Server CH#1\n")
    assert WgQuickWireguard._persisted_connection_id() == "abc"
    paths.write_text("")
    assert WgQuickWireguard._persisted_connection_id() is None


def test_initialize_persisted_connection(paths, monkeypatch):
    wg = connection()
    paths.write_text("# Connection abc\n")
    monkeypatch.setattr(wireguard, "tunnel_device", lambda: "utun4")
    assert isinstance(wg._initialize_persisted_connection("abc"), states.Connected)
    assert isinstance(wg._initialize_persisted_connection("other"), states.Disconnected)
    monkeypatch.setattr(wireguard, "tunnel_device", lambda: None)
    assert isinstance(wg._initialize_persisted_connection("abc"), states.Error)


class FakeProcess:
    def __init__(self, output=b"", returncode=0):
        self.output, self.returncode, self.input = output, returncode, None

    async def communicate(self, input=None):
        self.input = input
        return self.output, None

    async def wait(self):
        return self.returncode


def fake_processes(monkeypatch, outputs):
    """Fakes asyncio.create_subprocess_exec, answering by the command's last argument."""
    ran = []

    async def create(*command, **kwargs):
        process = FakeProcess(*outputs[command[-1]])
        ran.append((command, process))
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    return ran


def test_wg_quick_sends_the_config_on_stdin(monkeypatch):
    ran = fake_processes(monkeypatch, {"up": (b"done\n", 0)})
    assert asyncio.run(wireguard.wg_quick("up", "[Interface]")) == (0, "done")
    command, process = ran[0]
    assert command[-1] == "up" and command[0] == "/usr/bin/sudo"
    assert process.input == b"[Interface]"


def test_wg_quick_failure(monkeypatch):
    fake_processes(monkeypatch, {"down": (b"boom\n", 1)})
    assert asyncio.run(wireguard.wg_quick("down")) == (1, "boom")


def test_reset_leftover_dns_only_touches_services_with_the_tunnels_dns(monkeypatch):
    ran = []

    async def create(*command, **kwargs):
        ran.append(command)
        if command[1] == "-listallnetworkservices":
            return FakeProcess(b"An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Ethernet\n")
        if command[1] == "-getdnsservers":
            return FakeProcess(b"10.2.0.1\n" if command[2] == "Wi-Fi" else b"There aren't any DNS Servers set on Ethernet.\n")
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    asyncio.run(wireguard.reset_leftover_dns())
    resets = [c for c in ran if c[-2:] == ("dns-reset", "Wi-Fi")]
    assert len(resets) == 1 and resets[0][0] == "/usr/bin/sudo"
    assert not [c for c in ran if "Ethernet" in c and "dns-reset" in c]


class Listener:
    def __init__(self, running=False):
        self.is_running, self.stopped = running, False

    async def stop(self):
        self.stopped = True


@pytest.fixture
def lifecycle(paths, monkeypatch):
    """A connection whose wg-quick, DNS reset and notifications are recorded."""
    wg = connection()
    log = []
    wg.notified = []
    wg._notify_subscribers = wg.notified.append
    wg._agent_listener = Listener()
    wg._async_start_local_agent_listener = lambda: log.append("agent")
    wg.log = log

    async def wg_quick(action, config=None):
        log.append(action)
        return wg.wg_quick_result

    async def reset():
        log.append("reset-dns")

    async def reachable(*args):
        return wg.reachable

    wg.wg_quick_result, wg.reachable, wg.device = (0, ""), True, None
    monkeypatch.setattr(wireguard, "wg_quick", wg_quick)
    monkeypatch.setattr(wireguard, "reset_leftover_dns", reset)
    monkeypatch.setattr(wireguard, "tunnel_device", lambda: wg.device)
    monkeypatch.setattr(wireguard.tcpcheck, "is_any_port_reachable", reachable)
    monkeypatch.setattr(wireguard, "EventContext", lambda **kw: types.SimpleNamespace(**kw), raising=False)
    return wg


def test_start_brings_the_tunnel_up_and_hides_the_private_key(lifecycle, paths):
    asyncio.run(lifecycle.start())
    assert lifecycle.log == ["reset-dns", "up", "agent"]
    config = paths.read_text()
    assert "PrivateKey = (with the helper)" in config and "PRIVATEKEY" not in config
    assert config.startswith(f"# Connection {lifecycle._unique_id}\n")
    assert paths.stat().st_mode & 0o777 == 0o600
    assert lifecycle.notified == []


def test_start_takes_down_a_leftover_tunnel(lifecycle):
    lifecycle.device = "utun4"
    asyncio.run(lifecycle.start())
    assert lifecycle.log[:3] == ["down", "reset-dns", "up"]


def test_start_times_out_when_the_server_is_unreachable(lifecycle):
    lifecycle.reachable = False
    asyncio.run(lifecycle.start())
    assert lifecycle.log == []
    assert isinstance(lifecycle.notified[0], events.Timeout)


def test_start_reports_a_failed_tunnel(lifecycle):
    lifecycle.wg_quick_result = (1, "wg-quick: bad config")
    asyncio.run(lifecycle.start())
    assert "agent" not in lifecycle.log
    assert isinstance(lifecycle.notified[0], events.TunnelSetupFailed)


def test_start_when_cancelled_while_checking_the_server(lifecycle, monkeypatch):
    async def reachable(*args):
        lifecycle._cancelled = True
        return True

    monkeypatch.setattr(wireguard.tcpcheck, "is_any_port_reachable", reachable)
    asyncio.run(lifecycle.start())
    assert lifecycle.log == []
    assert isinstance(lifecycle.notified[0], events.Disconnected)


def test_stop_brings_the_tunnel_down(lifecycle):
    lifecycle.device = "utun4"
    lifecycle._agent_listener = Listener(running=True)
    asyncio.run(lifecycle.stop())
    assert lifecycle._agent_listener.stopped and lifecycle._cancelled
    assert lifecycle.log == ["down", "reset-dns"]
    assert isinstance(lifecycle.notified[0], events.Disconnected)


def test_stop_without_a_tunnel(lifecycle):
    asyncio.run(lifecycle.stop())
    assert lifecycle.log == ["reset-dns"]


def test_remove_persistence_keeps_files_while_the_tunnel_is_up(lifecycle, paths, monkeypatch):
    async def noop(self):
        pass

    monkeypatch.setattr(wireguard.VPNConnection, "remove_persistence", noop)
    exit_ip = paths.with_name("exit_ip")
    paths.write_text("x")
    exit_ip.write_text("1.2.3.4")
    monkeypatch.setattr(wireguard, "exit_ip_path", lambda: exit_ip)

    lifecycle.device = "utun4"
    asyncio.run(lifecycle.remove_persistence())
    assert paths.exists() and exit_ip.exists() and lifecycle._unique_id is None

    lifecycle.device = None
    asyncio.run(lifecycle.remove_persistence())
    assert not paths.exists() and not exit_ip.exists()


def test_notify_from_the_agent_thread_records_the_exit_ip(lifecycle, paths, monkeypatch):
    exit_ip = paths.with_name("exit_ip")
    monkeypatch.setattr(wireguard, "exit_ip_path", lambda: exit_ip)
    scheduled = []
    lifecycle._asyncio_loop = types.SimpleNamespace(call_soon_threadsafe=lambda *a: scheduled.append(a))

    class Connected(events.Connected):
        def __init__(self, details):
            self.context = types.SimpleNamespace(connection_details=details)

    lifecycle._notify_subscribers_threadsafe(Connected(types.SimpleNamespace(server_ipv4="9.9.9.9")))
    assert exit_ip.read_text() == "9.9.9.9"
    lifecycle._notify_subscribers_threadsafe(Connected(None))
    assert len(scheduled) == 2


def test_import_without_networkmanager_keeps_an_imported_package():
    package = wireguard.sys.modules["proton.vpn.backend.networkmanager.core"]
    wireguard._import_without_networkmanager("proton.vpn.backend.networkmanager.core")
    assert wireguard.sys.modules["proton.vpn.backend.networkmanager.core"] is package


def test_init_keeps_the_running_loop():
    async def create():
        wg = WgQuickWireguard("server", "credentials", "settings", "tier",
                              connection_persistence=object(), publisher=object())
        return wg, asyncio.get_running_loop()

    wg, loop = asyncio.run(create())
    assert wg._asyncio_loop is loop and not wg._cancelled
    assert wg._user_tier == "tier" and not wg._agent_listener.is_running
    assert isinstance(wg.initial_state, states.Disconnected)


def test_feature_updates_apply_while_active():
    assert connection().are_feature_updates_applied_when_active


def test_update_credentials_restarts_the_agent_listener(lifecycle):
    async def start():
        lifecycle.log.append("listener")

    lifecycle._start_local_agent_listener = start
    asyncio.run(lifecycle.update_credentials("new credentials"))
    assert lifecycle._vpncredentials == "new credentials"
    assert lifecycle.log == ["listener"]


def test_update_settings_requests_features_from_a_running_agent(lifecycle):
    async def request(features):
        lifecycle.log.append(("features", features))

    lifecycle._agent_listener = Listener(running=True)
    lifecycle._request_connection_features = request
    settings = types.SimpleNamespace(features="new features")
    asyncio.run(lifecycle.update_settings(settings))
    assert lifecycle._settings is settings
    assert lifecycle.log == [("features", "new features")]


def test_update_settings_starts_an_agent_for_an_earlier_runs_tunnel(lifecycle):
    settings = types.SimpleNamespace(features="new features")
    asyncio.run(lifecycle.update_settings(settings))
    assert lifecycle.log == []
    lifecycle.device = "utun4"
    asyncio.run(lifecycle.update_settings(settings))
    assert lifecycle.log == ["agent"]
