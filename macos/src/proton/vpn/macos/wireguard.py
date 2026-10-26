"""
WireGuard connections on macOS, brought up with wireguard-tools' wg-quick.

This takes the place of Proton's NetworkManager WireGuard backend. It builds the
same tunnel (addresses, DNS, peer) as a wg-quick config and reuses Proton's
local agent code, which confirms the connection and applies its features
(NetShield, VPN Accelerator, ...) once the tunnel is up.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import sys
import types
import uuid
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Optional

from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.connection import VPNConnection, events, states
from proton.vpn.connection.events import EventContext

from proton.vpn.macos import privileged
from proton.vpn.macos.tunnel import INTERFACE, IPV4_ADDRESS as TUNNEL_IPV4, tunnel_device


def _import_without_networkmanager(package: str):
    """
    Lets modules under Proton's NetworkManager backend package be imported without
    running its __init__, which imports NetworkManager's GObject bindings.
    """
    if package in sys.modules:
        return
    parent = sys.modules[package.rsplit(".", 1)[0]]
    module = types.ModuleType(package)
    module.__path__ = [os.path.join(path, package.rsplit(".", 1)[1]) for path in parent.__path__]
    sys.modules[package] = module


import proton.vpn.backend.networkmanager  # noqa: E402  pylint: disable=C0413
_import_without_networkmanager("proton.vpn.backend.networkmanager.core")
# pylint: disable=C0413
from proton.vpn.backend.networkmanager.core import tcpcheck  # noqa: E402
from proton.vpn.backend.networkmanager.core.localagent_mixin import LocalAgentMixin  # noqa: E402

logger = logging.getLogger(__name__)

# As in Proton's NetworkManager WireGuard backend.
IPV4_ADDRESS, IPV4_DNS = f"{TUNNEL_IPV4}/32", "10.2.0.1"
IPV6_ADDRESS, IPV6_DNS = "2a07:b944::2:2/128", "2a07:b944::2:1"

BREW_BIN = "/opt/homebrew/bin"
PATH = f"{BREW_BIN}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


def _which(name: str) -> Optional[str]:
    return shutil.which(name, path=PATH)


def config_path() -> Path:
    directory = Path(VPNExecutionEnvironment().path_cache, "connection")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return directory / f"{INTERFACE}.conf"


def exit_ip_path() -> Path:
    return config_path().with_name("exit_ip")


async def wg_quick(action: str, config: Optional[str] = None) -> tuple[int, str]:
    """Runs `wg-quick up|down` through the root helper, which takes the config on stdin."""
    process = await asyncio.create_subprocess_exec(
        *privileged.command(action),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await process.communicate((config or "").encode())
    output = output.decode(errors="replace").strip()
    logger.info("wg-quick %s exited with %s:\n%s", action, process.returncode, output)
    return process.returncode, output


async def reset_leftover_dns():
    """
    Resets network services whose DNS is still the tunnel's while no tunnel is up.

    wg-quick saves each service's DNS when it brings a tunnel up and restores it
    when it brings it down, so a tunnel brought up while another one's DNS was
    still set would restore the tunnel's DNS, leaving DNS broken once disconnected.
    """
    process = await asyncio.create_subprocess_exec(
        "/usr/sbin/networksetup", "-listallnetworkservices", stdout=asyncio.subprocess.PIPE)
    output, _ = await process.communicate()
    for service in output.decode().splitlines()[1:]:
        service = service.lstrip("*")
        process = await asyncio.create_subprocess_exec(
            "/usr/sbin/networksetup", "-getdnsservers", service, stdout=asyncio.subprocess.PIPE)
        servers, _ = await process.communicate()
        if IPV4_DNS in servers.decode().split():
            logger.warning("Resetting DNS left over from the tunnel on %s", service)
            process = await asyncio.create_subprocess_exec(*privileged.command("dns-reset", service))
            await process.wait()


class WgQuickWireguard(VPNConnection, LocalAgentMixin):
    """Creates a WireGuard connection with wg-quick."""
    backend = "wgquick"
    protocol = "wireguard"
    ui_protocol = "WireGuard"

    def __init__(self, *args, **kwargs):
        self._asyncio_loop = asyncio.get_running_loop()
        self._cancelled = False
        super().__init__(*args, **kwargs)
        LocalAgentMixin.__init__(self, self._user_tier)

    @property
    def enable_ipv6_support(self) -> bool:
        """Returns if IPv6 support is enabled or not."""
        return self._vpnserver.has_ipv6_support and self._settings.ipv6

    @property
    def are_feature_updates_applied_when_active(self) -> bool:
        return True

    async def update_credentials(self, credentials):
        """Notifies the vpn server that the wireguard certificate needs a refresh."""
        await super().update_credentials(credentials)
        await self._start_local_agent_listener()

    async def update_settings(self, settings):
        """Update features on the active agent connection."""
        await super().update_settings(settings)
        if self._agent_listener.is_running:
            await self._request_connection_features(settings.features)
        elif tunnel_device():
            # A connection made by an earlier run of the CLI has no agent listener
            # in this process; starting one requests the new features and reports
            # the Connected status that `protonvpn config set` waits for.
            self._async_start_local_agent_listener()

    def _notify_subscribers_threadsafe(self, event):
        """Notifies subscribers from the local agent's thread."""
        details = event.context.connection_details
        if isinstance(event, events.Connected) and details and details.server_ipv4:
            # For `vpn status`, which reads files rather than asking the local agent.
            exit_ip_path().write_text(details.server_ipv4, encoding="utf-8")
        self._asyncio_loop.call_soon_threadsafe(self._notify_subscribers, event)

    async def start(self):
        self._cancelled = False

        server_reachable = await tcpcheck.is_any_port_reachable(
            self._vpnserver.server_ip,
            self._vpnserver.openvpn_ports.tcp
        )
        if not server_reachable:
            logger.info("VPN server NOT reachable.")
            self._notify_subscribers(events.Timeout(EventContext(connection=self)))
            return

        if self._cancelled:
            self._notify_subscribers(events.Disconnected(EventContext(connection=self)))
            return

        if tunnel_device():
            # Left over from a connection that was never brought down.
            await wg_quick("down")
        await reset_leftover_dns()

        self._unique_id = str(uuid.uuid4())
        # Kept for `vpn status`, without the private key; the helper keeps its own copy to bring
        # the tunnel down.
        config = self._generate_config()
        path = config_path()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(re.sub(r"^PrivateKey = .*$", "PrivateKey = (with the helper)", config, flags=re.MULTILINE))

        returncode, output = await wg_quick("up", config)
        if returncode:
            self._notify_subscribers(
                events.TunnelSetupFailed(EventContext(connection=self, error=output))
            )
            return

        # The local agent confirms the connection, which triggers the Connected event.
        self._async_start_local_agent_listener()

    async def stop(self):
        self._cancelled = True
        if self._agent_listener.is_running:
            await self._agent_listener.stop()

        if tunnel_device():
            await wg_quick("down")
        await reset_leftover_dns()

        self._notify_subscribers(events.Disconnected(EventContext(connection=self)))

    async def remove_persistence(self):
        await super().remove_persistence()
        if not tunnel_device():
            config_path().unlink(missing_ok=True)
            exit_ip_path().unlink(missing_ok=True)
        self._unique_id = None

    def _initialize_persisted_connection(self, connection_id: str) -> states.State:
        context = states.StateContext(
            event=events.Initialized(EventContext(connection=self)),
            connection=self
        )

        if self._persisted_connection_id() != connection_id:
            return states.Disconnected(context)

        if tunnel_device():
            return states.Connected(context)

        # The tunnel dropped without being disconnected.
        return states.Error(context)

    @staticmethod
    def _persisted_connection_id() -> Optional[str]:
        try:
            first_line = config_path().read_text(encoding="utf-8").partition("\n")[0]
        except OSError:
            return None
        return first_line.removeprefix("# Connection ").strip() or None

    def _generate_config(self) -> str:
        addresses = [IPV4_ADDRESS]
        dns = self._dns_servers(IPv4Address, IPV4_DNS)
        if self.enable_ipv6_support:
            addresses.append(IPV6_ADDRESS)
            dns += self._dns_servers(IPv6Address, IPV6_DNS)

        # IPv6 is routed into the tunnel even without an IPv6 address, where it's
        # dropped, so that it can't leak around the VPN.
        allowed_ips = ["0.0.0.0/0", "::/0"]

        return "\n".join([
            f"# Connection {self._unique_id}",
            f"# Server {self._vpnserver.server_name}",
            "[Interface]",
            f"PrivateKey = {self._vpncredentials.pubkey_credentials.wg_private_key}",
            f"Address = {', '.join(addresses)}",
            f"DNS = {', '.join(dns)}",
            "",
            "[Peer]",
            f"PublicKey = {self._vpnserver.x25519pk}",
            f"AllowedIPs = {', '.join(allowed_ips)}",
            f"Endpoint = {self._vpnserver.server_ip}:{self._vpnserver.wireguard_ports.udp[0]}",
            "",
        ])

    def _dns_servers(self, ip_version, default: str) -> list[str]:
        custom_dns = self._settings.custom_dns
        ips = [dns.exploded for dns in custom_dns.get_enabled_dns_list_based_on_ip_version(ip_version)]
        if custom_dns.enabled and any(dns.enabled for dns in custom_dns.ip_list):
            # Only the custom servers, so an IPv4-only list doesn't get Proton's IPv6 DNS added.
            return ips
        return [default]

    @classmethod
    def get_key(cls):
        return cls.protocol

    @classmethod
    def get_priority(cls):
        return 1

    @classmethod
    def validate(cls):
        return all(_which(tool) for tool in ("wg-quick", "wg", "wireguard-go", "bash")) and privileged.HELPER.exists()

    @classmethod
    def get_protocol_group(cls) -> str:
        return "generic"


def register(registry):
    """Registers the wg-quick WireGuard implementation in the given registry."""
    registry.register(WgQuickWireguard)
