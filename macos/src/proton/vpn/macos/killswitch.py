"""
Kill switch for macOS, as pf rules in an anchor under com.apple/, which the
stock /etc/pf.conf already evaluates, so pf.conf itself is left alone.

While it's on, outgoing traffic is blocked except through the tunnel (traffic
from the tunnel's addresses), to the VPN server, on loopback, to the local
network and for DHCP. It stays on if the tunnel drops, and only comes off when
Proton's state machine disables it, i.e. on an intentional disconnect.
"""
import logging
import re
from pathlib import Path
from typing import Optional

from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.killswitch.interface import KillSwitch

from proton.vpn.macos import privileged
from proton.vpn.macos.tunnel import IPV4_ADDRESS

logger = logging.getLogger(__name__)

IPV6_ADDRESS = "2a07:b944::2:2"
LOCAL_NETWORKS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4",
    "255.255.255.255/32", "fe80::/10", "ff00::/8",
]




def _token_path() -> Path:
    return Path(VPNExecutionEnvironment().path_cache, "connection", "pf-token")


def _endpoint_from_config() -> Optional[str]:
    """The VPN server's IP, from the tunnel's config, when Proton doesn't pass the server."""
    config = Path(VPNExecutionEnvironment().path_cache, "connection", "proton.conf")
    try:
        match = re.search(r"^Endpoint = (.+):\d+$", config.read_text(encoding="utf-8"), re.MULTILINE)
    except OSError:
        return None
    return match.group(1) if match else None


def rules(server_ip: Optional[str]) -> str:
    """The anchor's rules, letting traffic to the given VPN server through."""
    lines = [
        "pass out quick on lo0 all",
        f"pass out quick inet from {IPV4_ADDRESS} to any",
        f"pass out quick inet6 from {IPV6_ADDRESS} to any",
        "pass out quick proto udp from any port 68 to any port 67",
        f"pass out quick to {{ {' '.join(LOCAL_NETWORKS)} }}",
    ]
    if server_ip:
        lines.append(f"pass out quick to {server_ip}")
    lines.append("block drop out quick all")
    return "\n".join(lines) + "\n"


class PfKillSwitch(KillSwitch):
    """Kill switch implemented with pf."""

    async def enable(self, vpn_server=None, permanent: bool = False):
        if permanent:
            # Proton's "advanced" kill switch blocks everything while disconnected,
            # Proton's API included, so it couldn't connect again; treat it as standard.
            logger.warning("The permanent kill switch isn't supported on macOS; using the standard one.")

        server_ip = vpn_server.server_ip if vpn_server else _endpoint_from_config()
        result = privileged.run("pf-load", stdin=rules(server_ip))
        if result.returncode:
            raise RuntimeError(f"Couldn't load the kill switch rules: {result.stderr.strip()}")

        token = _token_path()
        if not token.exists():
            # -E enables pf, counting a reference that -X <token> gives back. The
            # file also marks the kill switch as on, so disabling it is free when it's off.
            result = privileged.run("pf-enable")
            found = re.search(r"Token : (\d+)", result.stderr + result.stdout)
            token.write_text(found.group(1) if found else "", encoding="utf-8")
        logger.info("Kill switch enabled, allowing %s.", server_ip)

    async def disable(self):
        token = _token_path()
        if not token.exists():
            return
        privileged.run("pf-flush")
        if reference := token.read_text(encoding="utf-8").strip():
            privileged.run("pf-release", reference)
        token.unlink()
        logger.info("Kill switch disabled.")

    async def enable_ipv6_leak_protection(self):
        # The tunnel routes all IPv6 into itself, so it can't leak around it.
        pass

    async def disable_ipv6_leak_protection(self):
        pass

    @staticmethod
    def _get_priority() -> int:
        return 100

    @staticmethod
    def _validate(validate_params: Optional[dict] = None):
        return True


def is_enabled() -> bool:
    """Whether the kill switch's rules are loaded, for status output."""
    return _token_path().exists()
