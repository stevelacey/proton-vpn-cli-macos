"""The wg-quick tunnel's state, kept free of heavy imports for quick status checks."""
import subprocess
from pathlib import Path
from typing import Optional

# wg-quick names the interface after its config file, proton.conf.
INTERFACE = "proton"

# The tunnel's address, as in Proton's NetworkManager WireGuard backend.
IPV4_ADDRESS = "10.2.0.2"


def tunnel_device() -> Optional[str]:
    """
    Returns the utun device of the wg-quick tunnel, if it's up.

    wg-quick records the device in /var/run/wireguard/proton.name, but that's only
    readable by root, so this looks for a WireGuard device with Proton's address.
    """
    for sock in sorted(Path("/var/run/wireguard").glob("utun*.sock")):
        device = sock.stem
        result = subprocess.run(
            ["/sbin/ifconfig", device], capture_output=True, text=True, check=False
        )
        if result.returncode == 0 and f"inet {IPV4_ADDRESS} " in result.stdout:
            return device

    return None
