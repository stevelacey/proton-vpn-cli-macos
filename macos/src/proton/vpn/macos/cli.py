"""Entry point for `protonvpn`: Proton's CLI with the macOS backends plugged in."""
import contextlib
import fcntl
import os
import sys
import tempfile

from proton.vpn.macos import bundled

bundled.install()

# pylint: disable=wrong-import-position
from proton.utils.environment import ExecutionEnvironment


def _get_dir_paths(_self):
    """Like Linux's defaults, but with a runtime dir macOS has (/run/user doesn't exist)."""
    home = os.path.expanduser("~")
    return os.path.join(home, ".config"), os.path.join(home, ".cache"), tempfile.gettempdir()


# Before importing api-core, which creates runtime dirs at import time.
ExecutionEnvironment._get_dir_paths = _get_dir_paths  # pylint: disable=protected-access

# proton-core's fast SRP loads the unversioned libssl.dylib with ctypes, which macOS aborts the
# process for unless the Python finds a Homebrew OpenSSL first; its pure Python SRP works anywhere.
sys.modules.setdefault("proton.session.srp._ctsrp", None)

# pylint: disable=wrong-import-position
from proton.loader import Loader
from proton.keyring.textfile import KeyringBackendJsonFiles
from proton.vpn.core.api import ProtonVPNAPI
from proton.vpn.core.registry import Registry

from proton.vpn.macos import privileged
from proton.vpn.macos.keychain import KeychainKeyring
from proton.vpn.macos.killswitch import PfKillSwitch


def create_registry() -> Registry:
    """Registers the macOS connection backend in place of NetworkManager's."""
    registry = Registry()
    registry.register_from_module("proton.vpn.macos.wireguard")
    return registry


def _wait_for_current_tasks_ignoring_cancelled():
    """
    After `disconnect`, Proton's CLI waits for every pending task with
    asyncio.gather, which re-raises the CancelledError of a transport ping
    cancelled at shutdown, so a successful disconnect exits with status 1.
    """
    # pylint: disable=import-outside-toplevel
    import asyncio
    from proton.vpn.cli.commands import server

    async def wait_for_current_tasks(timeout=10):
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        try:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout)
        except asyncio.TimeoutError:
            print(f"Timed out after {timeout}s waiting for tasks to finish")

    server.wait_for_current_tasks = wait_for_current_tasks


def install():
    """Plugs the macOS backends into Proton's api-core."""
    ProtonVPNAPI.create_registry = staticmethod(create_registry)
    _wait_for_current_tasks_ignoring_cancelled()

    # Setting these up front stops the loader from importing the Linux
    # implementations that api-core declares as entry points.
    Loader.set_all("keyring", {"keychain": KeychainKeyring, "json": KeyringBackendJsonFiles})
    Loader.set_all("killswitch", {"pf": PfKillSwitch})
    Loader.set_all("split_tunneling", {})


@contextlib.contextmanager
def locked():
    """
    Holds a lock for the length of a command that changes the connection or
    settings, so that overlapping commands (say from the menu bar and Alfred)
    queue up instead of racing, which leaves wg-quick saving the tunnel's DNS
    as the one to restore. The environment variable lets child processes in.
    """
    if os.environ.get(LOCK_HELD):
        yield
        return
    with open(os.path.join(os.path.expanduser("~"), ".cache", "Proton", "VPN", ".lock"), "a",
              encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        os.environ[LOCK_HELD] = "1"
        try:
            yield
        finally:
            del os.environ[LOCK_HELD]


LOCK_HELD = "PROTONVPN_LOCK_HELD"
READ_ONLY_COMMANDS = {"status", "info", "countries", "cities", "servers"}


def main():
    """Runs Proton's CLI."""
    install()

    # pylint: disable=import-outside-toplevel
    from proton.vpn.cli import main as cli_main

    command = next((arg for arg in sys.argv[1:] if not arg.startswith("-")), None)
    if command == "connect" and not privileged.is_set_up():
        sys.exit("Connecting needs a one-time setup first: run `vpn setup`, which asks for your password.")
    with contextlib.nullcontext() if command in READ_ONLY_COMMANDS else locked():
        # Skips the check for Proton's Linux GUI over D-Bus.
        cli_main(allow_concurrency=True)


if __name__ == "__main__":
    main()
