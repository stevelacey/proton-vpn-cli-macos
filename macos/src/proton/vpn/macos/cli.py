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


NETSHIELD_LEVELS = {0: "off", 1: "malware-only", 2: "malware-ads-trackers", 3: "malware-ads-trackers-adult"}


def _add_adult_content_netshield():
    """
    Adds NetShield's level 3, which also blocks adult content. Proton's apps offer it and its
    servers apply it, but the Linux CLI only lists levels 0 to 2.
    """
    # pylint: disable=import-outside-toplevel
    from proton.vpn.cli.commands import feature_setting_definitions as definitions
    netshield = definitions.NetshieldType
    describe = netshield.get_human_friendly_state_string
    netshield.to_list_of_str = staticmethod(lambda: list(NETSHIELD_LEVELS.values()))
    netshield.from_str = staticmethod(lambda value: {v: k for k, v in NETSHIELD_LEVELS.items()}.get(value, 2))
    netshield.to_str = staticmethod(lambda value: NETSHIELD_LEVELS.get(int(value), "malware-ads-trackers"))
    netshield.get_human_friendly_state_string = staticmethod(
        lambda value: "malware, ads, trackers and adult content" if int(value) == 3 else describe(value))
    definitions.NETSHIELD_FEATURE.value_to_help["malware-ads-trackers-adult"] = \
        "Block malware, ads, trackers and adult content"

    # The command's choices and help were built when it was defined, so they're updated too.
    from proton.vpn.cli.commands import settings as commands  # pylint: disable=import-outside-toplevel
    command = commands.netshield_command
    for param in command.params:
        if hasattr(param.type, "choices"):
            param.type.choices = list(NETSHIELD_LEVELS.values())
    command.epilog = commands._format_setting_epilog(definitions.NETSHIELD_FEATURE)  # pylint: disable=protected-access


PORT_FORWARDING_HOW_IT_WORKS = """How It Works:
  On P2P servers, the server forwards a port to you while connected.
  protonvpn keeps it in the background, and 'protonvpn status' shows it."""


def _explain_port_forwarding():
    """
    Proton's CLI says to keep the forwarded port with a natpmpc script from its Linux guide;
    here `protonvpn watch` keeps it in the background, so its messages point to status instead.
    """
    # pylint: disable=import-outside-toplevel,protected-access
    import click
    from proton.vpn.cli.commands import feature_setting_definitions as definitions, server, settings
    from proton.vpn.session.servers.types import ServerFeatureEnum
    show_capabilities = server._display_relevant_server_capabilities

    async def display_relevant_server_capabilities(controller, logical):
        current = await controller.get_settings()
        if current.features.port_forwarding and ServerFeatureEnum.P2P in logical.features:
            click.echo("\nPort forwarding is active on this server: run 'protonvpn status' for the port.")
        else:
            await show_capabilities(controller, logical)

    server._display_relevant_server_capabilities = display_relevant_server_capabilities
    settings._feature_specific_success_postfix = lambda feature, value: ""

    feature = definitions.PORT_FORWARDING_FEATURE
    epilog = feature.help_epilog
    if "How It Works" in epilog:
        start = epilog.index("How It Works")
        end = epilog.index("\b\nExamples:")
        feature.help_epilog = epilog[:start] + PORT_FORWARDING_HOW_IT_WORKS + "\n" + epilog[end:]
    settings.set_group.commands[feature.command].epilog = settings._format_setting_epilog(feature)


def install():
    """Plugs the macOS backends into Proton's api-core."""
    ProtonVPNAPI.create_registry = staticmethod(create_registry)
    _wait_for_current_tasks_ignoring_cancelled()
    _add_adult_content_netshield()
    _explain_port_forwarding()

    # Setting these up front stops the loader from importing the Linux
    # implementations that api-core declares as entry points.
    Loader.set_all("keyring", {"keychain": KeychainKeyring, "json": KeyringBackendJsonFiles})
    Loader.set_all("killswitch", {"pf": PfKillSwitch})
    Loader.set_all("split_tunneling", {})


@contextlib.contextmanager
def locked():
    """
    Holds a lock for the length of a command that changes the connection or
    settings, so that overlapping commands (say from two apps at once)
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
    if command == "connect" and not {"--help", "-h"} & set(sys.argv):
        privileged.ensure_set_up()
    from proton.vpn.macos import vpn  # pylint: disable=import-outside-toplevel
    with contextlib.nullcontext() if command in READ_ONLY_COMMANDS else locked():
        if command == "connect" and not {"--help", "-h"} & set(sys.argv):
            vpn.drop_dead_tunnel()
        # Skips the check for Proton's Linux GUI over D-Bus.
        cli_main(allow_concurrency=True)
    if command in ("connect", "config"):
        vpn.keep_watching()


if __name__ == "__main__":  # pragma: no cover
    main()
