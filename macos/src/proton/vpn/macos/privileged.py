"""
Running the root-only parts (wg-quick, pfctl, networksetup) through the helper `vpn setup` installs.

The helper is root-owned and its user may run it with sudo without a password; see helper.sh for
what it accepts.
"""
import getpass
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

HELPER = Path("/usr/local/libexec/proton-vpn-cli-macos-helper")
SUDOERS = Path("/etc/sudoers.d/proton-vpn-cli-macos")
SOURCE = Path(__file__).with_name("helper.sh")


def command(*args: str) -> list[str]:
    """The command line that runs the helper as root."""
    return ["/usr/bin/sudo", "-n", str(HELPER), *args]


def run(*args: str, stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(command(*args), input=stdin, capture_output=True, text=True, check=False)


def bundled_version() -> str:
    for line in SOURCE.read_text(encoding="utf-8").splitlines():
        if line.startswith("VERSION="):
            return line.removeprefix("VERSION=")
    return ""


def is_set_up() -> bool:
    """Whether the installed helper is this version's and runs without a password."""
    if not HELPER.exists():
        return False
    result = run("version")
    return result.returncode == 0 and result.stdout.strip() == bundled_version()


def setup(user: Optional[str] = None):
    """
    Installs the helper and the sudo rule for it, as root; otherwise reruns itself with sudo,
    which asks for the password once.
    """
    user = user or os.environ.get("SUDO_USER") or getpass.getuser()
    if os.geteuid() != 0:
        os.execv("/usr/bin/sudo", ["sudo", sys.executable, "-m", "proton.vpn.macos.vpn", "setup", "--user", user])

    HELPER.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SOURCE, HELPER)
    os.chown(HELPER, 0, 0)
    os.chmod(HELPER, 0o755)

    rule = f"{user} ALL=(root) NOPASSWD: {HELPER}\n"
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sudoers") as file:
        file.write(rule)
    if subprocess.run(["/usr/sbin/visudo", "-cf", file.name], capture_output=True, check=False).returncode:
        os.unlink(file.name)
        sys.exit("vpn: the sudo rule didn't validate, so nothing was changed in /etc/sudoers.d")
    os.chown(file.name, 0, 0)
    os.chmod(file.name, 0o440)
    shutil.move(file.name, SUDOERS)

    missing = [tool for tool in ("wg-quick", "wireguard-go") if not shutil.which(tool, path="/opt/homebrew/bin:/usr/local/bin")]
    print(f"Set up: {user} can now connect without a password.")
    if missing:
        print(f"Also needed: brew install wireguard-tools bash (missing {', '.join(missing)})")
