"""
Running the root-only parts (wg-quick, pfctl, networksetup) through the helper `protonvpn setup` installs.

The helper is root-owned and its user may run it with sudo without a password; see helper.sh for
what it accepts.
"""
import getpass
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

HELPER = Path("/usr/local/libexec/proton-vpn-cli-macos-helper")
# Root-owned copies of what the helper runs, since Homebrew's files can be changed by anything running as you.
TOOLS = Path("/usr/local/libexec/proton-vpn-cli-macos")
SUDOERS = Path("/etc/sudoers.d/proton-vpn-cli-macos")
SOURCE = Path(__file__).with_name("helper.sh")
HOMEBREW = "/opt/homebrew/bin:/usr/local/bin"


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


def ensure_set_up():
    """Connecting needs the helper: sets it up first in a terminal, where sudo can ask for the password."""
    if is_set_up():
        return
    if not sys.stdin.isatty():
        sys.exit("protonvpn: connecting needs a one-time setup first: run `protonvpn setup`, which asks for your password.")
    print("Connecting needs a one-time setup first, which asks for your Mac password.")
    setup()


def setup(user: Optional[str] = None):
    """
    Installs the helper and the sudo rule for it, as root; otherwise reruns itself with sudo,
    which asks for the password once.
    """
    user = user or os.environ.get("SUDO_USER") or getpass.getuser()
    if os.geteuid() != 0:
        if is_set_up() and not outdated_tools():
            print("Already set up: connecting doesn't need your password.")
            return
        command = ["/usr/bin/sudo", sys.executable, "-m", "proton.vpn.macos.vpn", "setup", "--user", user]
        if subprocess.run(command, check=False).returncode:
            sys.exit(1)
        return

    found = {tool: shutil.which(tool, path=HOMEBREW) for tool in ("wg-quick", "wg", "wireguard-go", "bash")}
    if not all(found.values()):
        sys.exit("protonvpn: setup needs Homebrew's wireguard-tools, wireguard-go and bash: "
                 "brew install wireguard-tools wireguard-go bash")
    HELPER.parent.mkdir(parents=True, exist_ok=True)
    unsafe = writable_by_others(HELPER.parent)
    if unsafe:
        sys.exit(f"protonvpn: {unsafe} can be changed by users other than root, so the helper can't go in it")
    install_tools(found)
    shutil.copyfile(SOURCE, HELPER)
    os.chown(HELPER, 0, 0)
    os.chmod(HELPER, 0o755)

    rule = f"{user} ALL=(root) NOPASSWD: {HELPER}\n"
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sudoers") as file:
        file.write(rule)
    if subprocess.run(["/usr/sbin/visudo", "-cf", file.name], capture_output=True, check=False).returncode:
        os.unlink(file.name)
        sys.exit("protonvpn: the sudo rule didn't validate, so nothing was changed in /etc/sudoers.d")
    os.chown(file.name, 0, 0)
    os.chmod(file.name, 0o440)
    shutil.move(file.name, SUDOERS)
    print(f"Set up: {user} can now connect without a password.")


def setup_in_dialog():
    """
    Runs setup as root after macOS's own password dialog, for Alfred, which has no terminal and
    shouldn't see the password.
    """
    import shlex  # pylint: disable=import-outside-toplevel
    refreshing = bool(outdated_tools())
    command = shlex.join([sys.executable, "-m", "proton.vpn.macos.vpn", "setup", "--user", getpass.getuser()])
    script = f"do shell script {json.dumps(command)} with administrator privileges"
    result = subprocess.run(["/usr/bin/osascript", "-e", script], capture_output=True, text=True, check=False)
    if result.returncode:
        sys.exit("Setup cancelled" if "User canceled" in result.stderr else f"protonvpn: {result.stderr.strip()}")
    print("WireGuard tools refreshed" if refreshing else result.stdout.strip())


def writable_by_others(path: Path) -> Optional[Path]:
    """The first of path and its parents that isn't root's alone, if any."""
    for folder in (path, *path.parents):
        info = folder.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            return folder
    return None


def linked_libraries(binary: Path) -> list[str]:
    """The libraries a binary loads from outside macOS, like Homebrew's readline for its bash."""
    def otool(flag):
        output = subprocess.run(["/usr/bin/otool", flag, str(binary)], capture_output=True, text=True, check=True).stdout
        return [line.split()[0] for line in output.splitlines()[1:] if line.strip()]

    own = otool("-D")
    return [library for library in otool("-L")
            if library not in own and not library.startswith(("/usr/lib/", "/System/", "@"))]


def install_tools(found: dict[str, str]):
    """
    Copies wg-quick and what it runs (wg, wireguard-go, and bash with the libraries it loads) into
    TOOLS for the helper, so running it as root never runs a file your account can change.
    Running setup again copies Homebrew's latest.
    """
    staging = TOOLS.with_name(TOOLS.name + ".new")
    shutil.rmtree(staging, ignore_errors=True)
    (staging / "lib").mkdir(parents=True)
    for tool, path in found.items():
        shutil.copyfile(os.path.realpath(path), staging / tool)
    # Where each came from, which names its version, e.g. /opt/homebrew/Cellar/bash/5.3.20/bin/bash.
    (staging / "sources.json").write_text(json.dumps({tool: os.path.realpath(path) for tool, path in found.items()}))

    # bash's libraries go in lib, and everything that loads them is pointed there, then signed again.
    pending, changed = [staging / "bash"], []
    while pending:
        binary = pending.pop()
        for library in linked_libraries(binary):
            name = os.path.basename(library)
            copy = staging / "lib" / name
            if not copy.exists():
                shutil.copyfile(os.path.realpath(library), copy)
                subprocess.run(["/usr/bin/install_name_tool", "-id", f"@executable_path/lib/{name}", str(copy)],
                               capture_output=True, check=True)
                pending.append(copy)
                changed.append(copy)
            subprocess.run(["/usr/bin/install_name_tool", "-change", library, f"@executable_path/lib/{name}",
                            str(binary)], capture_output=True, check=True)
        changed.append(binary)
    for binary in dict.fromkeys(changed):
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", str(binary)], capture_output=True, check=True)

    for folder, _, files in os.walk(staging):
        os.chown(folder, 0, 0)
        os.chmod(folder, 0o755)
        for name in files:
            os.chown(os.path.join(folder, name), 0, 0)
            os.chmod(os.path.join(folder, name), 0o644 if folder.endswith("lib") or name.endswith(".json") else 0o755)
    shutil.rmtree(TOOLS, ignore_errors=True)
    staging.rename(TOOLS)


def outdated_tools() -> list[str]:
    """The tools Homebrew has updated since setup copied them, which setup copies again."""
    try:
        copied = json.loads((TOOLS / "sources.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    current = {tool: shutil.which(tool, path=HOMEBREW) for tool in copied}
    return [tool for tool, source in copied.items() if current[tool] and os.path.realpath(current[tool]) != source]
