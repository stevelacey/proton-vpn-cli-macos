"""Keyring backend storing Proton's session data in the macOS login Keychain."""
import base64
import json
import subprocess

from proton.keyring import Keyring
from proton.keyring.exceptions import KeyringError

SERVICE = "Proton VPN CLI"

# `security -i` silently truncates lines past about 4 KB, so values are split
# across several items: `<key>` holds the number of chunks, `<key>.<n>` each chunk.
CHUNK_SIZE = 3000

ERR_ITEM_NOT_FOUND = 44


def _security(*args, stdin=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/usr/bin/security", *args], input=stdin, capture_output=True, text=True, check=False
    )


def _find(account: str) -> str:
    result = _security("find-generic-password", "-s", SERVICE, "-a", account, "-w")
    if result.returncode == ERR_ITEM_NOT_FOUND:
        raise KeyError(account)
    if result.returncode:
        raise KeyringError(result.stderr.strip())
    return result.stdout.strip()


class KeychainKeyring(Keyring):
    """
    Stores keys as generic passwords through /usr/bin/security, so that the
    items' access lists name Apple's signed tool rather than whichever Python
    binary is running, and reading them never prompts. Secrets are passed on
    stdin, never as arguments.
    """

    def _get_item(self, key):
        try:
            count = int(_find(key))
        except ValueError as exc:
            raise KeyError(key) from exc

        commands = "".join(
            f'find-generic-password -s "{SERVICE}" -a {key}.{n} -w\n' for n in range(count)
        )
        chunks = _security("-i", stdin=commands).stdout.split()
        if len(chunks) != count:
            raise KeyError(key)

        try:
            return json.loads(base64.b64decode("".join(chunks)))
        except ValueError as exc:
            self._del_item(key)
            raise KeyError(key) from exc

    def _del_item(self, key):
        count = _find(key)
        commands = "".join(
            f'delete-generic-password -s "{SERVICE}" -a {account}\n'
            for account in [key] + [f"{key}.{n}" for n in range(int(count) if count.isdigit() else 0)]
        )
        _security("-i", stdin=commands)

    def _set_item(self, key, value):
        try:
            secret = base64.b64encode(json.dumps(value).encode()).decode()
        except TypeError as exc:
            raise ValueError(value) from exc

        try:
            self._del_item(key)
        except KeyError:
            pass

        chunks = [secret[i:i + CHUNK_SIZE] for i in range(0, len(secret), CHUNK_SIZE)]
        commands = "".join(
            f'add-generic-password -U -s "{SERVICE}" -a {account} -w {password}\n'
            for account, password in [
                *((f"{key}.{n}", chunk) for n, chunk in enumerate(chunks)),
                # Written last, so a partial write reads as missing.
                (key, str(len(chunks))),
            ]
        )
        result = _security("-i", stdin=commands)
        if result.stderr.strip():
            raise KeyringError(result.stderr.strip())

    @classmethod
    def _get_priority(cls) -> int:
        return 100

    @classmethod
    def _validate(cls):
        return True
