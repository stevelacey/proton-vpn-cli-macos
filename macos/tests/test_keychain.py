import base64
import json
import subprocess
import types

import pytest
from proton.keyring.exceptions import KeyringError

from proton.vpn.macos import keychain
from proton.vpn.macos.keychain import KeychainKeyring


class FakeSecurity:
    """Stands in for /usr/bin/security, keeping the items in a dict."""

    def __init__(self):
        self.items = {}
        self.stdin = []
        self.error = ""

    def __call__(self, command, input=None, **kwargs):
        assert command[0] == "/usr/bin/security"
        args = command[1:]
        if args[0] == "find-generic-password":
            account = args[args.index("-a") + 1]
            if account not in self.items:
                return types.SimpleNamespace(returncode=44, stdout="", stderr="not found")
            return types.SimpleNamespace(returncode=0, stdout=self.items[account] + "\n", stderr="")

        assert args == ["-i"]
        self.stdin.append(input)
        out = []
        for line in input.splitlines():
            words = line.replace('"', "").split()
            account = words[words.index("-a") + 1]
            if words[0] == "find-generic-password":
                out.append(self.items[account])
            elif words[0] == "delete-generic-password":
                del self.items[account]
            else:
                self.items[account] = words[words.index("-w") + 1]
        return types.SimpleNamespace(returncode=0, stdout="\n".join(out), stderr=self.error)


@pytest.fixture
def security(monkeypatch):
    fake = FakeSecurity()
    monkeypatch.setattr(subprocess, "run", fake)
    return fake


def test_values_round_trip_in_chunks(security):
    value = {"token": "x" * 7000}
    KeychainKeyring()._set_item("session", value)
    assert security.items["session"] == "4"
    assert {"session.0", "session.1", "session.2", "session.3"} <= set(security.items)
    assert all(len(v) <= keychain.CHUNK_SIZE for k, v in security.items.items() if "." in k)
    assert KeychainKeyring()._get_item("session") == value


def test_secrets_go_on_stdin_not_arguments(security, monkeypatch):
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda command, **kw: seen.append(command) or security(command, **kw))
    KeychainKeyring()._set_item("session", {"password": "hunter2"})
    secret = base64.b64encode(json.dumps({"password": "hunter2"}).encode()).decode()
    assert secret in security.stdin[-1]
    assert not any(secret in " ".join(command) for command in seen)


def test_setting_replaces_the_old_value(security):
    keyring = KeychainKeyring()
    keyring._set_item("session", {"long": "y" * 7000})
    keyring._set_item("session", {"short": 1})
    assert keyring._get_item("session") == {"short": 1}
    assert "session.1" not in security.items


def test_set_rejects_values_json_cant_hold(security):
    with pytest.raises(ValueError):
        KeychainKeyring()._set_item("session", {"bad": object()})


def test_set_reports_security_errors(security):
    security.error = "SecKeychainItemCreate failed"
    with pytest.raises(KeyringError, match="SecKeychainItemCreate"):
        KeychainKeyring()._set_item("session", {})


def test_get_missing_item(security):
    with pytest.raises(KeyError):
        KeychainKeyring()._get_item("nothing")


def test_get_item_with_a_bad_count(security):
    security.items["session"] = "many"
    with pytest.raises(KeyError):
        KeychainKeyring()._get_item("session")


def test_get_item_missing_a_chunk(security):
    security.items["session"] = "2"
    security.items["session.0"] = "abcd"
    security.items["session.1"] = ""
    with pytest.raises(KeyError):
        KeychainKeyring()._get_item("session")


def test_get_corrupt_item_deletes_it(security):
    security.items.update({"session": "1", "session.0": base64.b64encode(b"not json").decode()})
    with pytest.raises(KeyError):
        KeychainKeyring()._get_item("session")
    assert security.items == {}


def test_delete(security):
    keyring = KeychainKeyring()
    keyring._set_item("session", {"a": 1})
    keyring._del_item("session")
    assert security.items == {}
    with pytest.raises(KeyError):
        keyring._del_item("session")


def test_find_reports_other_failures(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: types.SimpleNamespace(
        returncode=1, stdout="", stderr="  locked \n"))
    with pytest.raises(KeyringError, match="locked"):
        keychain._find("session")


def test_backend_is_preferred_and_valid():
    assert KeychainKeyring._get_priority() == 100
    assert KeychainKeyring._validate()
    assert json.loads(base64.b64decode(base64.b64encode(b"{}"))) == {}
