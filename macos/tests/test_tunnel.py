import subprocess
import types

from proton.vpn.macos import tunnel


def fake_ifconfig(monkeypatch, devices):
    ran = []

    def run(command, **kwargs):
        ran.append(command[-1])
        output = devices.get(command[-1])
        return types.SimpleNamespace(returncode=0 if output is not None else 1, stdout=output or "")

    monkeypatch.setattr(subprocess, "run", run)
    return ran


def test_tunnel_device_finds_the_device_with_protons_address(tmp_path, monkeypatch):
    for name in ("utun3", "utun4", "utun5"):
        (tmp_path / f"{name}.sock").touch()
    (tmp_path / "proton.name").touch()
    monkeypatch.setattr(tunnel, "Path", lambda _path: tmp_path)
    ran = fake_ifconfig(monkeypatch, {
        "utun3": "inet 10.9.0.2 --> 10.9.0.2 netmask 0xffffffff\n",
        "utun4": "inet 10.2.0.2 --> 10.2.0.2 netmask 0xffffffff\n",
        "utun5": "inet 10.2.0.2 --> 10.2.0.2 netmask 0xffffffff\n",
    })
    assert tunnel.tunnel_device() == "utun4"
    assert ran == ["utun3", "utun4"]


def test_tunnel_device_skips_failing_devices(tmp_path, monkeypatch):
    (tmp_path / "utun3.sock").touch()
    monkeypatch.setattr(tunnel, "Path", lambda _path: tmp_path)
    fake_ifconfig(monkeypatch, {})
    assert tunnel.tunnel_device() is None


def test_tunnel_device_without_wireguard_devices(tmp_path, monkeypatch):
    monkeypatch.setattr(tunnel, "Path", lambda _path: tmp_path / "missing")
    assert tunnel.tunnel_device() is None
