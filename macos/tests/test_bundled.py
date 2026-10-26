import importlib.metadata

from proton.vpn.macos.bundled import BundledFinder


def test_finds_bundled_package_versions():
    finder = BundledFinder({"proton-vpn-api-core": "5.8.11"})
    context = importlib.metadata.DistributionFinder.Context(name="proton_vpn_api_core")
    (found,) = finder.find_distributions(context)
    assert found.version == "5.8.11"
    assert not list(finder.find_distributions(importlib.metadata.DistributionFinder.Context(name="requests")))


import json
import sys

import pytest

from proton.vpn.macos import bundled


def test_bundled_distribution_has_a_name_and_version():
    dist = bundled.BundledDistribution("proton-core", "1.2.3")
    assert dist.metadata["Name"] == "proton-core"
    assert dist.version == "1.2.3"
    assert dist.read_text("RECORD") is None
    assert dist.locate_file("x").name == "x"


def test_finder_normalizes_names_and_has_no_specs():
    finder = bundled.BundledFinder({"proton-core": "1.2.3"})
    assert finder.find_spec("anything") is None
    context = importlib.metadata.DistributionFinder.Context(name="Proton_Core")
    assert [d.version for d in finder.find_distributions(context)] == ["1.2.3"]


@pytest.fixture
def meta_path(monkeypatch):
    monkeypatch.setattr(sys, "meta_path", list(sys.meta_path))


def test_install_registers_the_finder_once(tmp_path, monkeypatch, meta_path):
    versions = tmp_path / "bundled.json"
    versions.write_text(json.dumps({"proton-core": "1.2.3"}))
    monkeypatch.setattr(bundled, "VERSIONS", versions)
    monkeypatch.setattr(sys, "meta_path", [f for f in sys.meta_path if not isinstance(f, bundled.BundledFinder)])
    bundled.install()
    bundled.install()
    assert len([f for f in sys.meta_path if isinstance(f, bundled.BundledFinder)]) == 1


def test_install_does_nothing_in_a_development_checkout(tmp_path, monkeypatch, meta_path):
    monkeypatch.setattr(bundled, "VERSIONS", tmp_path / "missing.json")
    monkeypatch.setattr(sys, "meta_path", [f for f in sys.meta_path if not isinstance(f, bundled.BundledFinder)])
    bundled.install()
    assert not [f for f in sys.meta_path if isinstance(f, bundled.BundledFinder)]
