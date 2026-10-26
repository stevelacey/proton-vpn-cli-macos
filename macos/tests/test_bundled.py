import importlib.metadata

from proton.vpn.macos.bundled import BundledFinder


def test_finds_bundled_package_versions():
    finder = BundledFinder({"proton-vpn-api-core": "5.8.11"})
    context = importlib.metadata.DistributionFinder.Context(name="proton_vpn_api_core")
    (found,) = finder.find_distributions(context)
    assert found.version == "5.8.11"
    assert not list(finder.find_distributions(importlib.metadata.DistributionFinder.Context(name="requests")))
