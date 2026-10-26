"""
Package metadata for the Proton packages the release wheel bundles.

Proton's code looks up its own versions with importlib.metadata (api-core's also goes into the
app version it sends Proton's API), but bundled into one wheel they're no longer installed as
separate distributions. build-wheel records their versions in bundled.json, and this makes them
findable again. In a development checkout, where they're installed, there's no bundled.json.
"""
import importlib.metadata
import json
import sys
from pathlib import Path

VERSIONS = Path(__file__).with_name("bundled.json")


class BundledDistribution(importlib.metadata.Distribution):
    """A bundled package, with just a name and version."""

    def __init__(self, name: str, version: str):
        self._name, self._version = name, version

    def read_text(self, filename):
        if filename == "METADATA":
            return f"Metadata-Version: 2.1\nName: {self._name}\nVersion: {self._version}\n"
        return None

    def locate_file(self, path):
        return Path(__file__).parent / path


class BundledFinder(importlib.metadata.DistributionFinder):
    """Finds the bundled packages by name."""

    def __init__(self, versions: dict[str, str]):
        self._versions = versions

    def find_spec(self, *_args, **_kwargs):
        return None

    def find_distributions(self, context=importlib.metadata.DistributionFinder.Context()):
        normalized = (context.name or "").replace("_", "-").lower()
        if normalized in self._versions:
            yield BundledDistribution(normalized, self._versions[normalized])


def install():
    """Makes the bundled packages' metadata findable, when this is the release wheel."""
    if VERSIONS.exists() and not any(isinstance(f, BundledFinder) for f in sys.meta_path):
        sys.meta_path.append(BundledFinder(json.loads(VERSIONS.read_text(encoding="utf-8"))))
