import json

from proton.vpn.macos import vpn

SWITZERLAND = {"code": "CH", "name": "Switzerland", "aliases": ["swiss"], "servers": 2, "features": []}
SWEDEN = {"code": "SE", "name": "Sweden", "aliases": [], "servers": 1, "features": []}
UK = {"code": "UK", "name": "United Kingdom", "aliases": ["britain", "gb"], "servers": 1, "features": []}


def test_match_ranks_codes_and_aliases_first():
    assert vpn.match("swiss", [SWEDEN, SWITZERLAND])[0] == SWITZERLAND
    assert vpn.match("gb", [UK, SWEDEN]) == [UK]
    assert vpn.match("sw", [SWITZERLAND, SWEDEN]) == [SWEDEN, SWITZERLAND]


def test_match_finds_word_prefixes_and_substrings():
    assert vpn.match("kingdom", [UK, SWEDEN]) == [UK]
    assert vpn.match("eden", [UK, SWEDEN]) == [SWEDEN]


def test_match_lists_everything_without_a_query():
    assert vpn.match("", [UK, SWEDEN]) == [SWEDEN, UK]


def test_servers_filters_by_mode_and_sorts_by_load(tmp_path, monkeypatch):
    def server(name, features=0, load=50, city="Zurich", status=1, tier=2, exit_country="CH"):
        return {"Name": name, "Features": features, "Load": load, "City": city, "Status": status,
                "Tier": tier, "ExitCountry": exit_country, "EntryCountry": name.split("#")[0].split("-")[0]}

    servers = [
        server("CH#2", load=70),
        server("CH#1", load=20, features=vpn.P2P_FEATURE),
        server("CH#3", status=0),
        server("CH#4", city="Geneva", load=10),
        server("IS-CH#1", features=vpn.SECURE_CORE_FEATURE),
        server("SE#1", exit_country="SE"),
    ]
    path = tmp_path / "serverlist.json"
    path.write_text(json.dumps({"LogicalServers": servers, "MaxTier": 2}))
    monkeypatch.setattr(vpn, "SERVER_LIST", path)

    cities = vpn.servers("CH")
    assert [c["city"] for c in cities] == ["Geneva", "Zurich"]
    assert [s["name"] for s in cities[1]["servers"]] == ["CH#1", "CH#2"]
    assert cities[1]["servers"][0]["features"] == ["p2p"]

    assert [s["name"] for c in vpn.servers("CH", "p2p") for s in c["servers"]] == ["CH#1"]
    assert [s["name"] for c in vpn.servers("CH", "sc") for s in c["servers"]] == ["IS-CH#1"]
