"""Proton VPN, the short way.

  vpn                  show the current connection (--json for the menu bar app)
  vpn <country>        connect to the fastest server in a country, e.g. vpn swiss, vpn ch, vpn japan
  vpn <server>         connect to a specific server, e.g. vpn CH#10
  vpn fastest          connect to the fastest server anywhere
  vpn random [country] connect to a random server (anywhere, or in a country)
  vpn sc [country]     connect through Secure Core; also p2p, tor, e.g. vpn p2p nl
  vpn off              disconnect
  vpn setup            one-time setup, so connecting doesn't need your password (--check)
  vpn account          the signed-in account and plan (--json)
  vpn signout          sign out (sign in with: protonvpn signin <username>)
  vpn city [mode] <city>  connect to the fastest server in a city, e.g. vpn city new york
  vpn servers [mode] <country>  list a country's servers by city, least loaded first (--json)
  vpn list [query]     list matching countries (--alfred for Alfred script filter JSON, --json)
  vpn dns <choice>     proton, cloudflare, google, opendns or quad9
  vpn forward          keep the forwarded port alive (the menu bar app runs this)
  vpn settings         show NetShield, kill switch and port forwarding (--json)
  vpn set <setting> <value>   change a setting, as protonvpn config set

Connecting and disconnecting go through Proton's own CLI (protonvpn). Status and the
country list are read from its caches, so they're instant and work offline.
"""
import importlib.util
import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path

from proton.vpn.macos.tunnel import tunnel_device

CACHE = Path.home() / ".cache" / "Proton" / "VPN"
SERVER_LIST = CACHE / "serverlist.json"
CONNECTION = CACHE / "connection" / "connection_persistence.json"
EXIT_IP = CACHE / "connection" / "exit_ip"
WG_CONFIG = CACHE / "connection" / "proton.conf"
NAT_PMP_GATEWAY = "10.2.0.1"

# DNS choices besides Proton's own.
DNS_PROVIDERS = {
    "cloudflare": ["1.1.1.1", "1.0.0.1"],
    "google": ["8.8.8.8", "8.8.4.4"],
    "opendns": ["208.67.222.222", "208.67.220.220"],
    "quad9": ["9.9.9.9", "149.112.112.112"],
}
SETTINGS = Path.home() / ".config" / "Proton" / "VPN" / "settings.json"
# Flag icons the Alfred workflow renders into its cache.
FLAGS = Path(os.environ["alfred_workflow_cache"], "flags") if os.environ.get("alfred_workflow_cache") else None

ALIASES = {
    "AE": ["uae", "emirates", "dubai"],
    "BA": ["bosnia"],
    "CH": ["swiss", "schweiz", "suisse"],
    "CN": ["china"],
    "CZ": ["czech", "czech republic"],
    "DE": ["german", "deutschland"],
    "ES": ["spanish", "espana"],
    "FR": ["french"],
    "UK": ["gb", "britain", "great britain", "england", "british"],
    "HK": ["hongkong"],
    "IT": ["italian"],
    "JP": ["japanese"],
    "KR": ["korea"],
    "MM": ["burma"],
    "NL": ["holland", "dutch"],
    "PS": ["palestine"],
    "TR": ["turkey"],
    "US": ["usa", "america", "states"],
    "CI": ["ivory coast"],
    "CD": ["congo", "drc"],
}

# Server feature bits, as in api-core's ServerFeatureEnum.
SECURE_CORE_FEATURE, TOR_FEATURE, P2P_FEATURE, STREAMING_FEATURE = 1, 2, 4, 8

SERVER_NAME = re.compile(r"^[A-Za-z]{2}(-[A-Za-z]{2})?#\d+(-TOR)?$", re.IGNORECASE)
SECURE_CORE = re.compile(r"^[A-Z]{2}-[A-Z]{2}#")

# Leading words that pick which servers to connect to, as Proton CLI options.
MODES = {
    "random": "--random",
    "securecore": "--securecore",
    "sc": "--securecore",
    "p2p": "--p2p",
    "tor": "--tor",
}


def _country_codes():
    """Proton's country names, loaded by path to skip importing the rest of api-core."""
    import proton.vpn  # pylint: disable=import-outside-toplevel
    for path in proton.vpn.__path__:
        file = Path(path, "session", "servers", "country_codes.py")
        if file.exists():
            spec = importlib.util.spec_from_file_location("country_codes", file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise RuntimeError("Proton's country_codes module is missing")


def country_name(code):
    return _country_codes().get_country_name_by_code(code) or code


def fold(s):
    return "".join(c for c in unicodedata.normalize("NFKD", s.lower()) if not unicodedata.combining(c))


def logicals():
    try:
        return json.loads(SERVER_LIST.read_text())["LogicalServers"]
    except (OSError, ValueError, KeyError):
        return []


def countries():
    """Countries with regular servers, and what any of their servers support."""
    found = {}
    for logical in logicals():
        features = logical.get("Features", 0)
        country = found.setdefault(logical["ExitCountry"], {"servers": 0, "features": set()})
        if features & SECURE_CORE_FEATURE:
            country["features"].add("securecore")
            continue
        if features & TOR_FEATURE:
            country["features"].add("tor")
            continue
        country["servers"] += 1
        if features & P2P_FEATURE:
            country["features"].add("p2p")
        if features & STREAMING_FEATURE:
            country["features"].add("streaming")
        if logical.get("HostCountry"):
            # Smart routing: the server is hosted in another country.
            country["features"].add("smartrouting")

    names = _country_codes()
    return [
        {
            "code": code,
            "name": names.get_country_name_by_code(code) or code,
            "servers": country["servers"],
            "aliases": ALIASES.get(code, []),
            "features": sorted(country["features"]),
        }
        for code, country in found.items()
        if country["servers"]
    ]


def servers(code, mode=None):
    """A country's online servers for a mode (sc, p2p, tor or none), by city, least loaded first."""
    try:
        max_tier = json.loads(SERVER_LIST.read_text()).get("MaxTier", 2)
    except (OSError, ValueError):
        max_tier = 2
    cities = {}
    for logical in logicals():
        features = logical.get("Features", 0)
        if logical["ExitCountry"] != code or logical.get("Status") != 1 or logical.get("Tier", 0) > max_tier:
            continue
        if bool(features & SECURE_CORE_FEATURE) != (mode in ("sc", "securecore")):
            continue
        if bool(features & TOR_FEATURE) != (mode == "tor"):
            continue
        if mode == "p2p" and not features & P2P_FEATURE:
            continue
        cities.setdefault(logical.get("City") or "", []).append({
            "name": logical["Name"],
            "load": logical.get("Load", 0),
            "entry": logical.get("EntryCountry"),
            "features": [name for flag, name in ((P2P_FEATURE, "p2p"), (STREAMING_FEATURE, "streaming"),
                                                 (TOR_FEATURE, "tor")) if features & flag],
        })
    return [
        {"city": city, "servers": sorted(found, key=lambda s: (s["load"], s["name"]))}
        for city, found in sorted(cities.items())
    ]


def match(query, items):
    """Rank countries for a query: code, name, then alias and word prefixes, then substrings."""
    q = fold(query.strip())
    if not q:
        return sorted(items, key=lambda c: c["name"])

    ranked = []
    for c in items:
        name = fold(c["name"])
        aliases = c["aliases"]
        words = name.replace("-", " ").replace("&", " ").split()
        if q == c["code"].lower() or q == name or q in aliases:
            score = 0
        elif name.startswith(q) or any(a.startswith(q) for a in aliases):
            score = 1
        elif any(w.startswith(q) for w in words):
            score = 2
        elif q in name:
            score = 3
        else:
            continue
        ranked.append((score, c["name"], c))
    return [c for _, _, c in sorted(ranked, key=lambda r: (r[0], r[1]))]


def status():
    """The current connection, from the files Proton's CLI and wg-quick leave behind."""
    try:
        persisted = json.loads(CONNECTION.read_text())
        server = persisted["server"]
    except (OSError, ValueError, KeyError):
        persisted, server = {}, None

    # The backend writes the tunnel's config before Proton confirms the connection
    # and saves it, so a recent config for another connection means one is starting.
    try:
        header = WG_CONFIG.read_text().splitlines()[:2]
        connecting = (
            header[0].removeprefix("# Connection ") != persisted.get("connection_id")
            and time.time() - WG_CONFIG.stat().st_mtime < 60
        )
    except (OSError, IndexError):
        connecting = False
    if connecting:
        return {"state": "Connecting", "server": header[1].removeprefix("# Server ")}

    if not server:
        return {"state": "Disconnected"}

    result = {
        "state": "Connected" if tunnel_device() else "Dropped",
        "server": server.get("server_name"),
        "entry_ip": server.get("server_ip"),
    }
    for logical in logicals():
        if logical.get("Name") == result["server"]:
            result["code"] = logical["ExitCountry"]
            result["country"] = country_name(logical["ExitCountry"])
            result["city"] = logical.get("City")
            break
    try:
        result["ip"] = EXIT_IP.read_text().strip()
    except OSError:
        pass
    try:
        if result["state"] == "Connected" and settings()["port_forwarding"]:
            result["port"] = int(forwarded_port_path().read_text().strip())
    except (OSError, ValueError):
        pass
    return result


def settings():
    """Proton's settings that the menu bar and Alfred toggle, from its settings file."""
    try:
        data = json.loads(SETTINGS.read_text())
    except (OSError, ValueError):
        data = {}
    features = data.get("features", {})
    return {
        "netshield": features.get("netshield", 1),
        "kill_switch": data.get("killswitch", 0),
        "port_forwarding": features.get("port_forwarding", False),
        "dns": dns_choice(data.get("custom_dns", {})),
    }


def dns_choice(custom_dns):
    """Which DNS is in use: proton, one of DNS_PROVIDERS, or custom."""
    if not custom_dns.get("enabled"):
        return "proton"
    ips = [entry.get("ip") if isinstance(entry, dict) else entry for entry in custom_dns.get("ip_list", [])]
    return next((name for name, servers in DNS_PROVIDERS.items() if ips == servers), "custom")


def set_dns(choice):
    """Switches DNS, reconnecting to the same server, since DNS is part of the tunnel's config."""
    from proton.vpn.macos.cli import locked  # pylint: disable=import-outside-toplevel
    if choice not in ("proton", *DNS_PROVIDERS):
        sys.exit(f"vpn: unknown DNS '{choice}' (proton, {', '.join(DNS_PROVIDERS)})")

    with locked():
        current = status()
        if current["state"] == "Connected":
            run_protonvpn("disconnect")
        if choice in DNS_PROVIDERS:
            run_protonvpn("config", "set", "custom-dns", "on", "--dns", ",".join(DNS_PROVIDERS[choice]))
        else:
            run_protonvpn("config", "set", "custom-dns", "off")
        if current["state"] == "Connected":
            protonvpn("connect", current["server"])


def toggles(current_settings):
    """Commands that flip each setting, as (title, arg, keywords)."""
    on = current_settings
    return [
        ("Turn NetShield off" if on["netshield"] else "Turn NetShield on",
         f"set netshield {'off' if on['netshield'] else 'malware-ads-trackers'}",
         ["netshield", "adblock", "ads"]),
        ("Turn kill switch off" if on["kill_switch"] else "Turn kill switch on",
         f"set kill-switch {'off' if on['kill_switch'] else 'standard'}",
         ["kill switch", "killswitch"]),
        ("Turn port forwarding off" if on["port_forwarding"] else "Turn port forwarding on",
         f"set port-forwarding {'off' if on['port_forwarding'] else 'on'}",
         ["port forwarding", "forwarding"]),
    ]


def set_setting(name, value):
    """
    Changes a setting through Proton's CLI, which refuses to change the kill switch
    while connected; for that, this disconnects, changes it and reconnects.
    """
    from proton.vpn.macos.cli import locked  # pylint: disable=import-outside-toplevel
    with locked():
        current = status()
        if name != "kill-switch" or current["state"] != "Connected":
            protonvpn("config", "set", name, value)
            return

        run_protonvpn("disconnect")
        run_protonvpn("config", "set", name, value)
        protonvpn("connect", current["server"])


def run_protonvpn(*args):
    """Runs Proton's CLI in a separate process, for when one command isn't the last."""
    import subprocess  # pylint: disable=import-outside-toplevel
    result = subprocess.run([sys.executable, "-m", "proton.vpn.macos.cli", *args], check=False)
    if result.returncode:
        sys.exit(result.returncode)


def account():
    """The signed-in account's name and plan, or None when signed out."""
    from proton.vpn.macos import cli  # pylint: disable=import-outside-toplevel
    cli.install()
    # pylint: disable=import-outside-toplevel
    from proton.vpn.core.api import ProtonVPNAPI, ClientTypeMetadata
    api = ProtonVPNAPI(ClientTypeMetadata(type="cli"))
    if not api.is_user_logged_in():
        return None
    return {"username": api.account_name, "plan": api.account_data.plan_title}


def signin_from_stdin():
    """
    Signs in with Proton's own signin command, answering its prompts from lines on stdin,
    for the menu bar app: the username, then the password, then 2FA codes when asked for.

    Proton's CLI reads the password from the terminal, so it runs in a pseudo-terminal.
    Prints "2fa" when a code is needed, "2fa invalid" when one was wrong, then "ok <account>"
    or "error <message>".
    """
    import pty  # pylint: disable=import-outside-toplevel
    import select  # pylint: disable=import-outside-toplevel

    def reply(line):
        print(line, flush=True)

    username = sys.stdin.readline().strip()
    password = sys.stdin.readline().rstrip("\n")
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, "-m", "proton.vpn.macos.cli", "signin", username, "--totp"])

    output = ""
    while True:
        try:
            ready, _, _ = select.select([fd], [], [], 120)
            chunk = os.read(fd, 4096).decode(errors="replace") if ready else ""
        except OSError:
            chunk = ""
        if not chunk:
            break
        output += chunk
        if output.rstrip().endswith("Password:"):
            os.write(fd, (password + "\n").encode())
            output = ""
        elif output.rstrip().endswith("2FA Token:"):
            reply("2fa invalid" if "Invalid two-factor" in output else "2fa")
            os.write(fd, (sys.stdin.readline().strip() + "\n").encode())
            output = ""
    _, status = os.waitpid(pid, 0)
    found = re.search(r"Successfully signed in as '(.+)'", output)
    if status == 0 and found:
        reply(f"ok {found.group(1)}")
    else:
        errors = [line.removeprefix("Error: ") for line in output.splitlines() if line.startswith("Error")]
        reply("error " + (errors[-1] if errors else output.strip().splitlines()[-1] if output.strip() else "Sign in failed"))


def forwarded_port_path():
    import tempfile  # pylint: disable=import-outside-toplevel
    return Path(tempfile.gettempdir(), "Proton", "VPN", "forwarded_port")


def nat_pmp_map(protocol, lifetime=60):
    """Asks Proton's server for a port mapping over NAT-PMP, returning the external port."""
    import socket  # pylint: disable=import-outside-toplevel
    import struct  # pylint: disable=import-outside-toplevel
    opcode = {"udp": 1, "tcp": 2}[protocol]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        # Version 0, opcode, reserved, internal port 0 (Proton maps it 1:1), suggested port 0, lifetime.
        sock.sendto(struct.pack("!BBHHHI", 0, opcode, 0, 0, 0, lifetime), (NAT_PMP_GATEWAY, 5351))
        data, _ = sock.recvfrom(16)
    _, _, result, _, _, external, _ = struct.unpack("!BBHIHHI", data)
    if result:
        raise OSError(f"NAT-PMP error {result}")
    return external


def forward():
    """
    Keeps the forwarded port alive while connected with port forwarding on.

    Proton's server hands out the port for 60 seconds at a time; its CLI only
    renews it while it's running, i.e. while connecting. The menu bar app runs
    this alongside a connection.
    """
    path = forwarded_port_path()
    while status()["state"] == "Connected" and settings()["port_forwarding"]:
        try:
            port = nat_pmp_map("udp")
            nat_pmp_map("tcp")
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists() or path.read_text().strip() != str(port):
                path.write_text(str(port))
                print(f"Forwarded port {port}", flush=True)
        except OSError as exc:
            print(f"vpn: couldn't renew the forwarded port: {exc}", file=sys.stderr, flush=True)
        time.sleep(45)


def describe(s):
    if s["state"] == "Disconnected":
        return "Disconnected"
    if s["state"] == "Connecting":
        return f"Connecting to {s['server']}…"
    place = ", ".join(filter(None, [s.get("city"), s.get("country")]))
    text = f"{s['state']} to {s['server']}" if s["state"] == "Connected" else f"Dropped connection to {s['server']}"
    if place:
        text += f" ({place})"
    if s.get("ip") and s["state"] == "Connected":
        text += f", IP {s['ip']}"
    if s.get("port"):
        text += f", port {s['port']}"
    return text


def protonvpn(*args):
    """Runs Proton's CLI in this process."""
    from proton.vpn.macos import cli  # pylint: disable=import-outside-toplevel
    from proton.vpn.macos import privileged  # pylint: disable=import-outside-toplevel
    if args and args[0] == "connect" and not privileged.is_set_up():
        sys.exit("vpn: connecting needs a one-time setup first: run `vpn setup`, which asks for your password.")
    sys.argv[0] = "protonvpn"
    cli.install()
    from proton.vpn.cli import main as cli_main  # pylint: disable=import-outside-toplevel
    with cli.locked():
        cli_main(allow_concurrency=True, cli_args=list(args))


def connect(args):
    """Connects to the fastest server in a country, or a specific server, with any modes in front."""
    args = " ".join(args).split()  # Alfred passes everything as one argument
    options = []
    while args and args[0] in MODES:
        options.append(MODES[args.pop(0)])
    query = " ".join(args)

    if not query or fold(query) in ("fastest", "any"):
        protonvpn("connect", *options)
        return

    if SERVER_NAME.match(query):
        protonvpn("connect", query.upper(), *options)
        return

    found = match(query, countries())
    if not found:
        if not SERVER_LIST.exists():
            # No cached server list yet, so let Proton's CLI work out the country.
            protonvpn("connect", "--country", query, *options)
            return
        sys.exit(f"vpn: no country matches '{query}' (try: vpn list)")

    current = status()
    if not options and current["state"] == "Connected" and current.get("code") == found[0]["code"] \
            and not SECURE_CORE.search(current["server"] or ""):
        print(f"Already connected to {current['server']} ({current['country']})")
        return
    protonvpn("connect", "--country", found[0]["code"], *options)


def alfred(items, query):
    """Alfred script filter results; mode words in front (sc, p2p, tor, random) carry through."""
    words = query.split()
    modes = []
    while words and words[0].lower() in MODES:
        modes.append(words.pop(0).lower())
    query = " ".join(words)
    prefix = " ".join(modes)
    labels = {"--securecore": "Secure Core", "--p2p": "P2P", "--tor": "Tor", "--random": "random server"}
    note = ", ".join(labels[MODES[m]] for m in modes)

    current = status()
    results = []
    weak = []
    if query and not modes:
        strong, weak = commands(query, current)
        results += strong
    # In a mode, only countries that have servers for it.
    required = {"sc": "securecore", "securecore": "securecore", "p2p": "p2p", "tor": "tor"}
    for mode in modes:
        if mode in required:
            items = [c for c in items if required[mode] in c["features"]]
    if not query and not modes:
        results.append({"title": describe(current), "subtitle": "Proton VPN", "valid": False,
                        "icon": icon(current.get("code"))})
        if current["state"] != "Disconnected":
            results.append({"title": "Disconnect", "arg": "off", "autocomplete": "off"})
        results.append({"title": "Fastest server", "subtitle": "Quick Connect", "arg": "fastest", "autocomplete": "fastest"})
        results.append({"title": "Random server", "subtitle": "Anywhere", "arg": "random", "autocomplete": "random "})
        results.append({"title": "Secure Core", "subtitle": "Fastest Secure Core server; add a country", "arg": "sc",
                        "autocomplete": "sc "})
    elif not query:
        results.append({"title": f"Fastest server ({note})", "arg": prefix, "autocomplete": prefix + " "})
    for c in match(query, items) if query else []:
        results.append({
            "uid": f"{prefix} {c['code']}".strip(),
            "title": c["name"] + (f" ({note})" if note else ""),
            "subtitle": f"{c['code']} · {c['servers']} servers",
            "arg": f"{prefix} {c['code']}".strip(),
            "autocomplete": f"{prefix} {c['name']}".strip(),
            "icon": icon(c["code"]),
        })
    results += weak
    print(json.dumps({"items": results}))


def commands(query, current):
    """Alfred results for commands whose title or keywords start with the query."""
    candidates = []
    if current["state"] != "Disconnected":
        candidates.append(("Disconnect", describe(current), "off", ["off", "disconnect", "stop"]))
    candidates += [
        ("Fastest server", "Quick Connect", "fastest", ["fastest", "quick", "connect"]),
        ("Random server", "Anywhere", "random", ["random"]),
        ("Secure Core", "Fastest Secure Core server; add a country", "sc", ["sc", "secure core"]),
        ("P2P", "Fastest P2P server; add a country", "p2p", ["p2p", "torrent"]),
        ("Tor", "Fastest Tor server; add a country", "tor", ["tor", "onion"]),
    ]
    for title, arg, keywords in toggles(settings()):
        candidates.append((title, "Proton VPN setting", arg, keywords))
    in_use = settings()["dns"]
    for choice in ["proton", *DNS_PROVIDERS]:
        name = {"proton": "Proton", "opendns": "OpenDNS"}.get(choice, choice.title())
        candidates.append((
            f"Use {name}{'' if name.endswith('DNS') else ' DNS'}" + (" (in use)" if choice == in_use else ""),
            "Through the VPN",
            f"dns {choice}", ["dns", choice],
        ))

    q = fold(query.strip())
    strong, weak = [], []
    for title, subtitle, arg, keywords in candidates:
        result = {"title": title, "subtitle": subtitle, "arg": arg,
                  "autocomplete": arg + " " if arg in MODES else arg}
        if any(k.startswith(q) for k in [title.lower(), *keywords]):
            strong.append(result)
        elif any(w.startswith(q) for k in [title.lower(), *keywords] for w in k.split()):
            weak.append(result)
    return strong, weak


def icon(code):
    """The country's flag, when the Alfred workflow has rendered it."""
    path = FLAGS / f"{code}.png" if FLAGS and code else None
    return {"path": str(path)} if path and path.exists() else {}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    flags = [a for a in argv if a.startswith("--")]
    words = [a for a in argv if not a.startswith("--")]

    if not words or words[0] == "status":
        current = status()
        print(json.dumps(current) if "--json" in flags else describe(current))
    elif words[0] in ("off", "disconnect", "down"):
        if status()["state"] == "Disconnected":
            print("Already disconnected")
        else:
            protonvpn("disconnect")
    elif words[0] in ("fastest", "on", "quick"):
        connect(words[1:])
    elif words[0] == "setup":
        from proton.vpn.macos import privileged  # pylint: disable=import-outside-toplevel
        if "--check" in flags:
            sys.exit(0 if privileged.is_set_up() else 1)
        user = argv[argv.index("--user") + 1] if "--user" in argv else None
        privileged.setup(user)
    elif words[0] in ("signin", "login") and "--stdin" in flags:
        signin_from_stdin()
    elif words[0] == "account":
        current = account()
        if "--json" in flags:
            print(json.dumps(current))
        else:
            print(f"{current['username']} ({current['plan']})" if current else "Signed out")
    elif words[0] in ("signout", "logout"):
        protonvpn("signout")
    elif words[0] == "dns" and len(words) == 2:
        set_dns(words[1].lower())
    elif words[0] == "forward":
        forward()
    elif words[0] == "settings":
        current = settings()
        print(json.dumps(current) if "--json" in flags else "\n".join(f"{k}: {v}" for k, v in current.items()))
    elif words[0] == "set" and len(words) == 3:
        set_setting(*words[1:])
    elif words[0] == "city" and len(words) >= 2:
        args = " ".join(words[1:]).split()
        options = []
        while args and args[0] in MODES:
            options.append(MODES[args.pop(0)])
        protonvpn("connect", "--city", " ".join(args), *options)
    elif words[0] == "servers" and len(words) >= 2:
        mode = words[1].lower() if len(words) == 3 else None
        found = match(words[-1], countries())
        cities = servers(found[0]["code"], mode) if found else []
        if "--json" in flags:
            print(json.dumps(cities))
        else:
            for city in cities:
                print(city["city"])
                for server in city["servers"]:
                    print(f"  {server['name']:<10} {server['load']:>3}%  {' '.join(server['features'])}")
    elif words[0] in ("list", "ls"):
        query = " ".join(words[1:])
        items = countries()
        if "--alfred" in flags:
            alfred(items, query)
        elif "--json" in flags:
            print(json.dumps(match(query, items)))
        else:
            for c in match(query, items):
                print(f"{c['code']}  {c['name']}  ({c['servers']} servers)")
    elif words[0] in ("help",) or "--help" in flags or "-h" in argv:
        print(__doc__.strip())
    else:
        connect(words)


if __name__ == "__main__":
    main()
