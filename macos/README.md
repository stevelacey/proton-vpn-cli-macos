# Proton VPN CLI for macOS

Proton VPN's official [Linux CLI](https://github.com/ProtonVPN/proton-vpn-cli), running on macOS. Proton's
code is used as is; this adds the macOS parts it's missing:

- a WireGuard connection backend, using wireguard-tools' `wg-quick` instead of NetworkManager, with
  Proton's own local agent confirming the connection and applying NetShield, port forwarding and so on
- a kill switch, as pf rules in their own anchor (`/etc/pf.conf` is left alone)
- sign-in kept in the macOS Keychain
- `vpn`, a short front end with country aliases, Secure Core/P2P/Tor modes, DNS choices and JSON output

It works with the [menu bar app](https://github.com/stevelacey/proton-vpn-menubar) and the
[Alfred workflow](https://github.com/stevelacey/alfred-proton-vpn).

Unofficial: not made or endorsed by Proton AG.

## Install

```sh
brew install stevelacey/tap/proton-vpn-cli-macos
vpn setup                       # once; asks for your password
protonvpn signin <username>
```

Or with uv (`uv tool install proton-vpn-cli-macos`) or pipx, plus `brew install wireguard-tools bash`.

`vpn setup` installs a small root-owned helper (`/usr/local/libexec/proton-vpn-cli-macos-helper`) and a
sudo rule that lets you run it without a password. Connecting needs root for `wg-quick`, `pfctl` and
`networksetup`, and the helper only does those: it takes a tunnel config only if it's a plain WireGuard
config, since `wg-quick` would run `PostUp` and similar lines as root.

## Use

```sh
vpn                      # status
vpn swiss                # fastest server in Switzerland
vpn fastest
vpn random japan
vpn sc japan             # through Secure Core; also p2p, tor
vpn CH#871               # a specific server
vpn city new york
vpn servers ch           # servers by city, least loaded first
vpn off
vpn dns cloudflare       # proton, cloudflare, google, opendns or quad9
vpn set kill-switch standard
vpn set netshield malware-ads-trackers
vpn set port-forwarding on
vpn help
```

Proton's own commands work too: `protonvpn connect --country CH`, `protonvpn config set …` and so on.

## How it works

Everything is in [`macos/`](https://github.com/stevelacey/proton-vpn-cli-macos/tree/stable/macos), so this
fork's other files stay as Proton has them and merging their changes stays simple.

- `src/proton/vpn/macos/wireguard.py` registers the WireGuard backend in api-core's protocol registry, in
  place of NetworkManager.
- `killswitch.py` and `keychain.py` are plugged in through Proton's loader.
- `cli.py` is the `protonvpn` entry point. It installs those and points Proton's Linux paths at macOS
  ones before running Proton's CLI.
- `vendor/` has Proton's core libraries as submodules. Proton doesn't publish them to PyPI, so the
  release wheel bundles them, along with Proton's Rust extension (`scripts/build-platform` builds it
  without its Linux-only parts).

## Development

```sh
git clone --recurse-submodules=macos/vendor git@github.com:stevelacey/proton-vpn-cli-macos.git
cd proton-vpn-cli-macos/macos
brew install rust wireguard-tools bash
scripts/build-platform
uv sync
uv run pytest
uv run vpn setup
```

Releases are tagged `v*`; GitHub Actions builds a universal wheel, publishes it to PyPI and updates the
Homebrew formula.

## License

GPLv3, like Proton's code.
