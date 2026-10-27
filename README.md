# Proton VPN CLI for macOS

[![PyPI](https://img.shields.io/pypi/v/proton-vpn-cli-macos.svg?style=flat-square)](https://pypi.org/project/proton-vpn-cli-macos/)
[![CI](https://img.shields.io/github/actions/workflow/status/stevelacey/proton-vpn-cli-macos/ci.yml?branch=main&style=flat-square)](https://github.com/stevelacey/proton-vpn-cli-macos/actions/workflows/ci.yml?query=branch:main)
[![Coverage](https://img.shields.io/codecov/c/github/stevelacey/proton-vpn-cli-macos?style=flat-square)](https://codecov.io/gh/stevelacey/proton-vpn-cli-macos)
[![Downloads](https://img.shields.io/pepy/dt/proton-vpn-cli-macos.svg?style=flat-square)](https://pypi.org/project/proton-vpn-cli-macos/)
[![License](https://img.shields.io/github/license/stevelacey/proton-vpn-cli-macos?style=flat-square)](https://github.com/stevelacey/proton-vpn-cli-macos/blob/main/LICENSE)

A fork of the [Proton VPN CLI](https://github.com/ProtonVPN/proton-vpn-cli) that adds macOS support.

## Better together

- **[Proton VPN Menu Bar](https://github.com/stevelacey/proton-vpn-menubar)**: status, countries and settings in your menu bar
- **[Alfred Proton VPN](https://github.com/stevelacey/alfred-proton-vpn)**: `vpn swiss` from Alfred

They all drive the same connection: connect from one and the others keep up. Use them instead of
Proton's Mac app, not alongside it, since it runs its own VPN connection that these can't see or control.

## Install

```sh
brew install stevelacey/tap/proton-vpn-cli
vpn setup
protonvpn signin <username>
```

`vpn setup` asks for your password once, so connecting doesn't need it again. Connecting needs root
for `wg-quick`, `pfctl` and `networksetup`; setup installs a small root-owned helper that only does
those, and only takes plain WireGuard configs.

Or install it with `uv tool install proton-vpn-cli-macos` (or pipx), plus `brew install wireguard-tools bash`.

## Use

```sh
vpn                          # status
vpn swiss                    # fastest server in a country, by name, code or alias
vpn fastest
vpn random japan
vpn sc japan                 # Secure Core; also p2p and tor
vpn CH#871                   # a specific server
vpn city new york
vpn servers ch               # servers by city, least loaded first
vpn off
vpn dns cloudflare           # proton, cloudflare, google, opendns or quad9
vpn set kill-switch standard
vpn set netshield malware-ads-trackers
vpn set port-forwarding on
vpn help
```

`protonvpn` has the full set of commands and options:

```sh
protonvpn connect --country CH
protonvpn connect --city "New York" --p2p
protonvpn config set netshield malware-ads-trackers
protonvpn status
protonvpn --help
```

## How it works

- Connections are WireGuard, through `wg-quick`, with the local agent confirming each one and
  applying NetShield, port forwarding and the rest.
- The kill switch is pf rules in their own anchor; `/etc/pf.conf` is left alone.
- Sign-in is kept in the macOS Keychain.
- The release wheel includes the core libraries (`macos/vendor`) and the Rust extension.

## Develop

```sh
git clone --recurse-submodules=macos/vendor git@github.com:stevelacey/proton-vpn-cli-macos.git
cd proton-vpn-cli-macos/macos
brew install rust wireguard-tools bash
scripts/build-platform
uv sync
uv run pytest
uv run vpn setup
```

## License

GPLv3. Copyright (c) 2026 Proton AG; see
[COPYING](https://github.com/stevelacey/proton-vpn-cli-macos/blob/main/COPYING.md),
[LICENSE](https://github.com/stevelacey/proton-vpn-cli-macos/blob/main/LICENSE) and the
[contribution policy](https://github.com/stevelacey/proton-vpn-cli-macos/blob/main/CONTRIBUTING.md).
