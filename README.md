# Proton VPN CLI for macOS

[![PyPI](https://img.shields.io/pypi/v/proton-vpn-cli-macos.svg?style=flat-square)](https://pypi.org/project/proton-vpn-cli-macos/)
[![CI](https://img.shields.io/github/actions/workflow/status/stevelacey/proton-vpn-cli-macos/ci.yml?branch=main&style=flat-square)](https://github.com/stevelacey/proton-vpn-cli-macos/actions/workflows/ci.yml?query=branch:main)
[![Coverage](https://img.shields.io/codecov/c/github/stevelacey/proton-vpn-cli-macos/main?style=flat-square)](https://codecov.io/gh/stevelacey/proton-vpn-cli-macos)
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
protonvpn setup
```

`protonvpn setup` asks for your Mac password once, so connecting doesn't need it again, then signs
you in to your Proton account. Connecting needs root for `wg-quick`, `pfctl` and `networksetup`;
setup installs a small root-owned helper that only does those, and only takes plain WireGuard configs.
It also copies `wg-quick`, `wg`, `wireguard-go` and `bash` from Homebrew into a root-owned folder, since
anything running as you can change Homebrew's files; the helper only runs those copies and macOS's own
commands. Run `protonvpn setup` again to pick up Homebrew updates to them.

Or install it with `uv tool install proton-vpn-cli-macos` (or pipx), plus `brew install wireguard-tools bash`.

## Use

```sh
protonvpn                          # status
protonvpn swiss                    # fastest server in a country, by name, code or alias
protonvpn fastest
protonvpn random japan
protonvpn sc japan                 # Secure Core; also p2p and tor
protonvpn CH#871                   # a specific server
protonvpn city new york
protonvpn servers ch               # servers by city, least loaded first
protonvpn dns cloudflare           # proton, cloudflare, google, opendns or quad9
protonvpn set kill-switch standard
protonvpn set netshield malware-ads-trackers
protonvpn set port-forwarding on   # prints the forwarded port
protonvpn off
protonvpn help
```

Proton's own commands and options work too:

```sh
protonvpn connect --city "New York" --p2p
protonvpn config set netshield malware-ads-trackers
protonvpn countries list
protonvpn connect --help
```

## How it works

- Connections are WireGuard, through `wg-quick`, with the local agent confirming each one and
  applying NetShield, port forwarding and the rest.
- The kill switch is pf rules in their own anchor; `/etc/pf.conf` is left alone.
- While you're connected, a LaunchAgent runs `protonvpn watch` in the background, as Proton's apps
  do while they're open. If the tunnel stops carrying traffic, say when its server goes down, it
  reconnects to a similar server. It also keeps renewing the forwarded port, which Proton's server
  only hands out for a minute at a time. It's added the first time you connect, and stops by itself
  when you disconnect.
- Switching servers over a dead tunnel disconnects it first, rather than waiting out Proton's API
  timeouts through it.
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
uv run python -m proton.vpn.macos.vpn setup
```

## License

GPLv3. Copyright (c) 2026 Proton AG; see
[COPYING](https://github.com/stevelacey/proton-vpn-cli-macos/blob/main/COPYING.md),
[LICENSE](https://github.com/stevelacey/proton-vpn-cli-macos/blob/main/LICENSE) and the
[contribution policy](https://github.com/stevelacey/proton-vpn-cli-macos/blob/main/CONTRIBUTING.md).
