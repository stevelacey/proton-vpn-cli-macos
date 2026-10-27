#!/bin/bash
# The few things Proton VPN CLI for macOS needs root for. `protonvpn setup` installs this root-owned and
# lets its user run it through sudo without a password, so it takes no paths or commands: a tunnel
# config comes in on stdin and is only used if it's a plain WireGuard config, since wg-quick runs
# PreUp/PostUp lines as root.
#
#   helper up           brings the tunnel up with the config on stdin
#   helper down         brings it down
#   helper pf-load      loads the kill switch's pf rules on stdin into its anchor
#   helper pf-flush     removes them
#   helper pf-enable    enables pf, printing the reference token
#   helper pf-release <token>
#   helper dns-reset <network service>
#   helper version
set -euo pipefail

VERSION=1
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
dir=/var/run/proton-vpn
conf=$dir/proton.conf
anchor=com.apple/proton.vpn.killswitch

# Comments, sections and the keys our config uses, with values that can't hold commands.
allowed='^(#.*|\[Interface\]|\[Peer\]|(PrivateKey|Address|DNS|PublicKey|AllowedIPs|Endpoint) = [A-Za-z0-9+/=.:, -]+)$'

case "${1:-}" in
  up)
    config=$(cat)
    while IFS= read -r line; do
      if [[ -n $line && ! $line =~ $allowed ]]; then
        echo "Refusing a config line that isn't plain WireGuard: $line" >&2
        exit 2
      fi
    done <<< "$config"
    mkdir -p "$dir"
    chmod 700 "$dir"
    (umask 077 && printf '%s\n' "$config" > "$conf")
    exec bash wg-quick up "$conf"
    ;;
  down)
    exec bash wg-quick down "$conf"
    ;;
  pf-load)
    exec pfctl -a "$anchor" -f -
    ;;
  pf-flush)
    exec pfctl -a "$anchor" -F all
    ;;
  pf-enable)
    exec pfctl -E
    ;;
  pf-release)
    [[ ${2:-} =~ ^[0-9]+$ ]] || { echo "Not a pf token: ${2:-}" >&2; exit 2; }
    exec pfctl -X "$2"
    ;;
  dns-reset)
    [[ -n ${2:-} ]] || { echo "No network service given" >&2; exit 2; }
    exec networksetup -setdnsservers "$2" Empty
    ;;
  version)
    echo "$VERSION"
    ;;
  *)
    echo "Usage: $0 up|down|pf-load|pf-flush|pf-enable|pf-release <token>|dns-reset <service>|version" >&2
    exit 2
    ;;
esac
