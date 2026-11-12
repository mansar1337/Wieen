#!/bin/bash
# Install the Wieen agent into Sober's client process.
#
# Sober strips LD_PRELOAD from the environment it hands to the client, but
# the flatpak runtime's dynamic linker also reads /etc/ld.so.preload - and
# that file is not under Sober's control.  Writing the agent there makes
# ld.so load it into every process of the runtime, including the Roblox
# client.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# Preserve the invoking user's home when the script is run through sudo.
USER_HOME="${SUDO_HOME:-}"
if [ -z "$USER_HOME" ] && [ -n "${SUDO_USER:-}" ]; then
    USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi
USER_HOME="${USER_HOME:-$HOME}"
DATA="$USER_HOME/.var/app/org.vinegarhq.Sober/data/wieen"
# pick the runtime version Sober actually uses
VER=$(flatpak info org.vinegarhq.Sober 2>/dev/null | sed -n 's/.*Runtime:.*\/\([0-9][0-9]*\)$/\1/p' | tail -1)
RUNTIME=""
for cand in /var/lib/flatpak/runtime/org.gnome.Platform/x86_64/$VER/active; do
    [ -e "$cand" ] || continue
    RUNTIME="$(readlink -f "$cand")/files"
done
[ -n "$RUNTIME" ] || RUNTIME="$(readlink -f /var/lib/flatpak/runtime/org.gnome.Platform/x86_64/51/active)/files"

mkdir -p "$DATA"
cp "$REPO/build/wieen_agent.so" "$DATA/wieen_agent.so"
echo "agent installed: $DATA/wieen_agent.so"

if [ ! -w "$RUNTIME/etc" ]; then
    echo "need root for $RUNTIME/etc" >&2
    exit 1
fi
echo "$DATA/wieen_agent.so" > "$RUNTIME/etc/ld.so.preload"
echo "preload registered: $RUNTIME/etc/ld.so.preload"
echo "start Sober and join a game, then: wieen status"
