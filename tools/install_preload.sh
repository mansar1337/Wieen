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
# pick the runtime Sober actually uses.  Asking flatpak for the runtime of
# the app is locale independent, unlike scraping `flatpak info`.
REF="$(flatpak list --app --columns=application,runtime 2>/dev/null \
       | awk -F'\t' '$1 == "org.vinegarhq.Sober" {print $2; exit}')"
RUNTIME=""
for cand in "/var/lib/flatpak/runtime/$REF/active/files" \
            "$USER_HOME/.local/share/flatpak/runtime/$REF/active/files"; do
    [ -n "$REF" ] || continue
    [ -d "$cand" ] || continue
    RUNTIME="$(readlink -f "$cand")"
done
if [ -z "$RUNTIME" ]; then
    echo "cannot find the flatpak runtime Sober uses (ref '$REF')" >&2
    exit 1
fi

mkdir -p "$DATA"
cp "$REPO/build/wieen_agent.so" "$DATA/wieen_agent.so"
echo "agent installed: $DATA/wieen_agent.so"

if [ ! -w "$RUNTIME/etc" ]; then
    echo "need root for $RUNTIME/etc" >&2
    exit 1
fi
echo "$DATA/wieen_agent.so" > "$RUNTIME/etc/ld.so.preload"
if [ "$(cat "$RUNTIME/etc/ld.so.preload")" != "$DATA/wieen_agent.so" ]; then
    echo "the preload did not take in $RUNTIME/etc/ld.so.preload" >&2
    exit 1
fi
echo "preload registered: $RUNTIME/etc/ld.so.preload"
echo
echo "note: a flatpak runtime update replaces that deploy directory and the"
echo "preload goes with it.  if the agent stops loading after 'flatpak update',"
echo "run 'wieen launch' - it checks and registers the preload again."
echo "start Sober and join a game, then: wieen status"
