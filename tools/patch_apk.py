#!/usr/bin/env python3
"""Patch the Roblox client inside the Sober APK with the Wieen agent.

Sober's runtime traces the Roblox client and refuses to run code that does
not belong to the client image, so the agent cannot be injected from the
outside.  Instead we put it *into* the client image: the agent's flat blob
goes into the zero filled hole between .rodata and .text, and a couple of
Luau entry points are pointed at it.

    python3 patch_apk.py [--dry-run]

The patched APK replaces the one in Sober's data directory; the original is
kept as a backup.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = Path.home() / ".var/app/org.vinegarhq.Sober/data/sober"
PACKAGES = DATA / "packages/x86_64/com.roblox.client"
SPLIT = PACKAGES / "split_config.x86_64.apk"
BASE = PACKAGES / "base.apk"

# where the agent goes inside the client image
BLOB_OFF = 0xBA211A
HOLE = 0xBAC041

# Luau entry points to detour (offsets inside the client image)
TARGETS = {
    "luau_execute": 0x248FCB6,
    "lua_pcall": 0x246D070,
    "lua_getfield": 0x2404498,
    "lua_gettop": 0x2323926,
}

# the API the agent needs, relative to the image base
API = {
    "lua_compile": 0x25EC5C0,
    "lua_load": 0x23D4B1A,
    "lua_pcall": 0x246D070,
    "lua_getfield": 0x2404498,
    "lua_gettop": 0x2323926,
    "lua_settop": 0x2325A16,
    "lua_tolstring": 0x238896A,
    "lua_type": 0x233DA24,
    "lua_mainthread": 0x2306224,
}

MAILBOX_OFF = 0xC00000
MAILBOX_SIZE = 128 * 1024
TRAMPOLINE_OFF = 0xBF0000


def log(msg: str) -> None:
    print(f"[wieen] {msg}")


def patch_image(so: bytes, blob: bytes, meta: dict) -> bytes:
    """Return the patched client image."""
    sym = meta["symbols"]
    if HOLE not in range(len(so)) or so[HOLE:HOLE + 16] != b"\0" * 16:
        raise RuntimeError("the image does not have the expected hole")
    if len(blob) > 0x20000:
        raise RuntimeError("the agent blob is too large for the hole")

    out = bytearray(so)
    agent = bytearray(blob)

    # the agent needs to know where it lives and what it may call
    # struct wieen_cfg { long blob_off; long mailbox_off; long api[9]; }
    cfg = sym["wieen_cfg"]
    struct.pack_into("<q", agent, cfg + 0, BLOB_OFF)
    struct.pack_into("<q", agent, cfg + 8, MAILBOX_OFF)
    for i, name in enumerate(("lua_compile", "lua_load", "lua_pcall", "lua_getfield",
                               "lua_gettop", "lua_settop", "lua_tolstring", "lua_type",
                               "lua_mainthread")):
        struct.pack_into("<q", agent, cfg + 16 + 8 * i, API[name])

    # one trampoline per detoured function: replay the displaced prologue
    tramp_off = TRAMPOLINE_OFF
    detours = []
    for name, off in TARGETS.items():
        prologue = bytes(so[off:off + 12])
        tramp = bytearray(prologue)
        tramp += b"\x48\xb8" + struct.pack("<Q", off + 12)
        tramp += b"\xff\xe0"
        out[tramp_off:tramp_off + len(tramp)] = tramp
        struct.pack_into("<Q", agent, sym["wieen_original_fn"], tramp_off)
        hook = BLOB_OFF + sym["wieen_hook_stub"]
        detours.append((off, b"\x48\xb8" + struct.pack("<Q", hook) + b"\xff\xe0"))
        tramp_off += len(tramp)

    out[BLOB_OFF:BLOB_OFF + len(agent)] = agent
    for off, detour in detours:
        out[off:off + len(detour)] = detour
    return bytes(out)


def patch(dry_run: bool = False) -> int:
    so_path = REPO / "work/libs/libroblox.so"
    blob_path = REPO / "build/wieen_agent.bin"
    meta_path = REPO / "build/wieen_agent.bin.json"
    for p in (so_path, blob_path, meta_path):
        if not p.exists():
            log(f"missing {p}")
            return 1

    so = so_path.read_bytes()
    blob = blob_path.read_bytes()
    meta = json.loads(meta_path.read_text())

    patched = patch_image(so, blob, meta)
    work = REPO / "work/patched"
    work.mkdir(parents=True, exist_ok=True)
    (work / "libroblox.so").write_bytes(patched)
    log(f"patched image written to {work/'libroblox.so'} ({len(patched)} bytes)")

    if dry_run:
        return 0

    if not SPLIT.exists():
        log(f"{SPLIT} not found")
        return 1
    backup = SPLIT.with_suffix(".apk.orig")
    if not backup.exists():
        shutil.copy2(SPLIT, backup)
        log(f"backup: {backup}")
    else:
        # always patch the pristine original, not a previous patch
        shutil.copy2(backup, SPLIT)

    # rewrite the split APK with the patched client
    tmp = SPLIT.with_suffix(".apk.new")
    with zipfile.ZipFile(SPLIT) as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "lib/x86_64/libroblox.so":
                data = patched
                log(f"replacing {item.filename} ({len(data)} bytes)")
            dst.writestr(item, data)
    os.replace(tmp, SPLIT)
    log(f"patched APK installed: {SPLIT}")
    log("start Sober with:  wieen launch")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    return patch(args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
