#!/usr/bin/env python3
"""Inspect the candidate Luau copies in the client image.

Prints the client bytes of every entry point of every candidate, so the
real copy can be told apart from the alignment's false positives.
"""
from __future__ import annotations

import pathlib
import re
import struct
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"
HDR = REPO / "src/agent/luau_symbols.h"

NAMES = ["compile", "getfield", "gettop", "interpreter", "load",
         "pcall", "settop", "tolstring", "type"]


def segments(data: bytes):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, off + 8)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz, p_flags))
    return segs


def main() -> int:
    data = SO.read_bytes()
    segs = segments(data)

    def v2f(v):
        for va, po, fs, fl in segs:
            if va <= v < va + fs:
                return po + (v - va)
        return None

    text = HDR.read_text()
    copies = re.findall(r"static const struct wieen_luau_copy LUA_COPY_(\d+) = \{(.*?)\};",
                         text, re.S)
    which = sys.argv[1:] if len(sys.argv) > 1 else None
    for idx, body in copies:
        if which and idx not in which:
            continue
        vals = [int(v, 16) for v in re.findall(r"0x([0-9A-F]+)UL", body)]
        d = dict(zip(NAMES, vals))
        print(f"--- copy {idx} ---")
        for k in NAMES:
            f = v2f(d[k])
            hexs = data[f:f + 24].hex(" ") if f is not None else "??"
            print(f"  {k:12} {d[k]:#010x}  {hexs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
