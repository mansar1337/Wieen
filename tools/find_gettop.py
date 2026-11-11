#!/usr/bin/env python3
"""Search the client image for the byte pattern of Luau's lua_gettop.

lua_gettop is a tiny leaf function: it returns the number of stack slots in
use, so its machine code is nearly unique in the whole image.  Finding it
gives us an anchor for the real copy of the VM - and, from its position in
the object file, the offsets of its neighbours.
"""
from __future__ import annotations

import pathlib
import re
import struct
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"

PATTERNS = {
    "mov rax,[rdi+8]; sub rax,[rdi+0x10]": bytes.fromhex("488b4708482b4710"),
    "shr rax,4; ret": bytes.fromhex("48c1e804c3"),
    "mov rax,[rdi+8]": bytes.fromhex("488b4708"),
}


def segments(data: bytes):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from("<QQQQQ", data, off + 8)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz))
    return segs


def main() -> int:
    data = SO.read_bytes()
    segs = segments(data)

    def f2v(f):
        for va, po, fs in segs:
            if po <= f < po + fs:
                return va + (f - po)
        return None

    for name, pat in PATTERNS.items():
        hits = [m.start() for m in re.finditer(re.escape(pat), data)]
        print(f"{name}: {len(hits)} hits")
        for f in hits[:20]:
            v = f2v(f)
            print(f"   file {f:#x} vaddr {v:#x}  ctx {data[max(0,f-12):f+24].hex(' ')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
