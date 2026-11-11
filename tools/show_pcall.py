#!/usr/bin/env python3
"""Show the head of the candidate lua_pcall functions of the client.

Two copies of the VM can only be told apart by what their code does, so
this prints the first instructions of every candidate's pcall.
"""
from __future__ import annotations

import pathlib
import re
import struct
import subprocess
import sys
import tempfile

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
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from("<QQQQQ", data, off + 8)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz))
    return segs


def disasm(blob: bytes, base: int) -> list[str]:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(blob)
        path = tmp.name
    try:
        out = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", path],
            capture_output=True, text=True).stdout
    finally:
        pathlib.Path(path).unlink(missing_ok=True)
    lines = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)", line)
        if m:
            lines.append(f"{int(m.group(1),16)+base:08x}: {m.group(3).split('#')[0].strip()}")
    return lines


def main() -> int:
    data = SO.read_bytes()
    segs = segments(data)

    def v2f(v):
        for va, po, fs in segs:
            if va <= v < va + fs:
                return po + (v - va)
        return None

    out = subprocess.run(["readelf", "--debug-dump=frames", str(SO)],
                         capture_output=True, text=True).stdout
    fdes = {}
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes[int(m.group(1), 16)] = int(m.group(2), 16) - int(m.group(1), 16)

    text = HDR.read_text()
    copies = re.findall(r"static const struct wieen_luau_copy LUA_COPY_(\d+) = \{(.*?)\};",
                        text, re.S)
    wanted = set(sys.argv[1:])
    for idx, body in copies:
        if wanted and idx not in wanted:
            continue
        vals = [int(v, 16) for v in re.findall(r"0x([0-9A-F]+)UL", body)]
        d = dict(zip(NAMES, vals))
        off = d["pcall"]
        f = v2f(off)
        size = fdes.get(off, 0)
        print(f"=== copy {idx}  pcall={off:#x} size={size} ===")
        for line in disasm(data[f:f + min(size, 120)], off)[:26]:
            print("   " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
