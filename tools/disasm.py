#!/usr/bin/env python3
"""Disassemble a function of the client image (or of the reference build).

Usage:
    disasm.py <file> <offset> [length]
    disasm.py --ref lua_pcall
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


def disasm(blob: bytes, base: int = 0) -> str:
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
            addr = int(m.group(1), 16) + base
            text = m.group(3).split("#")[0].strip()
            lines.append(f"{addr:08x}: {text}")
    return "\n".join(lines)


def main() -> int:
    if sys.argv[1] == "--ref":
        sym = sys.argv[2]
        out = subprocess.run(["nm", "-S", "--defined-only", str(REPO / "work/luau-src/build-rel/x/lapi.cpp.o")],
                             capture_output=True, text=True).stdout
        addr = size = None
        for line in out.splitlines():
            p = line.split()
            if len(p) == 4 and p[3] == sym:
                addr, size = int(p[0], 16), int(p[1], 16)
        if addr is None:
            print("symbol not found")
            return 1
        blob = (REPO / "work/luau-src/build-rel/x/lapi.cpp.o").read_bytes()
        print(disasm(blob[addr:addr + size]))
        return 0

    path = pathlib.Path(sys.argv[1])
    off = int(sys.argv[2], 0)
    length = int(sys.argv[3], 0) if len(sys.argv) > 3 else 256
    data = path.read_bytes()
    if path == SO:
        segs = segments(data)
        f = None
        for va, po, fs in segs:
            if va <= off < va + fs:
                f = po + (off - va)
        if f is None:
            print("offset not in a loaded segment")
            return 1
        blob = data[f:f + length]
    else:
        blob = data[off:off + length]
    print(disasm(blob, off))
    return 0


if __name__ == "__main__":
    sys.exit(main())
