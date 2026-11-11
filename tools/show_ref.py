#!/usr/bin/env python3
"""Print the reference lua_pcall with its relocations, and the client's
candidate functions, so the two can be compared by hand."""
from __future__ import annotations

import pathlib
import re
import struct
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"
OBJ = REPO / "work/luau-src/build-rel/x/lapi.cpp.o"
SYM = "_Z9lua_pcallP9lua_Stateiii"


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


def ref_function():
    nm = subprocess.run(["nm", "-S", "--defined-only", str(OBJ)],
                        capture_output=True, text=True).stdout
    addr = size = None
    for line in nm.splitlines():
        p = line.split()
        if len(p) == 4 and p[3] == SYM:
            addr, size = int(p[0], 16), int(p[1], 16)
    return addr, size


def ref_disasm():
    addr, size = ref_function()
    out = subprocess.run(["objdump", "-dr", "-M", "intel", "--start-address", hex(addr),
                          "--stop-address", hex(addr + size), str(OBJ)],
                         capture_output=True, text=True).stdout
    keep = []
    for line in out.splitlines():
        s = line.strip()
        if not s or s.startswith("/") or s.startswith("work/") or s.startswith("Disassembly"):
            continue
        keep.append(line.rstrip())
    return "\n".join(keep)


def client_disasm(vaddr: int, length: int):
    data = SO.read_bytes()
    segs = segments(data)
    f = None
    for va, po, fs in segs:
        if va <= vaddr < va + fs:
            f = po + (vaddr - va)
    blob = data[f:f + length]
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(blob)
        path = tmp.name
    try:
        out = subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                              "-M", "intel", path], capture_output=True, text=True).stdout
    finally:
        pathlib.Path(path).unlink(missing_ok=True)
    lines = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)", line)
        if m:
            lines.append(f"{int(m.group(1),16)+vaddr:08x}: {m.group(3).split('#')[0].strip()}")
    return "\n".join(lines)


def main() -> int:
    if sys.argv[1] == "ref":
        print(ref_disasm())
        return 0
    vaddr = int(sys.argv[1], 0)
    length = int(sys.argv[2], 0) if len(sys.argv) > 2 else 460
    print(client_disasm(vaddr, length))
    return 0


if __name__ == "__main__":
    sys.exit(main())
