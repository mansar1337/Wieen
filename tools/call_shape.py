#!/usr/bin/env python3
"""Compare the call structure of the candidate lua_pcall functions.

lua_pcall is a small function with a very characteristic shape: it builds a
CallS on the stack and calls the VM's protected-call helper, then adjusts
the results.  A function that has the same call structure is very likely to
be the real lua_pcall, even though the client was built from a slightly
different Luau revision.
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
LUAU_OBJ = REPO / "work/luau-src/build-rel/x/lapi.cpp.o"

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


def disasm_lines(blob: bytes):
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
            lines.append((int(m.group(1), 16), m.group(3).split("#")[0].strip()))
    return lines


def calls_of(lines):
    out = []
    for addr, text in lines:
        if text.startswith("call"):
            out.append((addr, text))
    return out


def ref_pcall():
    nm = subprocess.run(["nm", "-S", "--defined-only", str(LUAU_OBJ)],
                        capture_output=True, text=True).stdout
    addr = size = None
    for line in nm.splitlines():
        p = line.split()
        if len(p) == 4 and p[3] == "_Z9lua_pcallP9lua_Stateiii":
            addr, size = int(p[0], 16), int(p[1], 16)
    blob = LUAU_OBJ.read_bytes()
    return disasm_lines(blob[addr:addr + size])


def main() -> int:
    print("=== reference lua_pcall ===")
    for addr, text in calls_of(ref_pcall()):
        print(f"   +{addr:#06x}  {text}")

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
    for idx, body in copies:
        vals = [int(v, 16) for v in re.findall(r"0x([0-9A-F]+)UL", body)]
        d = dict(zip(NAMES, vals))
        off = d["pcall"]
        f = v2f(off)
        size = fdes.get(off, 0)
        lines = disasm_lines(data[f:f + size])
        cs = calls_of(lines)
        print(f"copy {idx:>3} pcall={off:#x} size={size:4} calls={len(cs):2}  " +
              " ".join(f"{a:#x}" for a, _ in cs[:10]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
