#!/usr/bin/env python3
"""wieen: locate Luau's interpreter dispatch table inside the client.

Luau's VM uses a 256-entry table of code labels (kDispatchTable) indexed by
opcode. Finding that table pins down the interpreter function exactly.

Usage:
    dispatch.py <elf> [--table]
"""
import re
import struct
import subprocess
import sys


def load_segments(path):
    data = open(path, "rb").read()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        if p_type != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 0x08)
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        segs.append((p_vaddr, p_filesz, p_offset, p_flags, p_type))
    return data, segs


def main():
    elf = sys.argv[1]
    data, segs = load_segments(elf)
    text = [(v, f, o) for v, f, o, fl, t in segs if fl & 1]
    ranges = [(v, v + f) for v, f, _ in text]

    def is_code(x):
        return any(lo <= x < hi for lo, hi in ranges)

    for v, f, o, fl, ptype in segs:
        if fl & 1:
            continue
        blob = data[o:o + f]
        n = len(blob)
        i = 0
        while i + 8 * 256 <= n:
            vals = struct.unpack_from("<256Q", blob, i)
            if all(is_code(x) for x in vals):
                span = max(vals) - min(vals)
                if span < 0x40000:
                    print(f"dispatch table @ vaddr 0x{v + i:x}  span=0x{span:x} "
                          f"first=0x{vals[0]:x} last=0x{vals[-1]:x}")
                    if "--table" in sys.argv:
                        for k, x in enumerate(vals):
                            print(f"   [{k:3d}] 0x{x:x}")
            i += 8


if __name__ == "__main__":
    main()
