#!/usr/bin/env python3
"""wieen: find Luau's interpreter via its opcode dispatch table.

Luau's VM keeps kDispatchTable: 256 code-label addresses, one per opcode.
In the client it is a table of pointers into a single function, so we look for
256 consecutive words that all land inside one .eh_frame function range.

Usage:
    interp.py <elf> <client_funcs.txt> [--table]
"""
import struct
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
        segs.append((p_vaddr, p_filesz, p_offset, p_flags))
    return data, segs


def main():
    elf, funcs_file = sys.argv[1], sys.argv[2]
    funcs = []
    for line in open(funcs_file):
        a, s = line.split()
        funcs.append((int(a, 16), int(s)))
    funcs.sort()

    data, segs = load_segments(elf)
    for v, f, o, fl in segs:
        if fl & 1:
            continue
        blob = data[o:o + f]
        for i in range(0, len(blob) - 8 * 256, 8):
            vals = struct.unpack_from("<256Q", blob, i)
            if len(set(vals)) < 200:
                continue
            # every entry must live inside one and the same function
            for fs, flen in funcs:
                if fs <= vals[0] < fs + flen and all(fs <= x < fs + flen for x in vals):
                    print(f"dispatch table @ 0x{v + i:x} -> function 0x{fs:x} (size {flen})")
                    if "--table" in sys.argv:
                        for k, x in enumerate(vals):
                            print(f"   [{k:3d}] 0x{x:x}")
                    break


if __name__ == "__main__":
    main()
