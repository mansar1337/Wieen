#!/usr/bin/env python3
"""wieen: fast inverse-xref for direct calls (no objdump needed).

Scans executable segments for E8 rel32 call instructions and reports the
call sites that target a given address.

Usage:
    fastcallers.py <elf> <target> [<target> ...]
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
    elf = sys.argv[1]
    targets = {int(a, 0) for a in sys.argv[2:]}
    data, segs = load_segments(elf)
    for vaddr, filesz, poff, fl in segs:
        if not (fl & 1):
            continue
        blob = data[poff:poff + filesz]
        i = 0
        n = len(blob)
        while True:
            i = blob.find(b"\xe8", i)
            if i < 0 or i + 5 > n:
                break
            disp = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = vaddr + i + 5 + disp
            if tgt in targets:
                print(f"call to 0x{tgt:x} at 0x{vaddr + i:x}")
            i += 1


if __name__ == "__main__":
    main()
