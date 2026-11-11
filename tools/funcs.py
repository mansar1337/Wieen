#!/usr/bin/env python3
"""wieen: enumerate function starts inside an ELF address range.

Roblox's client is compiled with clang, which pads between functions with
int3 (0xcc). We use that to recover function boundaries in a stripped binary.

Usage:
    funcs.py <elf> <lo> <hi>
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
        segs.append((p_vaddr, p_filesz, p_offset, p_flags))
    return data, segs


def vaddr_to_off(segs, va):
    for v, fsz, off, fl in segs:
        if v <= va < v + fsz:
            return off + (va - v)
    return None


def main():
    elf = sys.argv[1]
    lo, hi = int(sys.argv[2], 0), int(sys.argv[3], 0)
    data, segs = load_segments(elf)
    # gather bytes of the requested range
    chunks = []
    for v, fsz, off, fl in segs:
        if not (fl & 1):
            continue
        s, e = max(v, lo), min(v + fsz, hi)
        if s >= e:
            continue
        chunks.append((s, data[off + (s - v):off + (e - v)]))
    chunks.sort()
    starts = []
    for base, blob in chunks:
        i = 0
        n = len(blob)
        while i < n:
            # find a run of int3 padding
            if blob[i] == 0xCC:
                j = i
                while j < n and blob[j] == 0xCC:
                    j += 1
                # a function starts after padding if the next byte is not padding/zero
                if j < n and blob[j] != 0x00:
                    starts.append(base + j)
                i = j
            else:
                i += 1
    starts = sorted(set(starts))
    for idx, s in enumerate(starts):
        nxt = starts[idx + 1] if idx + 1 < len(starts) else hi
        print(f"0x{s:x}  size~{nxt - s}")


if __name__ == "__main__":
    main()
