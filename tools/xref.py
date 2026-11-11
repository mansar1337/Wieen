#!/usr/bin/env python3
"""wieen: ELF string-xref finder.

Locates a string in an ELF file, maps its file offset to a virtual address,
then scans executable segments for RIP-relative references to it.

Usage:
    xref.py <elf> <string> [--all]
    xref.py <elf> --strings          # list strings in .rodata with addresses
"""
import re
import struct
import sys


def load_segments(path):
    """Return [(vaddr, filesz, memsz, offset, flags)] for PT_LOAD segments."""
    data = open(path, "rb").read()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        if p_type != 1:  # PT_LOAD
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 0x08)
        p_filesz, p_memsz = struct.unpack_from("<QQ", data, off + 0x20)
        segs.append((p_vaddr, p_filesz, p_memsz, p_offset, p_flags))
    return data, segs


def off_to_vaddr(segs, off):
    for vaddr, filesz, memsz, poff, flags in segs:
        if poff <= off < poff + filesz:
            return vaddr + (off - poff)
    return None


def vaddr_to_off(segs, vaddr):
    for sv, filesz, memsz, poff, flags in segs:
        if sv <= vaddr < sv + filesz:
            return poff + (vaddr - sv)
    return None


# lea/mov reg,[rip+disp32] : 48/4c 8d /8b, mod=00 r/m=101
REX = {0x48, 0x4C}
def scan_xrefs(data, segs, target_vaddr):
    hits = []
    for vaddr, filesz, memsz, poff, flags in segs:
        if not (flags & 1):  # PF_X
            continue
        seg = data[poff:poff + filesz]
        n = len(seg)
        i = 0
        while i < n - 7:
            b0, b1, b2 = seg[i], seg[i + 1], seg[i + 2]
            if b0 in REX and b1 in (0x8D, 0x8B) and (b2 & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", seg, i + 3)[0]
                insn_len = 7
                tgt = vaddr + i + insn_len + disp
                if tgt == target_vaddr:
                    hits.append(vaddr + i)
                i += insn_len
                continue
            i += 1
    return hits


def iter_strings(data, segs, minlen=5):
    for vaddr, filesz, memsz, poff, flags in segs:
        if flags & 1:
            continue  # skip exec
        seg = data[poff:poff + filesz]
        cur, start = [], poff
        for off, b in enumerate(seg):
            if 32 <= b < 127:
                if not cur:
                    start = poff + off
                cur.append(chr(b))
            else:
                if len(cur) >= minlen:
                    yield off_to_vaddr(segs, start), "".join(cur)
                cur = []
        if len(cur) >= minlen:
            yield off_to_vaddr(segs, start), "".join(cur)


def main():
    path = sys.argv[1]
    data, segs = load_segments(path)
    if len(sys.argv) > 2 and sys.argv[2] == "--strings":
        pat = sys.argv[3] if len(sys.argv) > 3 else None
        for va, s in iter_strings(data, segs):
            if pat is None or re.search(pat, s):
                print(f"0x{va:x}\t{s}")
        return

    needle = sys.argv[2].encode()
    idx = data.find(needle)
    if idx < 0:
        print(f"string not found: {needle!r}", file=sys.stderr)
        sys.exit(1)
    va = off_to_vaddr(segs, idx)
    print(f"# {needle!r} at file_off=0x{idx:x} vaddr=0x{va:x}")
    hits = scan_xrefs(data, segs, va)
    if not hits:
        print("# no rip-relative xrefs found")
    for h in hits:
        ctx = data[vaddr_to_off(segs, h):vaddr_to_off(segs, h) + 24]
        print(f"xref 0x{h:x}   bytes={ctx.hex(' ')}")


if __name__ == "__main__":
    main()
