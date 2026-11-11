#!/usr/bin/env python3
"""wieen: locate Luau's opcode dispatch table through .rela.dyn relocations.

kDispatchTable holds 256 code-label addresses; in a shared object the table
lives in .data.rel.ro and every slot is an R_X86_64_RELATIVE relocation whose
addend points at the interpreter. Consecutive slots therefore show up as a
run of relocations with stride 8 all targeting one function.

Usage:
    reldisp.py <elf> <client_funcs.txt>
"""
import struct
import sys
from collections import defaultdict


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
    elf, funcs_file = sys.argv[1], sys.argv[2]
    data, segs = load_segments(elf)

    # section headers -> find .rela.dyn
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sh = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack_from("<IIQQQQ", data, off)
        sh.append((name, typ, flags, addr, offset, size))
    strtab_off = sh[e_shstrndx][4]
    rel = None
    for name, typ, flags, addr, offset, size in sh:
        n = data[strtab_off + name:data.index(b"\0", strtab_off + name)].decode()
        if n in (".rela.dyn", ".rela.plt"):
            rel = (addr, offset, size)
            break
    if not rel:
        print("no .rela.dyn")
        return
    r_addr, r_off, r_size = rel
    print(f".rela.dyn at vaddr 0x{r_addr:x} size {r_size}")

    # index relocations by target function
    funcs = []
    for line in open(funcs_file):
        a, s = line.split()
        funcs.append((int(a, 16), int(s)))
    funcs.sort()

    def owner(addr):
        lo, hi = 0, len(funcs) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            fs, fl = funcs[mid]
            if addr < fs:
                hi = mid - 1
            elif addr >= fs + fl:
                lo = mid + 1
            else:
                return fs
        return None

    slots = defaultdict(list)
    n = r_size // 24
    for i in range(n):
        off = r_off + i * 24
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
        rtype = r_info & 0xFFFFFFFF
        if rtype != 8:  # R_X86_64_RELATIVE
            continue
        fn = owner(r_addend)
        if fn is not None:
            slots[fn].append((r_addr + r_offset, r_addend))

    for fn, lst in slots.items():
        if len(lst) < 100:
            continue
        lst.sort()
        offs = [o for o, _ in lst]
        stride = offs[1] - offs[0] if len(offs) > 1 else 0
        run = 1
        best = 1
        for i in range(1, len(offs)):
            if offs[i] - offs[i - 1] == stride:
                run += 1
                best = max(best, run)
            else:
                run = 1
        print(f"function 0x{fn:x}: {len(lst)} relocations, stride {stride}, longest run {best}, "
              f"table @ 0x{offs[0]:x}")


if __name__ == "__main__":
    main()
