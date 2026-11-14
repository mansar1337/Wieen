#!/usr/bin/env python3
"""Disassemble a function of the client image (or of the reference build).

Usage:
    disasm.py <file> <offset> [length]
    disasm.py --ref lua_pcall
"""
from __future__ import annotations

import pathlib
import struct
import subprocess
import sys

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


def elf_file_offset(data: bytes, addr: int) -> int | None:
    """Map a virtual address of a relocatable ELF object to its file offset."""
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_addr = struct.unpack_from("<Q", data, off + 0x10)[0]
        sh_offset = struct.unpack_from("<Q", data, off + 0x18)[0]
        sh_size = struct.unpack_from("<Q", data, off + 0x20)[0]
        if sh_addr <= addr < sh_addr + sh_size:
            return sh_offset + (addr - sh_addr)
    return None


def disasm(blob: bytes, base: int = 0) -> str:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        raise SystemExit("python3-capstone is required for correct virtual-address disassembly")
    lines = []
    for insn in Cs(CS_ARCH_X86, CS_MODE_64).disasm(blob, base):
        raw = " ".join(f"{b:02x}" for b in insn.bytes)
        lines.append(f"{insn.address:08x}: {raw:<24} {insn.mnemonic} {insn.op_str}")
    return "\n".join(lines)


def main() -> int:
    if sys.argv[1] == "--ref":
        sym = sys.argv[2]
        out = subprocess.run(["nm", "-S", "--defined-only", str(REPO / "work/luau-src/build-rel/x/lapi.cpp.o")],
                             capture_output=True, text=True).stdout
        addr = size = None
        for line in out.splitlines():
            p = line.split()
            if len(p) == 4 and (p[3] == sym or p[3].startswith(f"_Z{len(sym)}{sym}")):
                addr, size = int(p[0], 16), int(p[1], 16)
        if addr is None:
            print("symbol not found")
            return 1
        obj = REPO / "work/luau-src/build-rel/x/lapi.cpp.o"
        data = obj.read_bytes()
        fileoff = elf_file_offset(data, addr)
        if fileoff is None:
            print("symbol address is not in a section")
            return 1
        print(disasm(data[fileoff:fileoff + size], addr))
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
