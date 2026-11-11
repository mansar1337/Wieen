#!/usr/bin/env python3
"""Accurate call graph of the client image, built with capstone.

Scanning the raw bytes for 0xE8 finds plenty of false positives, because
the byte can be part of another instruction.  Here every function is
disassembled properly, using the function ranges the linker left in
.eh_frame, so the call sites are real.

Usage:
    calls.py --who-calls 0x22e4b72
    calls.py --calls-of 0x22e4648
"""
from __future__ import annotations

import argparse
import bisect
import pathlib
import re
import subprocess
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

REPO = pathlib.Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"


def load(path: pathlib.Path):
    data = path.read_bytes()
    e_phoff = int.from_bytes(data[0x20:0x28], "little")
    e_phentsize = int.from_bytes(data[0x36:0x38], "little")
    e_phnum = int.from_bytes(data[0x38:0x3A], "little")
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = int.from_bytes(data[off:off + 4], "little"), \
            int.from_bytes(data[off + 4:off + 8], "little")
        p_offset = int.from_bytes(data[off + 8:off + 16], "little")
        p_vaddr = int.from_bytes(data[off + 16:off + 24], "little")
        p_filesz = int.from_bytes(data[off + 32:off + 40], "little")
        segs.append((p_vaddr, p_offset, p_filesz, p_flags))
    return data, segs


def fdes(path: pathlib.Path):
    out = subprocess.run(["readelf", "--debug-dump=frames", str(path)],
                         capture_output=True, text=True).stdout
    funcs = []
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        funcs.append((lo, hi - lo))
    funcs.sort()
    return funcs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--who-calls", type=lambda s: int(s, 0), action="append", default=[])
    ap.add_argument("--calls-of", type=lambda s: int(s, 0), action="append", default=[])
    ap.add_argument("--lo", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--hi", type=lambda s: int(s, 0), default=0)
    args = ap.parse_args()

    data, segs = load(SO)
    funcs = fdes(SO)

    def v2f(v):
        for va, po, fs, fl in segs:
            if va <= v < va + fs:
                return po + (v - va)
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    wanted = set(args.who_calls)
    callers = {w: [] for w in wanted}
    calls_of = {}

    lo = args.lo or 0
    hi = args.hi or (1 << 64)

    for addr, size in funcs:
        if not (lo <= addr < hi):
            continue
        f = v2f(addr)
        if f is None:
            continue
        blob = data[f:f + size]
        targets = []
        for ins in md.disasm(blob, addr):
            if ins.mnemonic == "call":
                op = ins.op_str
                if op.startswith("0x"):
                    t = int(op, 16)
                    targets.append((ins.address, t))
                    if t in wanted:
                        callers[t].append((addr, size, ins.address))
        if args.calls_of and addr in args.calls_of:
            calls_of[addr] = targets

    for w in args.who_calls:
        print(f"callers of {w:#x}: {len(callers[w])}")
        for a, s, site in callers[w][:40]:
            print(f"   {site:#x} in {a:#x} (size {s})")
    for a in args.calls_of:
        print(f"calls of {a:#x}:")
        for site, t in calls_of.get(a, []):
            print(f"   {site:#x} -> {t:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
