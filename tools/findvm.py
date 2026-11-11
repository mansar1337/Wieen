#!/usr/bin/env python3
"""Find Luau's interpreter inside a running client.

Luau's VM keeps kDispatchTable: 256 entries, one per opcode, each holding
the absolute address of a label inside the interpreter.  In a running
process the table is resolved by the loader, so it is visible in memory
even though the file only holds relocations.

Given the table we can recover the interpreter: the labels live inside one
function, whose entry point sits just before the lowest label.

Usage:
    findvm.py <pid> [--image <base>] [--verbose]
"""
from __future__ import annotations

import re
import struct
import sys

ENTRIES = 256


def maps(pid: int) -> list[tuple[int, int, str, str]]:
    out = []
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        out.append((lo, hi, parts[1], parts[5].strip() if len(parts) > 5 else ""))
    return out


def find_image(pid: int) -> tuple[int, int]:
    """The client image: the big anonymous/memfd executable mapping."""
    best = None
    for lo, hi, perm, path in maps(pid):
        if "x" not in perm:
            continue
        size = hi - lo
        if size < 0x4000000:
            continue
        if best is None or size > best[2]:
            best = (lo, hi, size, path)
    if not best:
        raise RuntimeError("client image not found")
    return best[0], best[1]


def scan_dispatch(pid: int, code_lo: int, code_hi: int) -> list[tuple[int, int]]:
    """Return [(table_addr, min_label)] for every dispatch table found."""
    hits = []
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for lo, hi, perm, path in maps(pid):
            if "r" not in perm or (lo >= code_lo and hi <= code_hi):
                continue
            size = hi - lo
            if size > 64 << 20 or size < ENTRIES * 8:
                continue
            mem.seek(lo)
            data = mem.read(size)
            for i in range(0, len(data) - ENTRIES * 8, 8):
                vals = struct.unpack_from(f"<{ENTRIES}Q", data, i)
                if not all(code_lo <= v < code_hi for v in vals):
                    continue
                if max(vals) - min(vals) > 0x40000:
                    continue
                if len(set(vals)) < 32:
                    continue
                hits.append((lo + i, min(vals), max(vals)))
    return hits


def function_entry(pid: int, label: int, code_lo: int) -> int:
    """Walk back from a label to the prologue of the function that holds it."""
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        window = 0x4000
        start = max(code_lo, label - window)
        mem.seek(start)
        data = mem.read(label - start)
    best = None
    for i in range(len(data) - 4):
        if data[i:i + 4] == b"\x55\x48\x89\xe5":  # push rbp; mov rbp,rsp
            best = start + i
    if best is None:
        raise RuntimeError("no prologue found before the dispatch labels")
    return best


def main() -> int:
    pid = int(sys.argv[1])
    verbose = "--verbose" in sys.argv
    code_lo, code_hi = find_image(pid)
    print(f"image 0x{code_lo:x}..0x{code_hi:x}")
    hits = scan_dispatch(pid, code_lo, code_hi)
    if not hits:
        print("no dispatch table found")
        return 1
    for addr, lo_label, hi_label in hits:
        entry = function_entry(pid, lo_label, code_lo)
        print(f"dispatch table @ 0x{addr:x}: labels 0x{lo_label:x}..0x{hi_label:x} "
              f"-> interpreter entry 0x{entry:x}")
        if verbose:
            with open(f"/proc/{pid}/mem", "rb", 0) as mem:
                mem.seek(entry)
                print("  prologue:", mem.read(24).hex(" "))
    return 0


if __name__ == "__main__":
    sys.exit(main())
