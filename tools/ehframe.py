#!/usr/bin/env python3
"""wieen: extract function ranges from .eh_frame FDEs.

The stripped client keeps its unwind tables, and every FDE records the exact
pc range of one function. That gives us a precise function inventory to align
against the reference Luau build.

Usage:
    ehframe.py <elf> [--out list.txt] [--lo 0x..] [--hi 0x..]
"""
import re
import subprocess
import sys


def main():
    elf = sys.argv[1]
    lo, hi = 0, 1 << 64
    if "--lo" in sys.argv:
        lo = int(sys.argv[sys.argv.index("--lo") + 1], 0)
    if "--hi" in sys.argv:
        hi = int(sys.argv[sys.argv.index("--hi") + 1], 0)

    out = subprocess.run(["readelf", "--debug-dump=frames", elf],
                         capture_output=True, text=True).stdout
    rows = []
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        s, e = int(m.group(1), 16), int(m.group(2), 16)
        if s < lo or s > hi:
            continue
        rows.append((s, e - s))
    rows.sort()
    text = "\n".join(f"0x{s:x} {sz}" for s, sz in rows)
    if "--out" in sys.argv:
        open(sys.argv[sys.argv.index("--out") + 1], "w").write(text + "\n")
        print(f"{len(rows)} functions -> {sys.argv[sys.argv.index('--out') + 1]}")
    else:
        print(text)


if __name__ == "__main__":
    main()
