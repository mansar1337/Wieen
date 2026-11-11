#!/usr/bin/env python3
"""Dump the printable-string neighbourhood around an anchor inside an ELF file.

Usage: strpool.py <file> <anchor> [before_bytes] [after_bytes]
"""
import sys

path = sys.argv[1]
anchor = sys.argv[2].encode()
before = int(sys.argv[3]) if len(sys.argv) > 3 else 4096
after = int(sys.argv[4]) if len(sys.argv) > 4 else 8192

data = open(path, "rb").read()
i = data.find(anchor)
if i < 0:
    sys.exit(f"anchor {anchor!r} not found in {path}")
lo, hi = max(0, i - before), min(len(data), i + after)
chunk = data[lo:hi]

out, cur, start = [], [], lo
for off, b in enumerate(chunk):
    if 32 <= b < 127 or b in (9,):
        if not cur:
            start = lo + off
        cur.append(chr(b))
    else:
        if len(cur) >= 3:
            out.append((start, "".join(cur)))
        cur = []
if len(cur) >= 3:
    out.append((start, "".join(cur)))

for off, s in out:
    mark = " <== ANCHOR" if anchor.decode(errors="ignore") in s else ""
    print(f"0x{off:08x}  {s}{mark}")
