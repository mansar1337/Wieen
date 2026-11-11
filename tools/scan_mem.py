#!/usr/bin/env python3
"""Scan a process' memory for byte patterns, report address + owning mapping."""
import sys, re

pid = int(sys.argv[1])
needles = [s.encode() for s in sys.argv[2:]]

maps = []
with open(f"/proc/{pid}/maps") as f:
    for line in f:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) ([0-9a-f]+) \S+ \S+\s*(.*)", line)
        if m:
            lo, hi = int(m.group(1), 16), int(m.group(2), 16)
            maps.append((lo, hi, m.group(3), m.group(4), m.group(5).strip()))

mem = open(f"/proc/{pid}/mem", "rb", 0)
for lo, hi, perm, off, path in maps:
    if "r" not in perm:
        continue
    size = hi - lo
    if size > 512 * 1024 * 1024:
        continue
    try:
        mem.seek(lo)
        data = mem.read(size)
    except Exception:
        continue
    for n in needles:
        start = 0
        while True:
            i = data.find(n, start)
            if i < 0:
                break
            addr = lo + i
            ctx = data[max(0, i - 48):i + len(n) + 48]
            printable = "".join(chr(c) if 32 <= c < 127 else "." for c in ctx)
            print(f"[{pid}] {n!r:60} @ 0x{addr:x}  map={perm} {path or '[anon]'} (base_off={hex(int(off,16)) if off else '-'})")
            print(f"      ctx: {printable}")
            start = i + 1
