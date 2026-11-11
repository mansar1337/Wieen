#!/usr/bin/env python3
"""Build the call graph of the client image.

The client is stripped and built with a compiler we do not have, so the
functions cannot be matched by size.  What we can do is follow the calls:
a function that is called from the outside of the VM with four arguments -
a state pointer and three integers - is lua_pcall.

Usage:
    callgraph.py --calls 0x320da04          # who calls this function?
    callgraph.py --from 0x31f0000 --to 0x3220000   # calls inside a range
"""
from __future__ import annotations

import argparse
import bisect
import pathlib
import re
import struct
import subprocess
import sys

import numpy as np

REPO = pathlib.Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"


def load(path: pathlib.Path):
    data = path.read_bytes()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from("<QQQQQ", data, off + 8)
        segs.append((p_vaddr, p_offset, p_filesz, p_flags))
    return data, segs


def call_sites(data, segs):
    """All direct call instructions: (site, target)."""
    sites = []
    for va, po, fs, fl in segs:
        if not (fl & 1):
            continue
        seg = data[po:po + fs]
        arr = np.frombuffer(seg, dtype=np.uint8)
        idx = np.nonzero((arr == 0xE8) | (arr == 0xE9))[0]
        if len(idx) == 0:
            continue
        idx = idx[idx < len(arr) - 4]
        raw = arr[idx[:, None] + np.arange(1, 5)]
        disp = raw.copy().view(np.int32).reshape(-1)
        target = va + idx.astype(np.int64) + 5 + disp.astype(np.int64)
        for i, t in zip(idx, target):
            sites.append((va + int(i), int(t)))
    return sites


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=lambda s: int(s, 0),
                    help="list the callers of this address")
    ap.add_argument("--from", dest="lo", type=lambda s: int(s, 0))
    ap.add_argument("--to", dest="hi", type=lambda s: int(s, 0))
    ap.add_argument("--outside", type=lambda s: int(s, 0),
                    help="only callers outside this range")
    args = ap.parse_args()

    data, segs = load(SO)
    out = subprocess.run(["readelf", "--debug-dump=frames", str(SO)],
                         capture_output=True, text=True).stdout
    fdes = []
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        fdes.append((lo, hi - lo))
    fdes.sort()
    starts = [f[0] for f in fdes]

    def owner(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return None
        a, s = fdes[i]
        if addr < a + s:
            return (a, s)
        return None

    sites = call_sites(data, segs)
    print(f"{len(sites)} call sites")

    if args.calls is not None:
        callers = [(s, t) for s, t in sites if t == args.calls]
        print(f"callers of {args.calls:#x}: {len(callers)}")
        for s, t in callers:
            o = owner(s)
            print(f"   {s:#x} in {o[0]:#x} (size {o[1]})" if o else f"   {s:#x}")

    if args.lo is not None:
        sel = [(s, t) for s, t in sites
               if args.lo <= t < args.hi and (args.outside is None or
                                             not (args.outside <= s < args.hi))]
        print(f"calls into [{args.lo:#x},{args.hi:#x}): {len(sel)}")
        seen = {}
        for s, t in sel:
            seen.setdefault(t, []).append(s)
        for t in sorted(seen, key=lambda a: -len(seen[a]))[:40]:
            o = owner(t)
            print(f"   target {t:#x} size {o[1] if o else '?':>6} "
                  f"called {len(seen[t])}x  e.g. {seen[t][0]:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
