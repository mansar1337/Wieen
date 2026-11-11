#!/usr/bin/env python3
"""Map the reference Luau API onto the client, anchored and banded.

We know exactly where two of the reference's functions ended up in the
client (they mention strings that only the VM uses), so the mapping is
anchored.  From there we align outwards over a band of client functions:
the client may have extra functions in between - other objects of the same
library - so skipping a client function is cheap, while skipping a
reference function is not.
"""
from __future__ import annotations

import argparse
import bisect
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"
LUAU = REPO / "work/luau-src/build-rel/x"

WANTED = {
    "lapi.cpp.o": {
        "_Z9lua_pcallP9lua_Stateiii": "LUA_PCALL",
        "_Z12lua_getfieldP9lua_StateiPKc": "LUA_GETFIELD",
        "_Z10lua_gettopP9lua_State": "LUA_GETTOP",
        "_Z10lua_settopP9lua_Statei": "LUA_SETTOP",
        "_Z13lua_tolstringP9lua_StateiPm": "LUA_TOLSTRING",
        "_Z8lua_typeP9lua_Statei": "LUA_TYPE",
        "_Z8lua_callP9lua_Stateii": "LUA_CALL",
        "_Z13lua_newthreadP9lua_State": "LUA_NEWTHREAD",
    },
    "lvmload.cpp.o": {
        "_Z9luau_loadP9lua_StatePKcS2_mi": "LUA_LOAD",
    },
    "lcode.cpp.o": {
        "_Z12luau_compilePKcmP18lua_CompileOptionsPm": "LUA_COMPILE",
    },
    "lstate.cpp.o": {
        "_Z14lua_newstatePFvPvmmS0_": "LUA_NEWSTATE",
        "_Z9lua_closeP9lua_State": "LUA_CLOSE",
    },
}


def client_functions(so: Path):
    out = subprocess.run(["readelf", "--debug-dump=frames", str(so)],
                         capture_output=True, text=True).stdout
    funcs = []
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        funcs.append((lo, hi - lo))
    funcs.sort()
    return funcs


def reference_functions(obj: Path):
    out = subprocess.run(["nm", "-S", "--defined-only", str(obj)],
                         capture_output=True, text=True).stdout
    funcs = []
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4 and p[2] in "tT":
            funcs.append((int(p[0], 16), int(p[1], 16), p[3]))
    funcs.sort()
    return funcs


def similarity(a: int, b: int) -> float:
    """How similar two function sizes are; 1.0 means identical."""
    if a == b:
        return 1.0
    slack = 0.15 * b + 8
    return max(0.0, 1.0 - abs(a - b) / slack)


def align(ref_sizes, tgt, gap_c=-0.3, gap_r=-3.0):
    """Align a list of reference sizes onto a list of client functions."""
    n, m = len(ref_sizes), len(tgt)
    if n == 0 or m == 0:
        return []
    dp = [[0.0] * (m + 1) for _ in range(n + 1)]
    bt = bytearray((n + 1) * (m + 1))
    for i in range(1, n + 1):
        dp[i][0] = dp[i - 1][0] + gap_r
        bt[i * (m + 1)] = 1
    for j in range(1, m + 1):
        dp[0][j] = dp[0][j - 1] + gap_c
        bt[j] = 2
    for i in range(1, n + 1):
        ri = ref_sizes[i - 1]
        row = dp[i]
        prev = dp[i - 1]
        base = i * (m + 1)
        for j in range(1, m + 1):
            sim = 2.0 * similarity(ri, tgt[j - 1][1]) - 0.8
            best = prev[j - 1] + sim
            how = 0
            v = row[j - 1] + gap_c
            if v > best:
                best = v
                how = 2
            v = prev[j] + gap_r
            if v > best:
                best = v
                how = 1
            row[j] = best
            bt[base + j] = how
    i, j = n, m
    pairs = []
    while i > 0 and j > 0:
        h = bt[i * (m + 1) + j]
        if h == 0:
            pairs.append((i - 1, j - 1))
            i -= 1
            j -= 1
        elif h == 1:
            i -= 1
        else:
            j -= 1
    pairs.reverse()
    return pairs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--obj", default="lapi.cpp.o")
    ap.add_argument("--anchor", action="append", default=[])
    ap.add_argument("--band", type=int, default=20000)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    cf = client_functions(SO)
    cstarts = [f[0] for f in cf]
    rf = reference_functions(LUAU / args.obj)
    rindex = {name: i for i, (_, _, name) in enumerate(rf)}

    anchors = []
    for a in args.anchor:
        sym, addr = a.rsplit(":", 1)
        ri = rindex[sym]
        ci = bisect.bisect_left(cstarts, int(addr, 0))
        anchors.append((ri, ci))
        print(f"anchor {sym}: ref[{ri}] size {rf[ri][1]}  "
              f"client[{ci}] {cf[ci][0]:#x} size {cf[ci][1]}")

    result = {}
    for ri, ci in anchors:
        result[ri] = ci

    for ri, ci in anchors:
        # backwards
        lo = max(0, ci - args.band)
        seg_tgt = cf[lo:ci]
        seg_ref = [rf[i][1] for i in range(0, ri)]
        for r2, c2 in align(seg_ref, seg_tgt):
            result[r2] = lo + c2
        # forwards
        hi = min(len(cf), ci + 1 + args.band)
        seg_tgt = cf[ci + 1:hi]
        seg_ref = [rf[i][1] for i in range(ri + 1, len(rf))]
        for r2, c2 in align(seg_ref, seg_tgt):
            result[r2] = ci + 1 + c2

    wanted = WANTED.get(args.obj, {})
    for i in sorted(result):
        name = rf[i][2]
        j = result[i]
        mark = f"   <<< {wanted[name]}" if name in wanted else ""
        ratio = cf[j][1] / rf[i][1] if rf[i][1] else 0
        print(f"  {i:3} {name:55} ref={rf[i][1]:5} -> client {cf[j][0]:#x} "
              f"size={cf[j][1]:5} r={ratio:.2f}{mark}")

    if args.out and wanted:
        lines = []
        for i in sorted(result):
            name = rf[i][2]
            if name in wanted:
                lines.append(f"#define {wanted[name]} 0x{cf[result[i]][0]:X}UL")
        args.out.write_text("\n".join(lines) + "\n")
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
