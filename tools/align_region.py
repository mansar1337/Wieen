#!/usr/bin/env python3
"""Align the reference Luau API against a region of the client image.

The client is built with different compiler flags than our reference build,
so the function sizes differ - but the functions keep their order, so a
Needleman-Wunsch alignment over the sizes still lines them up.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"
LUAU = REPO / "work/luau-src/build-rel/x"

OBJECTS = {
    "lapi.cpp.o": ["_Z9lua_pcallP9lua_Stateiii", "_Z12lua_getfieldP9lua_StateiPKc",
                   "_Z10lua_gettopP9lua_State", "_Z10lua_settopP9lua_Statei",
                   "_Z13lua_tolstringP9lua_StateiPm", "_Z8lua_typeP9lua_Statei"],
    "lvmload.cpp.o": ["_Z9luau_loadP9lua_StatePKcS2_mi"],
    "lcode.cpp.o": ["_Z12luau_compilePKcmP18lua_CompileOptionsPm"],
    "lvmexecute.cpp.o": ["_ZL12luau_executeILb0EEvP9lua_State"],
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


def align(target, ref):
    n, m = len(ref), len(target)
    if n == 0 or m == 0:
        return []

    def close(a: int, b: int) -> float:
        if a == b:
            return 1.0
        mx = max(a, b)
        return max(0.0, 1.0 - abs(a - b) / mx) if mx else 1.0

    gap = -1.2
    dp = [[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        dp[i][0] = dp[i - 1][0] + gap
    for j in range(1, m + 1):
        dp[0][j] = dp[0][j - 1] + gap
    for i in range(1, n + 1):
        ri = ref[i - 1][1]
        row = dp[i]
        prev = dp[i - 1]
        for j in range(1, m + 1):
            sim = 2.0 * close(ri, target[j - 1][1]) - 0.8
            best = prev[j - 1] + sim
            if prev[j] + gap > best:
                best = prev[j] + gap
            if row[j - 1] + gap > best:
                best = row[j - 1] + gap
            row[j] = best

    i, j = n, m
    pairs = []
    while i > 0 and j > 0:
        ri = ref[i - 1][1]
        sim = 2.0 * close(ri, target[j - 1][1]) - 0.8
        if abs(dp[i][j] - (dp[i - 1][j - 1] + sim)) < 1e-9:
            pairs.append((ref[i - 1][2], target[j - 1][0], target[j - 1][1], ri))
            i, j = i - 1, j - 1
        elif dp[i][j] == dp[i - 1][j] + gap:
            i -= 1
        else:
            j -= 1
    pairs.reverse()
    return pairs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lo", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--hi", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--obj", default="lapi.cpp.o")
    args = ap.parse_args()

    target = client_functions(SO)
    region = [(a, s) for a, s in target if args.lo <= a < args.hi]
    print(f"region {args.lo:#x}..{args.hi:#x}: {len(region)} functions")

    ref = reference_functions(LUAU / args.obj)
    pairs = align(region, ref)
    print(f"aligned {len(pairs)} of {len(ref)} reference functions")
    wanted = set(OBJECTS[args.obj])
    for name, off, csize, rsize in pairs:
        mark = "  <<<" if name in wanted else ""
        print(f"   {name:55} ref={rsize:6}  client={off:#x} size={csize}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
