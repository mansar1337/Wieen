#!/usr/bin/env python3
"""Locate the Luau VM inside the client image, without knowing its version.

The client was built from a Luau revision that is not the one we have
locally, so the functions do not have the same size - but they are close,
and they keep their order.  So we look for a long run of client functions
whose sizes match the reference build's functions of lapi.cpp.o, allowing
a few bytes of slack and a few functions of slack for the cold sections
the linker splits off.

The result is a mapping from the reference's function list to the client's
function list, which is what the agent needs.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LUAU = REPO / "work/luau-src/build-rel/x"

WANTED = {
    "LUA_COMPILE": ("lcode.cpp.o", "_Z12luau_compilePKcmP18lua_CompileOptionsPm"),
    "LUA_LOAD": ("lvmload.cpp.o", "_Z9luau_loadP9lua_StatePKcS2_mi"),
    "LUA_PCALL": ("lapi.cpp.o", "_Z9lua_pcallP9lua_Stateiii"),
    "LUA_GETFIELD": ("lapi.cpp.o", "_Z12lua_getfieldP9lua_StateiPKc"),
    "LUA_GETTOP": ("lapi.cpp.o", "_Z10lua_gettopP9lua_State"),
    "LUA_SETTOP": ("lapi.cpp.o", "_Z10lua_settopP9lua_Statei"),
    "LUA_TOLSTRING": ("lapi.cpp.o", "_Z13lua_tolstringP9lua_StateiPm"),
    "LUA_TYPE": ("lapi.cpp.o", "_Z8lua_typeP9lua_Statei"),
    "LUA_INTERPRETER": ("lvmexecute.cpp.o", "_ZL12luau_executeILb0EEvP9lua_State"),
}

SEED = 6
MAX_SKIP = 4
TOL_ABS = 6      # bytes of slack
TOL_REL = 0.10   # and this much of the size


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


def similar(a: int, b: int) -> bool:
    return abs(a - b) <= max(TOL_ABS, int(b * TOL_REL))


def match_run(target, ref):
    """Find the longest fuzzy run of `ref` inside `target`."""
    n = len(target)
    by_size: dict[int, list[int]] = {}
    for i, (_, size) in enumerate(target):
        by_size.setdefault(size, []).append(i)

    seeds = []
    for rstart in range(0, len(ref) - SEED + 1):
        # the client indices whose size may match the k-th reference function
        cand = None
        for k in range(SEED):
            want = ref[rstart + k][1]
            lo = want - max(TOL_ABS, int(want * TOL_REL))
            hi = want + max(TOL_ABS, int(want * TOL_REL))
            here = []
            for size in range(lo, hi + 1):
                here.extend(by_size.get(size, ()))
            if not here:
                cand = []
                break
            cand = set(here) if cand is None else (cand & set(here))
            if not cand:
                break
        for t in sorted(cand or ()):
            if t + SEED <= n and all(similar(target[t + k][1], ref[rstart + k][1])
                                     for k in range(SEED)):
                seeds.append((rstart, t))
    best = []
    for rstart, tstart in seeds:
        pairs = [(rstart + k, tstart + k) for k in range(SEED)]
        # forward
        r, t, skip = rstart + SEED, tstart + SEED, 0
        while r < len(ref) and t < n:
            if similar(target[t][1], ref[r][1]):
                pairs.append((r, t))
                r += 1
                t += 1
                skip = 0
            else:
                skip += 1
                if skip > MAX_SKIP:
                    break
                t += 1
        # backward
        r, t, skip = rstart - 1, tstart - 1, 0
        back = []
        while r >= 0 and t >= 0:
            if similar(target[t][1], ref[r][1]):
                back.append((r, t))
                r -= 1
                t -= 1
                skip = 0
            else:
                skip += 1
                if skip > MAX_SKIP:
                    break
                t -= 1
        pairs = back[::-1] + pairs
        if len(pairs) > len(best):
            best = pairs
    return best


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--so", type=Path, default=REPO / "work/libs/libroblox.so")
    ap.add_argument("--obj", default="lapi.cpp.o")
    ap.add_argument("--min", type=int, default=40)
    args = ap.parse_args()

    target = client_functions(args.so)
    print(f"client functions: {len(target)}")
    ref = reference_functions(LUAU / args.obj)
    print(f"reference {args.obj}: {len(ref)} functions")

    pairs = match_run(target, ref)
    print(f"best run: {len(pairs)} functions")
    if len(pairs) < args.min:
        print("no convincing run")
        return 1
    for ri, ti in pairs[:8]:
        print(f"  ref {ref[ri][2]:60} {ref[ri][1]:6}  ->  client {target[ti][0]:#x} {target[ti][1]}")
    print("  ...")
    for ri, ti in pairs[-8:]:
        print(f"  ref {ref[ri][2]:60} {ref[ri][1]:6}  ->  client {target[ti][0]:#x} {target[ti][1]}")

    mapping = {ref[ri][2]: target[ti][0] for ri, ti in pairs}
    out = REPO / "work" / "lapi_map.json"
    out.write_text(json.dumps(mapping, indent=1))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
