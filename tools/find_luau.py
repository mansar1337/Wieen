#!/usr/bin/env python3
"""Find the copies of the Luau VM inside the Roblox client image.

The client is stripped, so its functions have no names.  But it was built
from the Luau sources, and the client and the reference build agree on the
*size* of the functions they have in common - that is the signal we use.

The matcher works like this:

  * take a run of consecutive reference functions,
  * find every place in the client where that run of sizes appears at
    consecutive addresses,
  * extend the match forward and backward, allowing the linker to have
    split a few functions into a cold section,
  * keep the matches that are long and exact - a false positive cannot
    reproduce a hundred function sizes in a row.

Usage:
    find_luau.py [--out src/agent/luau_symbols.h] [--top 8]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LUAU = REPO / "work/luau-src/build-rel/x"
DEFAULT_APK = (Path.home() / ".var/app/org.vinegarhq.Sober/data/sober/packages/x86_64/"
               "com.roblox.client/split_config.x86_64.apk")

# the Luau entry points we need, and the object file they live in
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

SEED = 6          # consecutive functions that must match exactly
MAX_SKIP = 3      # how many unmatched client functions we may step over
MIN_MATCH = 40    # how many functions a copy must explain


def extract_client(apk: Path, out: Path) -> Path:
    with zipfile.ZipFile(apk) as z:
        name = [n for n in z.namelist() if n.endswith("libroblox.so")][0]
        out.write_bytes(z.read(name))
    return out


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


def extend(target, ref, ri, ti):
    """Extend an anchored match forward and backward."""
    pairs = []

    r, t, skip = ri, ti, 0
    while r < len(ref) and t < len(target):
        if ref[r][1] == target[t][1]:
            pairs.append((r, t))
            r += 1
            t += 1
            skip = 0
        else:
            skip += 1
            if skip > MAX_SKIP:
                break
            t += 1
    forward = len(pairs)

    r, t, skip = ri - 1, ti - 1, 0
    back = []
    while r >= 0 and t >= 0:
        if ref[r][1] == target[t][1]:
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
    return pairs


def match_object(target, ref):
    """All maximal matches of `ref` inside `target`."""
    # index the client by the size of the first function of the seed
    by_size: dict[int, list[int]] = {}
    for i, (_, size) in enumerate(target):
        by_size.setdefault(size, []).append(i)

    best = []
    for rstart in range(0, len(ref) - SEED + 1):
        sizes = [ref[rstart + k][1] for k in range(SEED)]
        for ti in by_size.get(sizes[0], ()):
            if ti + SEED > len(target):
                continue
            if all(target[ti + k][1] == sizes[k] for k in range(SEED)):
                pairs = extend(target, ref, rstart, ti)
                if len(pairs) > len(best):
                    best = pairs
    return best


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", type=Path, default=DEFAULT_APK)
    ap.add_argument("--so", type=Path, default=REPO / "work/libs/libroblox.so")
    ap.add_argument("--out", type=Path, default=REPO / "src/agent/luau_symbols.h")
    ap.add_argument("--top", type=int, default=8)
    args = ap.parse_args()

    if not args.so.exists():
        extract_client(args.apk, args.so)
        print(f"extracted the client from {args.apk}")

    target = client_functions(args.so)
    print(f"client functions: {len(target)}")

    refs = {}
    for obj in {v[0] for v in WANTED.values()}:
        path = LUAU / obj
        if not path.exists():
            print(f"missing {path}")
            return 1
        refs[obj] = reference_functions(path)
        print(f"  {obj}: {len(refs[obj])} functions")

    # match every object we care about and keep the copies that agree
    matches = {}
    for obj in refs:
        pairs = match_object(target, refs[obj])
        print(f"{obj}: best match {len(pairs)} functions")
        matches[obj] = pairs

    # group the matches of the different objects into copies: a copy is a
    # set of functions that sit close to each other in the client
    anchors = []
    for obj, pairs in matches.items():
        for ri, ti in pairs:
            anchors.append((target[ti][0], obj, ri, ti))
    anchors.sort()

    copies = []
    used = set()
    for addr, obj, ri, ti in anchors:
        if ti in used:
            continue
        used.add(ti)
        copy = {}
        for other_obj, other_pairs in matches.items():
            for ri2, ti2 in other_pairs:
                if abs(target[ti2][0] - addr) < 0x400000:
                    copy.setdefault(other_obj, (ri2, ti2))
        entries = {}
        for key, (objname, sym) in WANTED.items():
            got = copy.get(objname)
            if not got:
                continue
            ri2, ti2 = got
            if refs[objname][ri2][2] == sym:
                entries[key] = target[ti2][0]
        if len(entries) >= 4:
            copies.append((addr, entries))

    copies.sort()
    print(f"copies found: {len(copies)}")
    for addr, entries in copies[:20]:
        print(f"  anchor {addr:#x}  " +
              " ".join(f"{k}={v:#x}" for k, v in sorted(entries.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
