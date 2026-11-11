#!/usr/bin/env python3
"""Score the candidate Luau copies by how well their function sizes match
the reference build.

A real copy of the VM has exactly the same function sizes as the reference
build, because both are compiled from the same sources.  The alignment can
produce false positives, but a false positive has to match the size of a
*big* function to survive.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"
HDR = REPO / "src/agent/luau_symbols.h"
LUAU = REPO / "work/luau-src/build-rel/x"

NAMES = ["compile", "getfield", "gettop", "interpreter", "load",
         "pcall", "settop", "tolstring", "type"]

REF_SYMBOL = {
    "compile": "_Z12luau_compilePKcmP18lua_CompileOptionsPm",
    "getfield": "_Z12lua_getfieldP9lua_StateiPKc",
    "gettop": "_Z10lua_gettopP9lua_State",
    "interpreter": "_ZL12luau_executeILb0EEvP9lua_State",
    "load": "_Z9luau_loadP9lua_StatePKcS2_mi",
    "pcall": "_Z9lua_pcallP9lua_Stateiii",
    "settop": "_Z10lua_settopP9lua_Statei",
    "tolstring": "_Z13lua_tolstringP9lua_StateiPm",
    "type": "_Z8lua_typeP9lua_Statei",
}


def ref_sizes() -> dict[str, int]:
    out = subprocess.run(["nm", "-S", "--defined-only", str(LUAU / "lapi.cpp.o")],
                         capture_output=True, text=True).stdout
    sizes = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4:
            sizes[p[3]] = int(p[1], 16)
    for extra in ("lvmload.cpp.o", "lcode.cpp.o", "lvmexecute.cpp.o"):
        out = subprocess.run(["nm", "-S", "--defined-only", str(LUAU / extra)],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            p = line.split()
            if len(p) == 4:
                sizes[p[3]] = int(p[1], 16)
    return {k: sizes[v] for k, v in REF_SYMBOL.items() if v in sizes}


def client_fdes() -> dict[int, int]:
    out = subprocess.run(["readelf", "--debug-dump=frames", str(SO)],
                         capture_output=True, text=True).stdout
    fdes = {}
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes[int(m.group(1), 16)] = int(m.group(2), 16) - int(m.group(1), 16)
    return fdes


def main() -> int:
    rs = ref_sizes()
    print("reference sizes:", {k: hex(v) for k, v in rs.items()})
    fdes = client_fdes()

    text = HDR.read_text()
    copies = re.findall(r"static const struct wieen_luau_copy LUA_COPY_(\d+) = \{(.*?)\};",
                        text, re.S)
    rows = []
    for idx, body in copies:
        vals = [int(v, 16) for v in re.findall(r"0x([0-9A-F]+)UL", body)]
        d = dict(zip(NAMES, vals))
        score = 0
        detail = []
        for k in NAMES:
            off = d.get(k, 0)
            size = fdes.get(off)
            want = rs.get(k)
            if size is not None and want is not None and size == want:
                score += 1
                detail.append(f"{k}:{size}")
            else:
                detail.append(f"{k}:{size}!={want}")
        rows.append((score, idx, d, detail))

    rows.sort(reverse=True)
    for score, idx, d, detail in rows[:15]:
        print(f"copy {idx:>3}  score {score}/9  pcall={d['pcall']:#x}  "
              + " ".join(detail))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
