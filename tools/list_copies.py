#!/usr/bin/env python3
"""List every candidate copy of the Luau VM with the size of each function.

The interpreter is the biggest function of the VM, so the candidate whose
interpreter has the size of the reference's luau_execute is the one worth
looking at.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"
HDR = REPO / "src/agent/luau_symbols.h"

NAMES = ["compile", "getfield", "gettop", "interpreter", "load",
         "pcall", "settop", "tolstring", "type"]


def main() -> int:
    out = subprocess.run(["readelf", "--debug-dump=frames", str(SO)],
                         capture_output=True, text=True).stdout
    fdes = {}
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes[int(m.group(1), 16)] = int(m.group(2), 16) - int(m.group(1), 16)

    text = HDR.read_text()
    copies = re.findall(r"static const struct wieen_luau_copy LUA_COPY_(\d+) = \{(.*?)\};",
                        text, re.S)
    for idx, body in copies:
        vals = [int(v, 16) for v in re.findall(r"0x([0-9A-F]+)UL", body)]
        d = dict(zip(NAMES, vals))
        sizes = " ".join(f"{k[:4]}={fdes.get(d[k], 0)}" for k in NAMES)
        print(f"copy {idx:>3}  interp={d['interpreter']:#x}({fdes.get(d['interpreter'],0)}) "
              f"pcall={d['pcall']:#x}({fdes.get(d['pcall'],0)})  {sizes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
