#!/usr/bin/env python3
"""Map the reference Luau API onto the client by anchoring on a known pair.

The client's Luau is a slightly different revision, so the functions are not
in the same place and not exactly the same size - but they keep their order.
We anchor the two lists on a function we can identify in the client (here:
one that mentions a string only the VM uses) and then check whether the
rest of the lists line up.
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--obj", default="lapi.cpp.o")
    ap.add_argument("--anchor-ref", required=True,
                    help="mangled name of the reference function we located")
    ap.add_argument("--anchor-client", required=True, help="client address")
    args = ap.parse_args()

    cf = client_functions(SO)
    cstarts = [f[0] for f in cf]
    import bisect
    cidx = bisect.bisect_left(cstarts, int(args.anchor_client, 0))
    print(f"anchor {args.anchor_client} -> client index {cidx} "
          f"(addr {cf[cidx][0]:#x} size {cf[cidx][1]})")

    rf = reference_functions(LUAU / args.obj)
    ridx = None
    for i, (_, _, name) in enumerate(rf):
        if name == args.anchor_ref:
            ridx = i
    if ridx is None:
        print("reference symbol not found")
        return 1
    print(f"reference {args.anchor_ref} -> index {ridx} (size {rf[ridx][1]})")

    delta = cidx - ridx
    print(f"delta = {delta}")
    print()
    good = bad = 0
    for i, (_, rsize, name) in enumerate(rf):
        j = i + delta
        if j < 0 or j >= len(cf):
            continue
        caddr, csize = cf[j]
        ratio = csize / rsize if rsize else 0
        flag = "ok " if 0.75 <= ratio <= 1.3 else "BAD"
        if flag == "ok ":
            good += 1
        else:
            bad += 1
        print(f"  {flag} {i:3} {name:55} ref={rsize:5} -> client {caddr:#x} size={csize:5} "
              f"ratio={ratio:.2f}")
    print(f"\n{good} plausible, {bad} not")
    return 0


if __name__ == "__main__":
    sys.exit(main())
