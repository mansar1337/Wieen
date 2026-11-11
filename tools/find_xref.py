#!/usr/bin/env python3
"""Find the code that references a string in the client image.

Used to anchor the Luau VM: the strings that the VM's error paths use are
unique, so the function that mentions one of them belongs to the VM, and
that tells us where the VM lives in the image.
"""
from __future__ import annotations

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


def fdes(path: pathlib.Path):
    out = subprocess.run(["readelf", "--debug-dump=frames", str(path)],
                         capture_output=True, text=True).stdout
    funcs = []
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        funcs.append((lo, hi - lo))
    funcs.sort()
    return funcs


def find_string(data, segs, needle: bytes):
    idx = data.find(needle)
    if idx < 0:
        return None
    for va, po, fs, fl in segs:
        if po <= idx < po + fs:
            return va + (idx - po)
    return None


def xrefs(data, segs, target: int):
    """All rip-relative references to `target` inside executable segments.

    The scan is generic: any 32-bit displacement that resolves to the
    target counts, whatever instruction it belongs to.
    """
    hits = []
    for va, po, fs, fl in segs:
        if not (fl & 1):
            continue
        seg = data[po:po + fs]
        arr = np.frombuffer(seg, dtype=np.uint8)
        # every 4-byte window interpreted as a signed displacement
        win = np.lib.stride_tricks.as_strided(arr, shape=(len(arr) - 3, 4),
                                               strides=(1, 1))
        disp = win.copy().view(np.int32).reshape(-1)
        dest = va + np.arange(len(disp), dtype=np.int64) + 4 + disp.astype(np.int64)
        for i in np.nonzero(dest == target)[0]:
            hits.append(va + int(i))
    return hits


def main() -> int:
    data, segs = load(SO)
    funcs = fdes(SO)
    starts = [f[0] for f in funcs]

    for needle in sys.argv[1:]:
        target = find_string(data, segs, needle.encode())
        if target is None:
            print(f"{needle!r}: not found")
            continue
        hits = xrefs(data, segs, target)
        print(f"{needle!r} at {target:#x}: {len(hits)} xrefs")
        for h in hits:
            i = bisect.bisect_right(starts, h) - 1
            lo, size = funcs[i]
            print(f"    xref {h:#x}  ->  function {lo:#x} (size {size})")


if __name__ == "__main__":
    sys.exit(main())
