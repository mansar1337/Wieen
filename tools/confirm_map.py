#!/usr/bin/env python3
"""Confirm the function mapping by comparing instruction sequences.

The alignment lines the reference build's functions up with the client's by
size and order, which is not proof: the client's Luau is a different
revision, so the order may differ.  Here every reference function is
matched against every client function in the region by the *shape* of its
machine code - the sequence of opcodes - which does not depend on the
register allocation or the frame layout.

Usage:
    confirm_map.py --lo 0x3180000 --hi 0x3240000 --obj lapi.cpp.o
"""
from __future__ import annotations

import argparse
import difflib
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
SO = REPO / "work/libs/libroblox.so"
LUAU = REPO / "work/luau-src/build-rel/x"

WANTED = {
    "lapi.cpp.o": ["_Z9lua_pcallP9lua_Stateiii", "_Z12lua_getfieldP9lua_StateiPKc",
                   "_Z10lua_gettopP9lua_State", "_Z10lua_settopP9lua_Statei",
                   "_Z13lua_tolstringP9lua_StateiPm", "_Z8lua_typeP9lua_Statei",
                   "_Z8lua_callP9lua_Stateii"],
    "lvmload.cpp.o": ["_Z9luau_loadP9lua_StatePKcS2_mi"],
    "lcode.cpp.o": ["_Z12luau_compilePKcmP18lua_CompileOptionsPm"],
    "lvmexecute.cpp.o": ["_ZL12luau_executeILb0EEvP9lua_State"],
    "lstate.cpp.o": ["_Z14lua_newstatePFvPvmmS0_", "_Z9lua_closeP9lua_State"],
    "laux.cpp.o": ["_Z15luaL_newstate", "_Z9luaL_openlibsP9lua_State"],
}


def segments(data: bytes):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from("<QQQQQ", data, off + 8)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz))
    return segs


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


def disasm_blob(blob: bytes, base: int):
    """-> list of (address, mnemonic)"""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp.write(blob)
        path = tmp.name
    try:
        out = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", path],
            capture_output=True, text=True).stdout
    finally:
        Path(path).unlink(missing_ok=True)
    res = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S+)", line)
        if m:
            res.append((int(m.group(1), 16) + base, m.group(3)))
    return res


def mnemonics_of_ref(obj: Path, funcs):
    """mnemonic list per reference function"""
    out = subprocess.run(["objdump", "-d", "-M", "intel", str(obj)],
                         capture_output=True, text=True).stdout
    insns = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S+)", line)
        if m:
            insns.append((int(m.group(1), 16), m.group(3)))
    res = {}
    starts = [f[0] for f in funcs]
    for addr, size, name in funcs:
        seq = [mn for a, mn in insns if addr <= a < addr + size]
        res[name] = seq
    return res


def mnemonics_of_client(so: Path, region):
    data = so.read_bytes()
    segs = segments(data)
    lo = region[0][0]
    hi = region[-1][0] + region[-1][1]
    # find the file range
    fo = None
    for va, po, fs in segs:
        if va <= lo < va + fs:
            fo = po + (lo - va)
            flen = hi - lo
            break
    if fo is None:
        return {}
    blob = data[fo:fo + flen]
    insns = disasm_blob(blob, lo)
    res = {}
    for addr, size in region:
        res[addr] = [mn for a, mn in insns if addr <= a < addr + size]
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lo", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--hi", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--obj", default="lapi.cpp.o")
    args = ap.parse_args()

    all_funcs = client_functions(SO)
    region = [(a, s) for a, s in all_funcs if args.lo <= a < args.hi]
    print(f"region: {len(region)} functions")

    ref = reference_functions(LUAU / args.obj)
    refm = mnemonics_of_ref(LUAU / args.obj, ref)
    clm = mnemonics_of_client(SO, region)
    print(f"disassembled {len(clm)} client functions")

    # bag of mnemonics, cosine similarity
    vocab = {}
    for seq in refm.values():
        for mn in seq:
            vocab.setdefault(mn, len(vocab))
    cvocab = {}
    for seq in clm.values():
        for mn in seq:
            cvocab.setdefault(mn, len(cvocab))
    shared = sorted(set(vocab) & set(cvocab))
    print(f"mnemonics: {len(vocab)} reference, {len(cvocab)} client, {len(shared)} shared")

    def vector(seq, table):
        v = np.zeros(len(table), dtype=np.float32)
        for mn in seq:
            i = table.get(mn)
            if i is not None:
                v[i] += 1
        return v

    table = {mn: i for i, mn in enumerate(shared)}
    refvecs = [vector(refm[n], table) for _, _, n in ref]
    clvecs = [vector(clm[a], table) for a, _ in region]
    R = np.stack(refvecs)
    C = np.stack(clvecs)
    R /= np.linalg.norm(R, axis=1, keepdims=True) + 1e-9
    C /= np.linalg.norm(C, axis=1, keepdims=True) + 1e-9
    S = R @ C.T

    # refine with the order of the instructions, which the bag ignores
    wanted = set(WANTED.get(args.obj, []))
    results = []
    for ri, (_, rsize, name) in enumerate(ref):
        rseq = refm[name]
        if len(rseq) < 6:
            continue
        cand = np.argsort(-S[ri])[:40]
        best = (0.0, None)
        for ci in cand:
            cseq = clm[region[int(ci)][0]]
            if not cseq:
                continue
            ratio = difflib.SequenceMatcher(None, rseq, cseq).ratio()
            if ratio > best[0]:
                best = (ratio, int(ci))
        if best[1] is None:
            continue
        caddr, csize = region[best[1]]
        results.append((best[0], name, rsize, caddr, csize, best[1]))

    results.sort(reverse=True)
    for score, name, rsize, caddr, csize, ci in results:
        if name in wanted or score > 0.8:
            mark = "  <<<" if name in wanted else ""
            print(f"  {name:55} ref_size={rsize:5} -> {caddr:#x} size={csize:5} "
                  f"score={score:.3f}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
