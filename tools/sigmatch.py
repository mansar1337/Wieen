#!/usr/bin/env python3
"""wieen: signature matcher.

Extracts the leading instruction bytes of a function from a locally built
object/archive and searches a target ELF for near-identical windows.

Used to locate Luau API functions inside the stripped Roblox client binary.

Usage:
    sigmatch.py --dump <archive> <symbol>          # show bytes of a symbol
    sigmatch.py --scan <target.so> <archive> <symbol> [--bytes N] [--tol N]
"""
import re
import struct
import subprocess
import sys


def objdump_function(archive, symbol):
    """Disassemble the whole archive and slice out one function's bytes."""
    out = subprocess.run(
        ["objdump", "-d", archive],
        capture_output=True, text=True).stdout
    m = re.search(r"^[0-9a-f]+ <" + re.escape(symbol) + r">:\s*$", out, re.M)
    if not m:
        return None
    body = out[m.end():]
    raw = bytearray()
    for line in body.splitlines():
        mm = re.match(r"^\s+([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)", line)
        if not mm:
            if raw:
                break
            continue
        raw += bytes.fromhex(mm.group(2).replace(" ", ""))
    return bytes(raw)


def text_of(elf):
    """Return (bytes, vaddr) of the executable PT_LOAD segments concatenated."""
    data = open(elf, "rb").read()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    chunks = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        if p_type != 1 or not (p_flags & 1):
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 0x08)
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        chunks.append((p_vaddr, data[p_offset:p_offset + p_filesz]))
    return chunks


def score(a, b):
    """Mismatch count between two byte strings (len = min)."""
    n = min(len(a), len(b))
    return sum(1 for i in range(n) if a[i] != b[i])


def scan_target(target, pat, tol, nbytes, topk=6, lo=None, hi=None):
    """Chunked tolerant sliding-window search across executable segments."""
    import numpy as np
    patarr = np.frombuffer(pat[:nbytes], dtype=np.uint8)
    results = []
    for vaddr, seg in text_of(target):
        if lo is not None and vaddr + len(seg) < lo:
            continue
        if hi is not None and vaddr > hi:
            continue
        arr = np.frombuffer(seg, dtype=np.uint8)
        step = 1 << 20
        for base in range(0, max(1, len(arr) - nbytes), step):
            end = min(base + step, len(arr) - nbytes)
            if end <= base:
                break
            chunk = arr[base:end]
            win = np.lib.stride_tricks.sliding_window_view(chunk, nbytes)
            diff = (win != patarr).sum(axis=1)
            order = np.argsort(diff)[:topk]
            for o in order:
                d = int(diff[o])
                addr = vaddr + base + int(o)
                if lo is not None and addr < lo:
                    continue
                if hi is not None and addr > hi:
                    continue
                if d <= tol:
                    results.append((d, addr, seg[base + int(o):base + int(o) + nbytes]))
    results.sort()
    return results


def main():
    args = sys.argv[1:]
    mode = args[0]
    if mode == "--dump":
        print(objdump_function(args[1], args[2]).hex(" "))
        return

    target = args[1]
    archive = args[2]
    symbol = args[3]
    nbytes = 32
    tol = 8
    if "--bytes" in args:
        nbytes = int(args[args.index("--bytes") + 1])
    if "--tol" in args:
        tol = int(args[args.index("--tol") + 1])

    pat = objdump_function(archive, symbol)
    if not pat:
        print(f"symbol {symbol} not found in {archive}", file=sys.stderr)
        sys.exit(1)
    pat = pat[:nbytes]
    print(f"# {symbol}: {pat.hex(' ')}")

    lo = hi = None
    if "--lo" in args:
        lo = int(args[args.index("--lo") + 1], 0)
    if "--hi" in args:
        hi = int(args[args.index("--hi") + 1], 0)

    for d, va, win in scan_target(target, pat, tol, nbytes, lo=lo, hi=hi):
        print(f"  MATCH vaddr=0x{va:x} diff={d}/{nbytes}  {win.hex(' ')}")


if __name__ == "__main__":
    main()
