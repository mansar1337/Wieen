#!/usr/bin/env python3
"""wieen: align a stripped binary's function sequence against a reference build.

Both sequences are (address, size) lists. We align them with difflib using a
size-similarity heuristic, so a reference function name can be transferred to
the stripped target even though the compilers differ.

Usage:
    align.py <target.elf> <target_lo> <target_hi> <reference.o> [symbol_filter]
"""
import difflib
import re
import subprocess
import sys


def target_funcs(elf, lo, hi):
    """Function inventory from .eh_frame (exact pc ranges)."""
    out = subprocess.run(
        ["python3", __file__.rsplit("/", 1)[0] + "/ehframe.py", elf, "--lo", hex(lo), "--hi", hex(hi)],
        capture_output=True, text=True).stdout
    res = []
    for line in out.splitlines():
        m = re.match(r"0x([0-9a-f]+)\s+(\d+)", line)
        if m:
            res.append((int(m.group(1), 16), int(m.group(2))))
    return res


def ref_funcs(obj, filt=None):
    out = subprocess.run(["nm", "-S", "--defined-only", obj], capture_output=True, text=True).stdout
    res = []
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]+)\s+([0-9a-f]+)\s+([tT])\s+(\S+)", line)
        if not m:
            continue
        name = m.group(4)
        if filt and filt not in name:
            continue
        res.append((int(m.group(1), 16), int(m.group(2), 16), name))
    res.sort()
    return res


def main():
    elf, lo, hi, obj = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), sys.argv[4]
    filt = sys.argv[5] if len(sys.argv) > 5 else None

    tgt = target_funcs(elf, lo, hi)
    ref = ref_funcs(obj, filt)
    print(f"target functions: {len(tgt)}   reference functions: {len(ref)}")

    def close(a, b):
        if a == b:
            return 1.0
        m = max(a, b)
        if m == 0:
            return 1.0
        return max(0.0, 1.0 - abs(a - b) / m)

    # Needleman-Wunsch on size similarity
    n, m = len(ref), len(tgt)
    GAP = -0.35
    dp = [[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        dp[i][0] = dp[i - 1][0] + GAP
    for j in range(1, m + 1):
        dp[0][j] = dp[0][j - 1] + GAP
    for i in range(1, n + 1):
        ri = ref[i - 1][1]
        for j in range(1, m + 1):
            sim = 2.0 * close(ri, tgt[j - 1][1]) - 0.6
            dp[i][j] = max(dp[i - 1][j - 1] + sim, dp[i - 1][j] + GAP, dp[i][j - 1] + GAP)

    pairs = []
    i, j = n, m
    while i > 0 and j > 0:
        ri = ref[i - 1][1]
        sim = 2.0 * close(ri, tgt[j - 1][1]) - 0.6
        if abs(dp[i][j] - (dp[i - 1][j - 1] + sim)) < 1e-9:
            pairs.append((ref[i - 1], tgt[j - 1], close(ri, tgt[j - 1][1])))
            i, j = i - 1, j - 1
        elif dp[i][j] == dp[i - 1][j] + GAP:
            i -= 1
        else:
            j -= 1
    pairs.reverse()
    print(f"{'reference':<58} {'ref size':>9} {'target':>12} {'tgt size':>9}  sim")
    for r, t, s in pairs:
        if s < 0.55:
            continue
        print(f"  {r[2]:<56} {r[1]:>9}  0x{t[0]:x} {t[1]:>9}  {s:.2f}")


if __name__ == "__main__":
    main()
