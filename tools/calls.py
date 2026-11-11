#!/usr/bin/env python3
"""wieen: list the direct call targets inside an address range of an ELF.

Flags targets that land inside known Luau code regions so the VM entry
points can be picked out of Roblox call sites.

Usage:
    calls.py <elf> <start> <end> [--vm 0x31e0000:0x3220000] [--mark 0x3500000:0x3520000]
"""
import re
import struct
import subprocess
import sys


def parse_ranges(args):
    out = []
    for a in args:
        if ":" in a:
            lo, hi = a.split(":")
            out.append((int(lo, 0), int(hi, 0)))
    return out


def main():
    elf = sys.argv[1]
    lo, hi = int(sys.argv[2], 0), int(sys.argv[3], 0)
    marks = []
    for flag in ("--vm", "--mark"):
        if flag in sys.argv:
            marks.append((flag, parse_ranges([sys.argv[sys.argv.index(flag) + 1]])[0]))

    out = subprocess.run(
        ["objdump", "-d", f"--start-address={lo}", f"--stop-address={hi}", "-M", "intel", elf],
        capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*call\s+([0-9a-f]+)\s+<", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        target = int(m.group(3), 16)
        # relative call target
        if len(raw) == 5 and raw[0] == 0xe8:
            disp = struct.unpack_from("<i", raw, 1)[0]
            target = addr + 5 + disp
        tag = ""
        for name, (a, b) in marks:
            if a <= target <= b:
                tag = f"  <== {name}"
        print(f"0x{addr:x}  call 0x{target:x}{tag}")


if __name__ == "__main__":
    main()
