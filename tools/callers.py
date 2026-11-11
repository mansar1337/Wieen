#!/usr/bin/env python3
"""wieen: find callers of a target address (inverse xref for direct calls).

Usage:
    callers.py <elf> <target_addr> [--region 0x3500000:0x3520000]
"""
import re
import struct
import subprocess
import sys


def main():
    elf = sys.argv[1]
    target = int(sys.argv[2], 0)
    region = None
    if "--region" in sys.argv:
        lo, hi = sys.argv[sys.argv.index("--region") + 1].split(":")
        region = (int(lo, 0), int(hi, 0))

    out = subprocess.run(["objdump", "-d", "-M", "intel", elf],
                         capture_output=True, text=True).stdout
    cur = None
    hits = []
    for line in out.splitlines():
        m = re.match(r"^\s+([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*call\s+([0-9a-f]+)\s+<", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        t = int(m.group(3), 16)
        if len(raw) == 5 and raw[0] == 0xe8:
            t = addr + 5 + struct.unpack_from("<i", raw, 1)[0]
        if t == target:
            hits.append(addr)
    for h in hits:
        if region and not (region[0] <= h <= region[1]):
            continue
        print(f"caller 0x{h:x}")


if __name__ == "__main__":
    main()
