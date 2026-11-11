#!/usr/bin/env python3
"""Turn the agent shared object into the flat blob the host injects.

The blob keeps the section layout of the linked object: every section is
placed at its own virtual address and the gaps are filled with zeros, so
RIP relative references inside the code keep pointing at the right place.

Writes  <blob>          the raw image
        <blob>.json     symbol offsets and the relocation list
"""
import json
import subprocess
import sys


def sections(obj):
    out = subprocess.run(["readelf", "-S", "-W", obj], capture_output=True, text=True).stdout
    secs = []
    for line in out.splitlines():
        parts = line.replace("[", " ").replace("]", " ").split()
        if len(parts) > 6:
            name, typ = parts[1], parts[2]
            try:
                addr = int(parts[3], 16)
                off = int(parts[4], 16)
                size = int(parts[5], 16)
            except ValueError:
                continue
            secs.append((name, typ, addr, off, size))
    return secs


def symbols(obj):
    out = subprocess.run(["nm", "-S", obj], capture_output=True, text=True).stdout
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 4:
            syms[parts[3]] = int(parts[0], 16)
        elif len(parts) == 3:
            syms[parts[2]] = int(parts[0], 16)
    return syms


def relocations(obj):
    out = subprocess.run(["readelf", "-r", "-W", obj], capture_output=True, text=True).stdout
    rels = []
    for line in out.splitlines():
        if "R_X86_64_RELATIVE" not in line:
            continue
        parts = line.split()
        if len(parts) >= 4:
            try:
                rels.append((int(parts[0], 16), int(parts[2], 16)))
            except ValueError:
                pass
    return rels


def main():
    obj, out = sys.argv[1], sys.argv[2]
    keep = ("wieen_blob_start", ".text", ".rodata", ".data", ".bss")
    secs = [s for s in sections(obj) if s[0] in keep]
    secs.sort(key=lambda s: s[2])

    total = max((s[2] + s[4]) for s in secs) if secs else 0
    blob = bytearray(total)
    with open(obj, "rb") as f:
        for name, typ, addr, off, size in secs:
            if typ == "NOBITS":
                continue
            f.seek(off)
            data = f.read(size)
            blob[addr:addr + len(data)] = data

    syms = symbols(obj)
    rels = relocations(obj)
    info = {
        "size": len(blob),
        "symbols": syms,
        "relocs": [{"offset": o, "addend": a} for o, a in rels],
    }
    open(out, "wb").write(bytes(blob))
    json.dump(info, open(out + ".json", "w"), indent=1)
    print(f"{out}: {len(blob)} bytes, {len(rels)} relative relocations")


if __name__ == "__main__":
    main()
