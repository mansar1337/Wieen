#!/usr/bin/env python3
"""Show the structure of a Luau bytecode blob.

    bytecode.py <file.bin>

The blob is the one the host compiler produces for the client: the opcode
numbers in it are the wire numbers of the client, so they are shown with
the name of the upstream opcode they came from.
"""
from __future__ import annotations

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]


def wire_to_name() -> dict[int, str]:
    names: dict[int, str] = {}
    for line in (REPO / "tools/opcode_map.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        names[int(parts[3])] = parts[1]
    return names


class Blob:
    def __init__(self, data: bytes):
        self.d = data
        self.o = 0

    def u8(self) -> int:
        b = self.d[self.o]
        self.o += 1
        return b

    def varint(self) -> int:
        result = 0
        shift = 0
        while True:
            b = self.u8()
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                return result

    def u32(self) -> int:
        v = int.from_bytes(self.d[self.o:self.o + 4], "little")
        self.o += 4
        return v

    def skip(self, n: int) -> None:
        self.o += n


def main() -> int:
    path = sys.argv[1]
    data = pathlib.Path(path).read_bytes()
    names = wire_to_name()
    b = Blob(data)
    version = b.u8()
    typesversion = b.u8()
    print(f"version={version} typesversion={typesversion} size={len(data)}")
    strings = b.varint()
    print(f"strings={strings}")
    for _ in range(strings):
        n = b.varint()
        b.skip(n)
    if typesversion >= 1:
        index = b.u8()
        while index != 0:
            b.varint()
            index = b.u8()
    protos = b.varint()
    print(f"protos={protos}")
    for p in range(protos):
        size = b.varint()
        start = b.o
        maxstack = b.u8()
        numparams = b.u8()
        nups = b.u8()
        is_vararg = b.u8()
        flags = b.u8()
        typesize = b.varint()
        b.skip(typesize)
        sizecode = b.varint()
        ops: list[int] = []
        for i in range(sizecode):
            word = b.u32()
            ops.append(word & 0xFF)
        b.o = start + size
        print(f"  proto {p}: size={size} stack={maxstack} params={numparams} "
              f"upvals={nups} vararg={is_vararg} flags={flags} "
              f"types={typesize} code={sizecode}")
        print("    ops: " + " ".join(
            f"{op}:{names.get(op, '?')}" for op in ops))
    mainid = b.varint()
    print(f"main={mainid} at_end={b.o == len(data)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
