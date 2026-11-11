#!/usr/bin/env python3
"""Read a Windows minidump: the exception and the faulting address."""
from __future__ import annotations

import pathlib
import struct
import sys


def main() -> int:
    path = pathlib.Path(sys.argv[1])
    data = path.read_bytes()
    if data[:4] != b"MDMP":
        print("not a minidump")
        return 1
    nstreams = struct.unpack_from("<I", data, 8)[0]
    dir_rva = struct.unpack_from("<I", data, 12)[0]
    print(f"{nstreams} streams")

    for i in range(nstreams):
        off = dir_rva + i * 12
        stype, size, rva = struct.unpack_from("<III", data, off)
        if stype == 6:  # ExceptionStream
            tid, align = struct.unpack_from("<II", data, rva)
            code, flags, record, address = struct.unpack_from("<IIII", data, rva + 8)
            nparams = struct.unpack_from("<I", data, rva + 24)[0]
            print(f"exception: thread {tid} code {code:#x} address {address:#x} "
                  f"params {nparams}")
            for p in range(min(nparams, 4)):
                v = struct.unpack_from("<Q", data, rva + 32 + p * 8)[0]
                print(f"   param{p} = {v:#x}")
        elif stype == 3:  # ThreadList
            count = struct.unpack_from("<I", data, rva)[0]
            print(f"threads: {count}")
            for t in range(count):
                tid, stack_start, stack_size, ctx_rva = struct.unpack_from(
                    "<IIII", data, rva + 4 + t * 48)
                if t == 0 and ctx_rva:
                    rip, rsp, rbp = struct.unpack_from("<QQQ", data, ctx_rva + 0xF8)
                    print(f"   thread {tid} rip={rip:#x} rsp={rsp:#x} rbp={rbp:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
