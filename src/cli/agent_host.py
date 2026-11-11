#!/usr/bin/env python3
"""Wieen host — talk to the agent that lives inside the Roblox client.

The agent is preloaded into Sober's client process (see
tools/install_preload.sh).  It exposes a mailbox in the client's own memory;
the host writes a Luau snippet there and reads the result back.  No sockets
are involved, so the agent never has to make a system call while it runs
inside the traced client.
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inject  # noqa: E402

AGENT_LIB = "/home/xendr4x/.var/app/org.vinegarhq.Sober/data/wieen/wieen_agent.so"

# struct wieen_mbox { u64 cmd_len, status, result_len, seq; char cmd[], result[]; }
MBOX_HEADER = 32
MAX_MESSAGE = 64 * 1024


class Agent:
    """The agent inside the Roblox client."""

    def __init__(self):
        self.pid, self.base = inject.find_client()
        self.mbox = inject.runtime_symbol(self.pid, AGENT_LIB, "wieen_mbox")
        self.seq = 0

    # -- raw mailbox access -------------------------------------------
    def _read(self, off: int, size: int) -> bytes:
        return inject.read_mem(self.pid, self.mbox + off, size)

    def _write(self, off: int, data: bytes) -> None:
        inject.write_mem(self.pid, self.mbox + off, data)

    def _u64(self, off: int) -> int:
        return struct.unpack("<Q", self._read(off, 8))[0]

    def _set_u64(self, off: int, value: int) -> None:
        self._write(off, struct.pack("<Q", value))

    # -- protocol -----------------------------------------------------
    def run(self, source: str, timeout: float = 15.0) -> str:
        payload = source.encode()
        if len(payload) > MAX_MESSAGE:
            raise ValueError("command too long")
        self.seq += 1
        # cmd_len @0, status @8, result_len @16, seq @24, cmd @32, result @32+64K
        self._write(MBOX_HEADER, payload + b"\0" * (MAX_MESSAGE - len(payload)))
        self._set_u64(24, self.seq)          # seq
        self._set_u64(0, len(payload))      # cmd_len
        self._set_u64(8, 0)                 # status

        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self._u64(8)
            seq = self._u64(16)
            if status == 1 and seq == self.seq:
                rlen = self._u64(16)
                rlen = min(rlen, MAX_MESSAGE)
                data = self._read(MBOX_HEADER + MAX_MESSAGE, rlen)
                self._set_u64(8, 0)
                return data.decode(errors="replace")
            time.sleep(0.02)
        raise TimeoutError("the agent did not answer in time")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: wieen_agent_host.py <source>", file=sys.stderr)
        return 2
    agent = Agent()
    print(agent.run(sys.argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
