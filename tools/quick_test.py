#!/usr/bin/env python3
"""Start Sober and run a snippet as soon as the agent is up.

The Roblox client only lives for a short while when nobody is logged in,
so the test has to be quick: it waits for the socket to answer and sends
the command right away.
"""
from __future__ import annotations

import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOCK = Path.home() / ".var/app/org.vinegarhq.Sober/data/wieen/wieen.sock"
COMPILER = REPO / "build" / "wieen-compile"


def connect(deadline: float):
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(20)
            s.connect(str(SOCK))
            return s
        except OSError:
            time.sleep(0.2)
    return None


def main() -> int:
    source = sys.argv[1] if len(sys.argv) > 1 else "return 1+1"

    subprocess.run(["flatpak", "kill", "org.vinegarhq.Sober"], capture_output=True)
    time.sleep(2)
    log = open("/tmp/opencode/sober_fast.log", "wb")
    subprocess.Popen(["flatpak", "run", "org.vinegarhq.Sober"],
                     stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                     start_new_session=True)

    s = connect(time.time() + 60)
    if not s:
        print("the agent never showed up")
        return 1
    print("connected to the agent")

    proc = subprocess.run([str(COMPILER), "-"], input=source.encode(),
                          capture_output=True)
    if proc.returncode != 0:
        print("compilation failed:", proc.stderr.decode(errors="replace"))
        return 1
    payload = proc.stdout

    s.sendall(struct.pack("<I", len(payload)) + payload)
    header = s.recv(4)
    if len(header) < 4:
        print("the agent closed the connection")
        return 1
    (length,) = struct.unpack("<I", header)
    data = b""
    while len(data) < length:
        chunk = s.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    print("result:", data.decode(errors="replace"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
