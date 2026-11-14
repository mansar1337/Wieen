#!/usr/bin/env python3
"""Send the same snippet many times and report where a session breaks.

A single call can look fine and still leave the state of the game a little
wrong; the damage shows up in the calls that come after it.  This tool sends
one snippet over and over, times every call, and says which call was the
first that did not answer.  It does not start or stop the client: point it
at a session that is already up.

Usage:
    repeat.py [--count N] [--raw] [--snippet SOURCE]
"""
from __future__ import annotations

import argparse
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOCK = Path.home() / ".var/app/org.vinegarhq.Sober/data/wieen/wieen.sock"
COMPILER = REPO / "build" / "wieen-compile"

DEFAULT_SNIPPET = 'return "ok"'


def connect(deadline: float) -> socket.socket | None:
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect(str(SOCK))
            return s
        except OSError:
            time.sleep(0.2)
    return None


def compile_source(source: str, raw: bool) -> bytes | str:
    command = [str(COMPILER), "-"] + (["--raw"] if raw else [])
    proc = subprocess.run(command, input=source.encode(), capture_output=True)
    if proc.returncode != 0:
        return "compilation failed: " + proc.stderr.decode(errors="replace").strip()
    return proc.stdout


def send_once(chunk: bytes) -> str:
    sock = connect(time.time() + 5)
    if not sock:
        return "the agent is gone"
    try:
        sock.sendall(struct.pack("<I", len(chunk)) + chunk)
        header = sock.recv(4)
        if len(header) != 4:
            return "the agent closed the connection"
        (length,) = struct.unpack("<I", header)
        data = b""
        while len(data) < length:
            part = sock.recv(length - len(data))
            if not part:
                break
            data += part
        return data.decode(errors="replace")
    except OSError as exc:
        return f"the connection broke: {exc}"
    finally:
        sock.close()


def client_alive() -> bool:
    out = subprocess.run(["flatpak", "ps", "--columns=application"],
                         capture_output=True, text=True)
    return "org.vinegarhq.Sober" in out.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--raw", action="store_true")
    parser.add_argument("--snippet", default=DEFAULT_SNIPPET)
    args = parser.parse_args()

    chunk = compile_source(args.snippet, args.raw)
    if isinstance(chunk, str):
        print(chunk)
        return 1

    print(f"snippet: {args.snippet!r}, {len(chunk)} bytes, {args.count} calls")
    worst = 0.0
    for i in range(1, args.count + 1):
        started = time.time()
        result = send_once(chunk)
        took = time.time() - started
        worst = max(worst, took)
        # an "error:" answer is still an answer: the state of the game held
        broken = result.startswith("the ")
        print(f"  [{i:3}] {took:6.2f}s {result[:70]!r}")
        if broken:
            print(f"first broken call: {i}")
            print("client is", "up" if client_alive() else "gone")
            return 1
        if not client_alive():
            print("the client died while the calls were still answering")
            return 1
    print(f"all {args.count} calls answered, slowest {worst:.2f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
