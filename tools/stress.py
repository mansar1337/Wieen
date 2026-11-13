#!/usr/bin/env python3
"""Run a script over and over and watch the client.

The client of Roblox checks its own code and patches it at runtime, and
the emulator of Sober does not understand every instruction the client
writes.  This runs a script every few seconds and says when the client is
gone, so a crash can be told apart from a crash caused by the scripts.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[1])


def alive() -> bool:
    out = subprocess.run(["flatpak", "ps", "--columns=application"],
                         capture_output=True, text=True)
    return "org.vinegarhq.Sober" in out.stdout


def main() -> int:
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 240
    every = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    deadline = time.time() + seconds
    n = 0
    while time.time() < deadline:
        n += 1
        started = time.time()
        proc = subprocess.run([sys.executable, f"{REPO}/src/cli/wieen.py", "exec",
                               "return 1 + 1"], capture_output=True, text=True)
        took = time.time() - started
        out = (proc.stdout or proc.stderr).strip().splitlines()
        last = out[-1] if out else "(nothing)"
        print(f"[{n}] {last!r} ({took:.2f}s)", flush=True)
        if not alive():
            print("the client is gone")
            return 1
        time.sleep(every)
    print(f"the client is still there after {n} scripts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
