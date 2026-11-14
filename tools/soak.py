#!/usr/bin/env python3
"""Run a handful of scripts in one session of Sober and watch the process.

A single command proves that the agent can run something; this proves that
it can keep doing it.  The client is started once, every snippet is sent
to the same session with a pause in between, and then the client is left
alone for a while: if it is still there at the end, the agent did not
break it.
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
LOG = REPO / "build" / "soak-sober.log"

SNIPPETS = [
    'print("hello world!")',
    "return 1 + 1",
    'local t = {} for i = 1, 1000 do t[i] = i * 2 end return #t',
    'print("second print") return tostring(2 ^ 10)',
    "local s = 0 for i = 1, 100000 do s = s + i end return s",
    'return type(game) .. " " .. tostring(wait)',
]


def connect(deadline: float) -> socket.socket | None:
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect(str(SOCK))
            return s
        except OSError:
            time.sleep(0.2)
    return None


def send(sock: socket.socket, source: str, raw: bool) -> str:
    command = [str(COMPILER), "-"]
    if raw:
        command.append("--raw")
    proc = subprocess.run(command, input=source.encode(), capture_output=True)
    if proc.returncode != 0:
        return "compilation failed: " + proc.stderr.decode(errors="replace").strip()
    chunk = proc.stdout
    sock.sendall(struct.pack("<I", len(chunk)) + chunk)
    header = sock.recv(4)
    if len(header) != 4:
        return "the agent closed the socket"
    (length,) = struct.unpack("<I", header)
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            break
        data += part
    return data.decode(errors="replace")


def send_retry(sock: socket.socket | None, source: str, raw: bool):
    """Send a snippet, reconnecting once if the socket died on the way.

    A long session outlives single connections; a broken pipe says nothing
    about the client, so the test asks again on a fresh one.
    """
    if sock is None:
        sock = connect(time.time() + 10)
    try:
        return send(sock, source, raw), sock
    except OSError:
        try:
            sock.close()
        except OSError:
            pass
        sock = connect(time.time() + 10)
        if sock is None:
            return "the agent is gone", None
        try:
            return send(sock, source, raw), sock
        except OSError as error:
            return f"the socket broke twice: {error}", sock


def alive(proc: subprocess.Popen | None = None) -> bool:
    # the client lives in a pid namespace of its own, so the host can only
    # see the instance flatpak started
    out = subprocess.run(["flatpak", "ps", "--columns=application"],
                         capture_output=True, text=True)
    if proc is not None and proc.poll() is not None:
        print(f"    flatpak run exited with {proc.returncode}")
    return "org.vinegarhq.Sober" in out.stdout


def main() -> int:
    idle = int(sys.argv[1]) if len(sys.argv) > 1 else 180
    raw = "--raw" in sys.argv

    LOG.parent.mkdir(parents=True, exist_ok=True)
    sock = None
    proc = None
    # the client sometimes closes itself a second after it starts, when the
    # network to the CDN of Roblox is not there; a start that holds is what
    # the test needs
    for attempt in range(1, 4):
        subprocess.run(["flatpak", "kill", "org.vinegarhq.Sober"], capture_output=True)
        time.sleep(2)
        log = open(LOG, "wb")
        proc = subprocess.Popen(
            [sys.executable, str(REPO / "src/cli/wieen.py"), "launch"],
            stdout=log, stderr=log, stdin=subprocess.DEVNULL,
            start_new_session=True)
        sock = connect(time.time() + 60)
        if not sock:
            print(f"attempt {attempt}: the agent never showed up")
            continue
        time.sleep(8)
        if alive(proc):
            print(f"connected; the client is up (attempt {attempt})")
            break
        print(f"attempt {attempt}: the client closed itself during startup")
        sock = None
    if not sock:
        print("the client does not stay up; is the network of Roblox there?")
        return 1

    # the client needs a moment before it runs scripts of its own, and the
    # agent can only run something inside one of them
    time.sleep(5)

    failures = 0
    for i, snippet in enumerate(SNIPPETS, 1):
        started = time.time()
        result, sock = send_retry(sock, snippet, raw)
        took = time.time() - started
        ok = not result.startswith("error") and "did not run" not in result \
            and not result.startswith("the ")
        if not ok:
            failures += 1
        print(f"[{i}] {snippet[:44]!r}\n    -> {result[:120]!r} ({took:.2f}s){'' if ok else ' - FAILED'}")
        if not alive(proc):
            print("the client is gone already")
            return 1
        time.sleep(1)

    print(f"idling for {idle} seconds")
    deadline = time.time() + idle
    while time.time() < deadline:
        time.sleep(min(30, max(1, deadline - time.time())))
        if not alive(proc):
            print("the client died while idle")
            return 1
        print(f"    still there, {int(deadline - time.time())} s of idle time left")

    print("done:", len(SNIPPETS) - failures, "of", len(SNIPPETS), "ran")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
