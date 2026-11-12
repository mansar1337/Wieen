#!/usr/bin/env python3
"""Run a list of snippets inside the game and print what they returned.

The agent serves one chunk per connection, so all the snippets of a run
share a single Sober session - which keeps the test quick.
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

RAW = "--raw" in __import__("sys").argv

SNIPPETS = [
    ("string", 'return "wieen-ok"'),
    ("builtin", 'return tostring(1)'),
    ("closure call", 'local f = function() return 1 end return f()'),
    ("global", 'return game ~= nil'),
    ("math call", 'return math.floor(2.5)'),
    ("arithmetic", "return 1 + 1"),
    ("power", "return 2 ^ 10"),
    ("division", "return 7 / 2"),
    ("modulo", "return 7 % 3"),
    ("length", 'return #"hello"'),
    ("typeof", "return typeof(game)"),
    ("loop", "local s = 0 for i = 1, 10 do s = s + i end return s"),
    ("table", "local t = {} for i = 1, 5 do t[i] = i * 2 end return table.concat(t, \",\")"),
    ("function", "local f = function(a, b) return a + b end return f(3, 4)"),
    ("closure", "local function outer() local x = 5 local function inner() return x end return inner() end return outer()"),
    ("string method", 'return ("abc"):upper()'),
    ("math", "return math.floor(3.7)"),
    ("nil", "return tostring(nil)"),
    ("varargs", 'return select("#", 1, 2, 3)'),
    ("named fields", "local t = {a = 1, b = 2} return t.a + t.b"),
    ("comparison", "if 1 < 2 and 3 >= 3 then return \"yes\" else return \"no\" end"),
    ("and or not", "return tostring(true and false or true)"),
    ("concatenation", 'return "a" .. "b" .. "c"'),
    ("method call", "return game:GetService(\"Players\") ~= nil"),
    ("repeat", "local i = 0 repeat i = i + 1 until i >= 3 return i"),
    ("while", "local i = 0 while i < 4 do i = i + 1 end return i"),
    ("generic for", "local s = 0 for _, v in ipairs({1, 2, 3}) do s = s + v end return s"),
    ("nested table", "local t = {a = {b = {c = 42}}} return t.a.b.c"),
    ("unary minus", "return -5"),
    ("multiple returns", "local function f() return 1, 2 end return select(2, f())"),
    ("wait", 'wait() return "waited"'),
    ("wait with time", 'wait(0.1) return "waited"'),
    ("task wait", 'task.wait() return "waited"'),
    ("wait in loop", 'for i = 1, 3 do wait() end return "looped"'),
    ("error", "error(\"boom\")"),
]


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


def run(source: str) -> str:
    cmd = [str(COMPILER), "-"] + (["--raw"] if RAW else [])
    proc = subprocess.run(cmd, input=source.encode(), capture_output=True)
    if proc.returncode != 0:
        return f"compilation failed: {proc.stderr.decode(errors='replace').strip()}"
    payload = proc.stdout
    sock = connect(time.time() + 30)
    if not sock:
        return "the agent is gone"
    try:
        sock.sendall(struct.pack("<I", len(payload)) + payload)
        header = sock.recv(4)
        if len(header) < 4:
            return "the agent closed the connection"
        (length,) = struct.unpack("<I", header)
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data.decode(errors="replace")
    except OSError as exc:
        return f"the connection broke: {exc}"


def main() -> int:
    subprocess.run(["flatpak", "kill", "org.vinegarhq.Sober"], capture_output=True)
    time.sleep(2)
    log = open("/tmp/opencode/sober_selftest.log", "wb")
    subprocess.Popen(["flatpak", "run", "org.vinegarhq.Sober"],
                     stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                     start_new_session=True)

    probe = connect(time.time() + 90)
    if not probe:
        print("the agent never showed up")
        return 1
    # the agent serves one chunk per connection, so the probe is closed again
    probe.close()
    time.sleep(1)
    print("connected to the agent\n")

    failed = 0
    for name, source in SNIPPETS:
        result = run(source)
        status = "ok " if not result.startswith("error:") else "FAIL"
        print(f"  {status} {name:16} {result}")
        if result.startswith("error:") and name != "error":
            failed += 1
        if "closed the connection" in result or "the agent is gone" in result:
            print("  the agent died, stopping")
            break
    print(f"\n{failed} of {len(SNIPPETS)} snippets failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
