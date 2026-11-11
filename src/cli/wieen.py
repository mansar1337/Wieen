#!/usr/bin/env python3
"""Wieen — host side injector for Sober (VinegarHQ Roblox runtime).

Talks to the agent that lives inside the Sober client process over a UNIX
socket, executes Luau inside the game's own VM and prints the results.

    wieen install              install the agent + flatpak override
    wieen launch [url]         start Sober with the agent preloaded
    wieen status               check whether the agent is reachable
    wieen exec "return 1+1"    run a snippet
    wieen run script.lua       run a file
    wieen repl                 interactive session
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

APP_ID = "org.vinegarhq.Sober"
REPO = Path(__file__).resolve().parents[2]
AGENT_BUILD = REPO / "build" / "wieen_agent.so"
COMPILER = REPO / "build" / "wieen-compile"


def app_dir() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "flatpak" / APP_ID


def data_dir() -> Path:
    return Path.home() / ".var" / "app" / APP_ID / "data"


def wieen_dir() -> Path:
    d = data_dir() / "wieen"
    d.mkdir(parents=True, exist_ok=True)
    return d


def socket_path() -> Path:
    env = os.environ.get("WIEEN_SOCKET")
    return Path(env) if env else wieen_dir() / "wieen.sock"


def agent_path() -> Path:
    return wieen_dir() / "wieen_agent.so"


# ---------------------------------------------------------------- protocol


class Agent:
    """Client for the agent's socket protocol: [u32 len][payload]."""

    def __init__(self, path: Path | None = None, timeout: float = 10.0):
        self.path = path or socket_path()
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def connect(self) -> bool:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(str(self.path))
            self.sock = s
            return True
        except OSError:
            return False

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def _recv_exact(self, n: int) -> bytes:
        assert self.sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("agent closed the connection")
            buf += chunk
        return buf

    def compile(self, source: str) -> bytes:
        """Compile the snippet into Luau bytecode.

        The client only ships the Luau VM, not the compiler, so the
        bytecode is produced here and the agent loads it with the
        client's own luau_load.
        """
        if not COMPILER.exists():
            raise FileNotFoundError(f"compiler not built: {COMPILER} (run: make compile)")
        proc = subprocess.run([str(COMPILER), "-"], input=source.encode(),
                              capture_output=True)
        if proc.returncode != 0 or not proc.stdout:
            raise RuntimeError(proc.stderr.decode(errors="replace").strip()
                               or "compilation failed")
        return proc.stdout

    def exec(self, source: str) -> str:
        if self.sock is None and not self.connect():
            raise ConnectionError(f"no agent at {self.path}")
        assert self.sock is not None
        payload = self.compile(source)
        self.sock.sendall(struct.pack("<I", len(payload)) + payload)
        (length,) = struct.unpack("<I", self._recv_exact(4))
        return self._recv_exact(length).decode(errors="replace")


# ---------------------------------------------------------------- commands


def sober_install_dir() -> Path:
    out = subprocess.run(["flatpak", "info", "--show-location", APP_ID],
                         capture_output=True, text=True, check=True).stdout.strip()
    return Path(out) / "files" / "bin"


def cmd_patch(args: argparse.Namespace) -> int:
    """Replace Sober's libbadcpu.so with the Wieen shim."""
    bindir = sober_install_dir()
    target = bindir / "libbadcpu.so"
    original = bindir / "libbadcpu_orig.so"
    shim = REPO / "build" / "libbadcpu.so"
    if not shim.exists():
        print(f"shim not built: {shim} (run: make shim)", file=sys.stderr)
        return 1
    if not target.exists():
        print(f"unexpected layout, {target} missing", file=sys.stderr)
        return 1

    if not original.exists():
        shutil.copy2(target, original)
        print(f"original kept as {original}")
    shutil.copy2(shim, target)
    print(f"shim installed: {target}")
    print("undo with: wieen unpatch")
    return 0


def cmd_unpatch(args: argparse.Namespace) -> int:
    bindir = sober_install_dir()
    target = bindir / "libbadcpu.so"
    original = bindir / "libbadcpu_orig.so"
    if original.exists():
        shutil.copy2(original, target)
        print(f"restored {target}")
    else:
        print("no backup found, nothing to restore", file=sys.stderr)
        return 1
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    if not AGENT_BUILD.exists():
        print(f"agent not built: {AGENT_BUILD} (run: make agent)", file=sys.stderr)
        return 1
    target = agent_path()
    shutil.copy2(AGENT_BUILD, target)
    print(f"agent installed: {target}")

    sock = socket_path()
    cmd = [
        "flatpak", "override", "--user",
        f"--env=WIEEN_SOCKET={sock}",
        f"--env=WIEEN_AGENT={target}",
        APP_ID,
    ]
    subprocess.run(cmd, check=True)
    print("flatpak override set: WIEEN_SOCKET + WIEEN_AGENT")
    print("patch Sober:        wieen patch")
    print("start Sober with:   wieen launch")
    return 0


def cmd_launch(args: argparse.Namespace) -> int:
    if not agent_path().exists():
        print("agent not installed, run: wieen install", file=sys.stderr)
        return 1
    bindir = sober_install_dir()
    if not (bindir / "libbadcpu_orig.so").exists():
        print("Sober is not patched yet, run: wieen patch", file=sys.stderr)
        return 1
    cmd = ["flatpak", "run", APP_ID]
    if args.url:
        cmd.append(args.url)
    print("launching:", " ".join(cmd))
    return subprocess.call(cmd)


def cmd_status(args: argparse.Namespace) -> int:
    a = Agent()
    if not a.connect():
        print(f"no agent listening on {a.path}")
        print("hint: wieen install && wieen launch")
        return 1
    try:
        out = a.exec("return typeof(game)")
    except (OSError, ConnectionError) as e:
        print(f"agent unreachable: {e}")
        return 1
    finally:
        a.close()
    print(f"agent: {a.path}")
    print(f"typeof(game) = {out}")
    return 0


def cmd_exec(args: argparse.Namespace) -> int:
    a = Agent()
    if not a.connect():
        print(f"no agent listening on {a.path}", file=sys.stderr)
        return 1
    try:
        print(a.exec(args.source))
    except (OSError, ConnectionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        a.close()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    source = Path(args.file).read_text()
    return cmd_exec(argparse.Namespace(source=source))


def cmd_repl(args: argparse.Namespace) -> int:
    a = Agent()
    if not a.connect():
        print(f"no agent listening on {a.path}", file=sys.stderr)
        return 1
    print(f"wieen repl — {a.path}")
    print("multi-line input: end with a blank line, \\! to quit")
    buffer: list[str] = []
    try:
        while True:
            prompt = "... " if buffer else "wieen> "
            try:
                line = input(prompt)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not buffer and line.strip() in ("\\!", "quit", "exit"):
                break
            buffer.append(line)
            if line.strip() == "":
                source = "\n".join(buffer)
                buffer.clear()
                if not source.strip():
                    continue
                try:
                    print(a.exec(source))
                except (OSError, ConnectionError) as e:
                    print(f"error: {e}")
    finally:
        a.close()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="wieen", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("install", help="install the agent and set the flatpak override")
    sp.set_defaults(func=cmd_install)

    sp = sub.add_parser("patch", help="patch Sober so it loads the agent")
    sp.set_defaults(func=cmd_patch)

    sp = sub.add_parser("unpatch", help="restore Sober's original libbadcpu.so")
    sp.set_defaults(func=cmd_unpatch)

    sp = sub.add_parser("launch", help="start Sober with the agent preloaded")
    sp.add_argument("url", nargs="?", help="experience to open")
    sp.set_defaults(func=cmd_launch)

    sp = sub.add_parser("status", help="check whether the agent is reachable")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("exec", help="run a Luau snippet")
    sp.add_argument("source")
    sp.set_defaults(func=cmd_exec)

    sp = sub.add_parser("run", help="run a Luau file")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("repl", help="interactive session")
    sp.set_defaults(func=cmd_repl)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
