#!/usr/bin/env python3
"""Wieen — host side injector for Sober (VinegarHQ Roblox runtime).

Talks to the agent that lives inside the Sober client process over a UNIX
socket, executes Luau inside the game's own VM and prints the results.

    wieen install              install the agent and preload it in the runtime
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
import urllib.error
import urllib.request
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


# ---------------------------------------------------------------- preload


def runtime_ref() -> str | None:
    """The runtime Sober runs on, as flatpak composes it: app/arch/branch."""
    try:
        out = subprocess.run(
            ["flatpak", "list", "--app", "--columns=application,runtime"],
            capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].strip() == APP_ID:
            return parts[1].strip()
    return None


def preload_file() -> Path | None:
    """The ld.so.preload of the runtime deploy Sober is using right now.

    A runtime update replaces the deploy directory wholesale, and the
    preload goes with it - which is why the agent silently stops loading
    after `flatpak update`.
    """
    ref = runtime_ref()
    if not ref:
        return None
    roots = [Path("/var/lib/flatpak/runtime"),
             Path.home() / ".local/share/flatpak/runtime"]
    for root in roots:
        active = root / ref / "active"
        if active.exists():
            return active.resolve() / "files" / "etc" / "ld.so.preload"
    return None


def preload_ok() -> bool | None:
    """True when the agent is registered, False when it is not, None when
    the runtime cannot be inspected (no flatpak, no read access)."""
    path = preload_file()
    if path is None:
        return None
    try:
        return path.read_text().strip() == str(agent_path())
    except FileNotFoundError:
        return False
    except OSError:
        return None


def preload_hint() -> str:
    path = preload_file()
    where = str(path) if path else "the flatpak runtime"
    return (f"the preload is not registered in the current runtime deploy:\n"
            f"  {where}\n"
            f"flatpak updates the runtime by replacing that directory, and the\n"
            f"preload is lost with it. register it again:\n"
            f"  sudo {REPO / 'tools' / 'install_preload.sh'}\n"
            f"or just run: wieen launch (it fixes it before starting Sober)")


# ---------------------------------------------------------------- protocol


BOOTSTRAP = """\
-- the client has no working loadstring: it refuses the call because the
-- thread has no context of a script.  This one hands the source to the
-- host, which compiles it, and the agent loads the result.
--
-- The local shadows the global one, so the scripts of the game keep
-- seeing the stub of the client and are not touched.
local loadstring = function(src)
    return coroutine.yield(src)
end
"""


# a loadstring source may be a link: it is downloaded here, because the
# client has no http client of its own
FETCH_LIMIT = 1024 * 1024
_fetch_cache: dict[str, bytes] = {}


def fetch_link(url: str) -> bytes:
    """Download the source of a loadstring from a link."""
    if url in _fetch_cache:
        return _fetch_cache[url]
    request = urllib.request.Request(url, headers={"User-Agent": "wieen"})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = response.read(FETCH_LIMIT + 1)
    if len(data) > FETCH_LIMIT:
        raise RuntimeError(f"the link is bigger than {FETCH_LIMIT} bytes")
    if not data.strip():
        raise RuntimeError("the link is empty")
    _fetch_cache[url] = data
    return data


def lua_quote(text: str) -> str:
    """A Lua short string literal for the message."""
    out = ['"']
    for ch in text:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ord(ch) < 32 or ord(ch) == 127:
            out.append("\\%d" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def lua_text_chunk(data: bytes) -> str:
    """A Lua source whose chunk returns the given bytes as a string."""
    level = 0
    while (b"]" + b"=" * level + b"]") in data:
        level += 1
    eq = "=" * level
    return "return [" + eq + "[\n" + data.decode("utf-8", "surrogateescape") + "]" + eq + "]"


class Agent:
    """Client for the agent's socket protocol: [u32 len][payload]."""

    def __init__(self, path: Path | None = None, timeout: float = 150.0):
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

    def compile(self, source: str, loadstring: bool = False) -> bytes:
        """Compile the snippet into Luau bytecode.

        The client only ships the Luau VM, not the compiler, so the
        bytecode is produced here and the agent loads it with the
        client's own luau_load.  A loadstring source is a function of its
        own: it is compiled raw, and when it does not fit into one chunk
        the compiler returns a dispatcher over the parts.
        """
        if not COMPILER.exists():
            raise FileNotFoundError(f"compiler not built: {COMPILER} (run: make compile)")
        argv = [str(COMPILER), "-"]
        if loadstring:
            argv.append("--loadstring")
        proc = subprocess.run(argv, input=source.encode("utf-8", "surrogateescape"),
                              capture_output=True)
        if proc.returncode != 0 or not proc.stdout:
            raise RuntimeError(proc.stderr.decode(errors="replace").strip()
                               or "compilation failed")
        return proc.stdout

    def error_chunk(self, message: str) -> bytes:
        """A chunk that raises the message where the script waits for it."""
        message = message[:160]
        try:
            return self.compile("error(" + lua_quote(message) + ")", loadstring=True)
        except Exception:
            return b""

    def exec(self, source: str) -> str:
        if self.sock is None and not self.connect():
            raise ConnectionError(f"no agent at {self.path}")
        assert self.sock is not None
        # the client has no working loadstring, so the script gets one that
        # asks this side to compile the source
        payload = self.compile(BOOTSTRAP + source)
        self.sock.sendall(struct.pack("<I", len(payload)) + payload)
        while True:
            (length,) = struct.unpack("<I", self._recv_exact(4))
            data = self._recv_exact(length)
            if data.startswith(b"\x00http:"):
                # game:HttpGet was rewritten: the host downloads the text
                # and sends back a chunk that returns it
                url = data[len(b"\x00http:"):].decode(errors="replace")
                try:
                    text = fetch_link(url)
                    code = self.compile(lua_text_chunk(text), loadstring=True)
                except Exception as error:
                    print(f"wieen: cannot get {url}: {error}", file=sys.stderr)
                    code = self.error_chunk(f"wieen: cannot get {url}")
            elif data.startswith(b"\x00fetch:"):
                # the loadstring was given a link: the source is downloaded
                # here, then compiled the same way as any other one
                url = data[len(b"\x00fetch:"):].decode(errors="replace")
                try:
                    source_text = fetch_link(url).decode(errors="replace")
                    code = self.compile(source_text, loadstring=True)
                except Exception as error:  # the script sees the error
                    print(f"wieen: cannot load {url}: {error}",
                          file=sys.stderr)
                    code = self.error_chunk(f"wieen: cannot load {url}")
            elif data.startswith(b"\x00compile:"):
                # the agent wants a chunk compiled; this one is the source
                # of a loadstring, so it becomes a function of its own
                source_text = data[len(b"\x00compile:"):].decode(errors="replace")
                try:
                    code = self.compile(source_text, loadstring=True)
                except Exception as error:  # the script sees the error
                    code = b""
            else:
                return data.decode(errors="replace")
            reply = b"\x00compiled:" + code
            self.sock.sendall(struct.pack("<I", len(reply)) + reply)


# ---------------------------------------------------------------- commands


def cmd_install(args: argparse.Namespace) -> int:
    """Install the agent and make the flatpak runtime preload it."""
    if not AGENT_BUILD.exists():
        print(f"agent not built: {AGENT_BUILD} (run: make agent)", file=sys.stderr)
        return 1

    target = agent_path()
    shutil.copy2(AGENT_BUILD, target)
    print(f"agent installed: {target}")

    script = REPO / "tools" / "install_preload.sh"
    if not script.exists():
        print(f"installer missing: {script}", file=sys.stderr)
        return 1
    if subprocess.call([str(script)]) != 0:
        print("could not install the preload", file=sys.stderr)
        return 1

    print(f"socket: {socket_path()}")
    print("start Sober with: wieen launch")
    return 0


def cmd_launch(args: argparse.Namespace) -> int:
    if not agent_path().exists():
        print("agent not installed, run: wieen install", file=sys.stderr)
        return 1
    if preload_ok() is False and not getattr(args, "no_preload_fix", False):
        print("the flatpak runtime forgot the preload (it was updated),"
              " registering it again", file=sys.stderr)
        if subprocess.call(["sudo", "bash", str(REPO / "tools" / "install_preload.sh")]) != 0:
            print("could not register the preload", file=sys.stderr)
            return 1
    cmd = ["flatpak", "run"]
    # Flags for the agent inside the sandbox go through the host
    # environment, so there is no second set of switches to remember:
    #   WIEEN_FAULTLOG=1 wieen launch
    for name, value in os.environ.items():
        if name.startswith("WIEEN_") and name not in ("WIEEN_SOCKET",):
            cmd.append(f"--env={name}={value}")
    cmd += [APP_ID]
    if args.url:
        cmd.append(args.url)
    print("launching:", " ".join(cmd))
    return subprocess.call(cmd)


def cmd_gui(args: argparse.Namespace) -> int:
    """Start the interface of the injector."""
    script = REPO / "src" / "gui" / "wieen_gui.py"
    if not script.exists():
        print(f"interface missing: {script}", file=sys.stderr)
        return 1
    return subprocess.call([sys.executable, str(script)])


def cmd_status(args: argparse.Namespace) -> int:
    a = Agent()
    if not a.connect():
        print(f"no agent listening on {a.path}")
        if preload_ok() is False:
            print(preload_hint())
            return 1
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
        if preload_ok() is False:
            print(preload_hint(), file=sys.stderr)
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

    sp = sub.add_parser("install", help="install the agent and preload it in the runtime")
    sp.set_defaults(func=cmd_install)

    sp = sub.add_parser("launch", help="start Sober with the agent preloaded")
    sp.add_argument("url", nargs="?", help="experience to open")
    sp.add_argument("--no-preload-fix", action="store_true",
                    help="start Sober without touching the runtime preload")
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

    sp = sub.add_parser("gui", help="the interface: install, launch, attach")
    sp.set_defaults(func=cmd_gui)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
