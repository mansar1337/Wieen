"""Wieen injector — places the agent inside a running Sober client.

The Sober runtime traces the Roblox client and turns system calls made from
foreign code into a fatal error, so the agent is never loaded through
dlopen.  Instead the host copies the agent's flat blob into a padding hole
of the client image, redirects the Luau interpreter's entry at it and
talks to it through a mailbox that lives in the client's own memory.

    client image  = the APK's libroblox.so, mapped from an anonymous memfd
    blob hole     = the zero filled gap between .rodata and .text
    detour target = the Luau interpreter entry
    mailbox       = command/result area inside the client image
"""

from __future__ import annotations

import json
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

# offsets inside the Roblox client image (tools/scan_symbols.py regenerates them)
SYMBOL_SETS = {
    "live": Path(__file__).resolve().parents[2] / "work/analysis/symbols_live.json",
    "alt": Path(__file__).resolve().parents[2] / "work/analysis/symbols_alt.json",
}
SYMS = json.loads(SYMBOL_SETS["live"].read_text())

OFF_LUAU_COMPILE = 0x25EC5C0
OFF_LUAU_LOAD = 0x23D4B1A
OFF_LUAU_EXECUTE = 0x248FCB6      # luau_execute()
OFF_LUAU_INTERP = 0x24CF6F2       # luau_execute<false>()
OFF_LUA_PCALL = 0x246D070
OFF_LUA_GETFIELD = 0x2404498
OFF_LUA_GETTOP = 0x2323926
OFF_LUA_SETTOP = 0x2325A16
OFF_LUA_TOLSTRING = 0x238896A
OFF_LUA_TYPE = 0x233DA24
OFF_LUA_MAINTHREAD = 0x2306224

# luau_load's prologue, used to recognise the client image
SIG_LOAD = bytes.fromhex("554889e54157415641554154534883ec")

# where the blob, the trampoline and the mailbox go inside the image
BLOB_OFF = 0xBA211A
TRAMPOLINE_OFF = 0xBF0000
MAILBOX_OFF = 0xC00000
MAILBOX_SIZE = 128 * 1024

# the interpreter's prologue we displace (position independent)
HOOK_COPY_LEN = 12


def log(msg: str) -> None:
    print(f"[wieen] {msg}", file=sys.stderr)


# ---------------------------------------------------------------- client


def read_maps(pid: int) -> list[tuple[int, int, str, int, str]]:
    out = []
    for line in open(f"/proc/{pid}/maps"):
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        off = int(parts[2], 16)
        out.append((lo, hi, parts[1], off, parts[5].strip() if len(parts) > 5 else ""))
    return out


def read_mem(pid: int, addr: int, size: int) -> bytes:
    with open(f"/proc/{pid}/mem", "rb", 0) as f:
        f.seek(addr)
        return f.read(size)


def write_mem(pid: int, addr: int, data: bytes) -> None:
    fd = os.open(f"/proc/{pid}/mem", os.O_RDWR)
    try:
        os.pwrite(fd, data, addr)
    finally:
        os.close(fd)


def load_base(pid: int, suffix: str) -> int:
    """Load address of a mapped file: min(start - file_offset) over its maps."""
    base = None
    for lo, hi, perm, off, path in read_maps(pid):
        if path.endswith(suffix):
            cand = lo - off
            base = cand if base is None else min(base, cand)
    if base is None:
        raise RuntimeError(f"{suffix} not found")
    return base


def libc_symbol(pid: int, name: str) -> int:
    """Address of a libc symbol inside the client process."""
    for lo, hi, perm, off, path in read_maps(pid):
        if path.endswith("libc.so.6"):
            out = subprocess.run(["readelf", "--dyn-syms", "-W", f"/proc/{pid}/root{path}"],
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 8 and parts[7].split("@")[0] == name:
                    return load_base(pid, "libc.so.6") + int(parts[1], 16)
            raise RuntimeError(f"symbol {name} not found")
    raise RuntimeError("libc not found")


def runtime_symbol(pid: int, lib_suffix: str, symbol: str) -> int:
    """Runtime address of an exported symbol in a library of the process."""
    base = load_base(pid, lib_suffix)
    out = subprocess.run(["nm", "-D", lib_suffix], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == symbol:
            return base + int(parts[0], 16)
    raise RuntimeError(f"symbol {symbol} not found in {lib_suffix}")


def find_client(pid: int | None = None) -> tuple[int, int]:
    """Locate the Sober client process and the base of its image."""
    if pid is not None:
        maps = read_maps(pid)
        for lo, hi, perm, off, path in maps:
            if "x" in perm and hi - lo > 0x4000000:
                base = lo - off
                try:
                    if read_mem(pid, base + SYMS["luau_load"], len(SIG_LOAD)) == SIG_LOAD:
                        return pid, base
                except OSError:
                    continue
        raise RuntimeError("the given process does not hold the client image")
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            maps = read_maps(pid)
        except OSError:
            continue
        for lo, hi, perm, off, path in maps:
            if "x" not in perm or hi - lo < 0x4000000:
                continue
            base = lo - off
            try:
                sig = read_mem(pid, base + SYMS["luau_load"], len(SIG_LOAD))
            except OSError:
                continue
            if sig == SIG_LOAD:
                return pid, base
    raise RuntimeError("no Sober client found (is a game running?)")


# ---------------------------------------------------------------- blob


class AgentBlob:
    """The agent's flat image plus the metadata the host needs."""

    def __init__(self, path: Path):
        self.blob = bytearray(path.read_bytes())
        self.meta = json.loads(path.with_suffix(path.suffix + ".json").read_text())
        self.sym = self.meta["symbols"]

    def offset(self, name: str) -> int:
        return self.sym[name]

    def patch_ptr(self, name: str, value: int) -> None:
        off = self.offset(name)
        struct.pack_into("<Q", self.blob, off, value)

    def patch_cfg(self, values: dict[str, int]) -> None:
        base = self.offset("wieen_cfg")
        # struct wieen_cfg { void* image_base, lua_compile, lua_load, lua_pcall,
        #                    lua_getfield, lua_gettop, lua_settop, lua_tolstring,
        #                    lua_type, lua_mainthread, trampoline, mailbox; }
        for i, (name, value) in enumerate(values.items()):
            struct.pack_into("<Q", self.blob, base + 8 * i, value)


# ---------------------------------------------------------------- inject


TARGETS = {
    "interpreter": OFF_LUAU_INTERP,
    "luau_execute": OFF_LUAU_EXECUTE,
    "lua_pcall": OFF_LUA_PCALL,
    "lua_getfield": OFF_LUA_GETFIELD,
    "lua_gettop": OFF_LUA_GETTOP,
    "lua_settop": OFF_LUA_SETTOP,
    "lua_tolstring": OFF_LUA_TOLSTRING,
    "lua_type": OFF_LUA_TYPE,
    "luau_load": OFF_LUAU_LOAD,
}


def inject(agent_path: Path, blob_path: Path, target: str = "interpreter", symset: str = "live",
           pid: int | None = None) -> dict:
    global SYMS
    SYMS = json.loads(SYMBOL_SETS[symset].read_text())
    if target not in TARGETS and not target.startswith("libc:"):
        raise RuntimeError(f"unknown target {target}")
    pid, base = find_client(pid)
    log(f"client pid {pid}, image base 0x{base:x}")

    agent = AgentBlob(blob_path)

    # sanity: the interpreter's prologue has to look like Luau's
    if target.startswith("libc:"):
        interp = libc_symbol(pid, target[5:])
    else:
        interp = base + SYMS[target]
    prologue = read_mem(pid, interp, HOOK_COPY_LEN)
    log(f"target {target} at 0x{interp:x}, prologue {prologue.hex(' ')}")

    blob_addr = base + BLOB_OFF
    tramp_addr = base + TRAMPOLINE_OFF
    mbox_addr = base + MAILBOX_OFF

    # the agent needs to know where everything lives
    agent.patch_cfg({
        "image_base": base,
        "lua_compile": base + SYMS["luau_compile"],
        "lua_load": base + SYMS["luau_load"],
        "lua_pcall": base + SYMS["lua_pcall"],
        "lua_getfield": base + SYMS["lua_getfield"],
        "lua_gettop": base + SYMS["lua_gettop"],
        "lua_settop": base + SYMS["lua_settop"],
        "lua_tolstring": base + SYMS["lua_tolstring"],
        "lua_type": base + SYMS["lua_type"],
        "lua_mainthread": base + SYMS["lua_mainthread"],
        "mailbox": mbox_addr,
    })
    # the trampoline re-runs the prologue we displace and then continues
    # in the original function
    trampoline = bytearray(prologue[:HOOK_COPY_LEN])
    trampoline += b"\x48\xb8" + struct.pack("<Q", interp + HOOK_COPY_LEN)
    trampoline += b"\xff\xe0"

    agent.patch_ptr("wieen_original_fn", tramp_addr)
    agent.patch_ptr("wieen_mbox_ptr", mbox_addr)

    # everything lands in the client's own memory
    write_mem(pid, blob_addr, bytes(agent.blob))
    write_mem(pid, tramp_addr, bytes(trampoline))
    back = read_mem(pid, blob_addr, len(agent.blob))
    if back != bytes(agent.blob):
        raise RuntimeError("the agent blob did not land in the client image")

    # the mailbox starts out idle
    write_mem(pid, mbox_addr, b"\0" * 32)

    # point the interpreter at the agent
    hook = blob_addr + agent.offset("wieen_hook_stub")
    detour = b"\x48\xb8" + struct.pack("<Q", hook) + b"\xff\xe0"
    write_mem(pid, interp, detour)
    log(f"agent at 0x{blob_addr:x}, hook at 0x{hook:x}")
    log(f"mailbox at 0x{mbox_addr:x}, interpreter detoured at 0x{interp:x}")

    return {"pid": pid, "base": base, "blob": blob_addr, "mailbox": mbox_addr}


# ---------------------------------------------------------------- mailbox


class Mailbox:
    """Command/result channel inside the client's memory."""

    def __init__(self, pid: int, addr: int):
        self.pid = pid
        self.addr = addr
        self.seq = 0

    def _read(self, off: int, size: int) -> bytes:
        return read_mem(self.pid, self.addr + off, size)

    def _write(self, off: int, data: bytes) -> None:
        write_mem(self.pid, self.addr + off, data)

    def run(self, source: str, timeout: float = 15.0) -> str:
        payload = source.encode()
        if len(payload) > 64 * 1024:
            raise ValueError("command too long")
        self.seq += 1
        self._write(16, struct.pack("<Q", self.seq))          # seq
        self._write(24, payload + b"\0" * (64 * 1024 - len(payload)))
        self._write(0, struct.pack("<Q", len(payload)))       # cmd_len
        self._write(8, struct.pack("<Q", 0))                 # status

        deadline = time.time() + timeout
        while time.time() < deadline:
            status, _, rlen, seq = struct.unpack("<QQQQ", self._read(0, 32))
            if status == 1 and seq == self.seq:
                self._write(8, struct.pack("<Q", 0))
                return self._read(32, min(rlen, 64 * 1024)).decode(errors="replace")
            time.sleep(0.02)
        raise TimeoutError("the agent did not answer in time")


def main() -> int:
    repo = Path(__file__).resolve().parents[2]
    blob = repo / "build" / "wieen_agent.bin"
    if not blob.exists():
        log(f"agent blob missing: {blob} (run: make blob)")
        return 1
    target = "interpreter"
    if "--target" in sys.argv:
        target = sys.argv[sys.argv.index("--target") + 1]
    symset = "live"
    if "--syms" in sys.argv:
        symset = sys.argv[sys.argv.index("--syms") + 1]
    pid = int(sys.argv[sys.argv.index("--pid") + 1]) if "--pid" in sys.argv else None
    try:
        info = inject(repo / "build" / "wieen_agent.so", blob, target, symset, pid)
    except Exception as exc:  # noqa: BLE001
        log(f"injection failed: {exc}")
        return 1
    info["target"] = target
    print(json.dumps(info))
    return 0


if __name__ == "__main__":
    sys.exit(main())
