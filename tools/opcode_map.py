#!/usr/bin/env python3
"""Recover the client's Luau opcode permutation.

Why this is needed
------------------
The Roblox client ships Luau with a *shuffled* opcode numbering: its
dispatch table (RVA 0x6a301e0) has 95 live slots scattered over 0..254
while upstream Luau numbers its 95 opcodes 0..94.  Bytecode produced by an
upstream compiler therefore dispatches to the wrong handler, and an unused
slot jumps to address 0 - exactly the crash we observed in the game.

How the permutation is recovered
--------------------------------
Both interpreters are built from the same upstream source, so two things
survive a rebuild:

  * the *shape* of a handler body (the sequence of instructions), and
  * the *set of functions it calls*.

The first is used to align the two handler lists (Needleman-Wunsch over
instruction shapes).  The second is used to make the alignment exact: the
functions the upstream handler calls are matched with the functions the
client handler calls, and that correspondence is fed back into the score
until it stops changing.

Output is the table "upstream opcode -> client slot", plus the list of
pairs that stayed ambiguous.
"""
from __future__ import annotations

import difflib
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
CLIENT = REPO / "work/libs/libroblox.so"
REF = REPO / "work/luau-src/build-rel/x/lvmexecute.cpp.o"
FUNCS = REPO / "work/analysis/client_funcs.txt"

CLIENT_TABLE = 0x6A301E0
CLIENT_INTERP = (0x31FEF8A, 0x320596A)
REF_TABLE_OFF = 0x800

TEXT_START = 0x1AB0B80
TEXT_END = 0x694590D

# the Luau VM of the client, from the C API to the end of the interpreter
VM_AREA = (0x22E0000, 0x3210000)


# --------------------------------------------------------------------------
# reading the binaries
# --------------------------------------------------------------------------
def opcode_names() -> list[str]:
    text = (REPO / "work/luau-src/Common/include/Luau/Bytecode.h").read_text()
    body = re.search(r"enum LuauOpcode\s*\{(.*?)\n\};", text, re.S).group(1)
    return re.findall(r"\b(LOP_[A-Z0-9_]+)\s*,", body)


def client_rodata() -> tuple[int, int]:
    """the range of the client's .rodata section (file offsets)"""
    out = subprocess.run(["llvm-readelf", "-SW", str(CLIENT)],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 6 and parts[1] == ".rodata":
            off = int(parts[4], 16)
            return off, off + int(parts[5], 16)
    return 0, 0


def code_references(target: int) -> list[int]:
    """the code that loads the address of a data object"""
    data = CLIENT.read_bytes()
    buf = np.frombuffer(data[TEXT_START:TEXT_END], dtype=np.uint8)

    idx = np.nonzero(buf == 0x8D)[0]
    idx = idx[(idx >= 1) & (idx + 6 < len(buf))]
    idx = idx[((buf[idx - 1] == 0x48) | (buf[idx - 1] == 0x4C)) & ((buf[idx + 1] & 0xC7) == 0x05)]

    disp = (buf[idx + 2].astype(np.int64)
            | (buf[idx + 3].astype(np.int64) << 8)
            | (buf[idx + 4].astype(np.int64) << 16)
            | (buf[idx + 5].astype(np.int64) << 24))
    disp = np.where(disp >= 0x80000000, disp - 0x100000000, disp)
    tgt = TEXT_START + (idx - 1).astype(np.int64) + 7 + disp

    return sorted(TEXT_START + int(i) for i in idx[tgt == target])


def find_opcode_tables(live: set[int], expect: dict[int, int]):
    """the two tables of the client, the ones that match the handlers"""
    """the two tables the client uses for its opcodes.

    The client numbers its opcodes twice.  The bytecode it reads uses one
    numbering (the "wire" format), its interpreter another one, and while
    it loads a function it rewrites every opcode with a table.  Next to
    that table the client keeps a second one that maps its own opcode
    numbers back to the upstream ones.

    The two tables sit next to each other, so they are easy to recognise:
    the first one holds the slots of the client's dispatch table, the
    second one a permutation of the upstream opcode numbers.
    """
    start, end = client_rodata()
    if not end:
        return None

    arr = np.frombuffer(CLIENT.read_bytes()[start:end], dtype=np.uint8)
    n = len(arr)
    width = 256

    def marks(values: list[int], twice: bool) -> np.ndarray:
        """window starts that hold at least one (or two) of the values"""
        diff = np.zeros(n + width + 2, dtype=np.int32)
        for value in values:
            pos = np.nonzero(arr == value)[0]
            if len(pos) == 0:
                continue
            if twice:
                if len(pos) < 2:
                    continue
                lo = np.maximum(pos[1:] - width + 1, 0)
                hi = pos[:-1]
            else:
                lo = np.maximum(pos - width + 1, 0)
                hi = pos
            np.add.at(diff, lo, 1)
            np.add.at(diff, hi + 1, -1)
        return np.cumsum(diff)[:n]

    upstream = list(range(95))

    # windows that hold every upstream opcode exactly once
    have = np.ones(n, dtype=bool)
    twice = np.zeros(n, dtype=bool)
    for value in upstream:
        have &= marks([value], False) > 0
        twice |= marks([value], True) > 0
    permutation = have & ~twice

    # windows that hold every slot of the dispatch table exactly once
    have = np.ones(n, dtype=bool)
    twice = np.zeros(n, dtype=bool)
    for value in sorted(live):
        have &= marks([value], False) > 0
        twice |= marks([value], True) > 0
    slots = have & ~twice

    perm_pos = np.nonzero(permutation)[0].tolist()
    slot_pos = set(np.nonzero(slots)[0].tolist())

    for h in perm_pos:
        # the two tables sit next to each other
        for decoder_at in (h - width, h + width):
            if decoder_at not in slot_pos:
                continue
            if decoder_at < 0 or h + width > n:
                continue
            decoder = list(arr[decoder_at:decoder_at + width])
            upstream_of = list(arr[h:h + width])
            if sorted(v for v in decoder if v in live) != sorted(live):
                continue
            # the table has to name the opcode the handler belongs to
            if any(upstream_of[slot] != op for op, slot in expect.items()):
                continue
            return start + decoder_at, bytes(decoder), bytes(upstream_of)
    return None


def op_lengths() -> list[int]:
    """how many words each opcode occupies (1, or 2 for the ones with AUX)"""
    text = (REPO / "work/luau-src/Common/include/Luau/BytecodeUtils.h").read_text()
    body = re.search(r"inline int getOpLength\(LuauOpcode op\)(.*?)\n\}", text, re.S).group(1)
    lengths = [1] * 96
    names = opcode_names()
    # every case listed before the "return 2" of the switch takes two words
    head = body[:body.index("return 2;")]
    for name in re.findall(r"case (LOP_[A-Z0-9_]+):", head):
        for op, opname in enumerate(names):
            if opname == name:
                lengths[op] = 2
    return lengths


def relocations(path: Path, section: str | None = None) -> list[tuple[int, str, str]]:
    """[(offset, type, value)] of the relocation sections of an ELF file.

    `value` is the symbol name for external references and the addend
    (".text + 1234" or a plain number) for local ones.
    """
    out = subprocess.run(["llvm-readelf", "-rW", str(path)],
                         capture_output=True, text=True).stdout
    result = []
    current = None
    for line in out.splitlines():
        m = re.search(r"'\.rela\.(.+?)'", line)
        if m:
            current = m.group(1)
            continue
        if not current:
            continue
        if section and current != section:
            continue
        parts = line.split()
        if len(parts) < 3 or not re.fullmatch(r"[0-9a-f]{8,}", parts[0]):
            continue
        off = int(parts[0], 16)
        typ = parts[2]
        symbol = parts[4] if len(parts) > 4 else ""
        addend = ""
        if len(parts) > 6 and parts[5] in "+-":
            addend = parts[5] + parts[6]
        if "RELATIVE" in typ:
            # the addend is the value the slot will hold at load time
            addend = parts[3]
            symbol = ""
        result.append((off, typ, symbol, addend))
    return result


def ref_dispatch() -> dict[int, int]:
    """upstream opcode -> address of its handler label"""
    table: dict[int, int] = {}
    for off, typ, symbol, addend in relocations(REF, "data.rel.ro"):
        if not (REF_TABLE_OFF <= off < REF_TABLE_OFF + 256 * 8):
            continue
        if symbol != ".text" or not addend.startswith("+"):
            continue
        table[(off - REF_TABLE_OFF) // 8] = int(addend[1:], 16)
    return table


def client_dispatch() -> dict[int, int]:
    """client slot -> address of its handler label"""
    table: dict[int, int] = {}
    for off, typ, symbol, addend in relocations(CLIENT):
        if not (CLIENT_TABLE <= off < CLIENT_TABLE + 256 * 8):
            continue
        try:
            table[(off - CLIENT_TABLE) // 8] = int(addend, 16)
        except ValueError:
            continue
    return table


def disasm(path: Path, start: int, stop: int, elf: bool):
    """[(address, mnemonic, raw operands, normalised operands)]"""
    if elf:
        cmd = ["objdump", "-d", "-j", ".text", "-M", "intel", str(path)]
    else:
        cmd = ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel",
               f"--start-address={start}", f"--stop-address={stop}", str(path)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    res = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*(\S+)\s*(.*)", line)
        if not m:
            continue
        raw = m.group(3).split("#")[0].strip()
        norm = re.sub(r"0x[0-9a-f]+", "H", raw)
        norm = re.sub(r"\b[0-9a-f]{5,}\b", "H", norm)
        res.append((int(m.group(1), 16), m.group(2), raw, norm))
    return res


def handler_bodies(insns, starts: list[int]):
    """handler body: the instructions up to the dispatch tail.

    The tail of every handler is the indirect jump back into the dispatch
    loop, so the body ends there.
    """
    order = sorted(starts)
    result = {}
    for i, start in enumerate(order):
        stop = order[i + 1] if i + 1 < len(order) else (insns[-1][0] + 16 if insns else start)
        body = []
        for insn in insns:
            if insn[0] < start:
                continue
            if insn[0] >= stop:
                break
            body.append(insn)
            mnem, args = insn[1], insn[3]
            if mnem == "jmp" and ("*" in args or "PTR" in args):
                break
            if mnem == "ret":
                break
        result[start] = body
    return result


def shape(body) -> list[str]:
    """mnemonic plus the kind of its operands, ignoring register names"""
    res = []
    for _, mnem, _, args in body:
        if "[" in args:
            kind = "m"
        elif args:
            kind = "i"
        else:
            kind = ""
        res.append(mnem + kind)
    return res


def similarity(a: list[str], b: list[str]) -> float:
    if not a or not b:
        return 0.0
    r = difflib.SequenceMatcher(None, a, b).ratio()
    if a == b:
        r = min(1.0, r + 0.15)
    return r


# --------------------------------------------------------------------------
# call profiles
# --------------------------------------------------------------------------
def ref_call_names() -> dict[int, str]:
    """address of a call instruction -> name of the function it calls"""
    names: dict[int, str] = {}
    for off, typ, symbol, addend in relocations(REF, "text"):
        if typ not in ("R_X86_64_PLT32", "R_X86_64_PC32", "R_X86_64_GOTPCREL",
                       "R_X86_64_GOTPCRELX", "R_X86_64_REX_GOTPCRELX"):
            continue
        if not symbol or symbol.startswith("."):
            continue
        # the relocation sits on the displacement of the call, one byte
        # behind the instruction itself
        names[off - 1] = symbol
    return names


def client_functions() -> list[tuple[int, int]]:
    funcs = []
    for line in FUNCS.read_text().splitlines():
        a, b = line.split()
        funcs.append((int(a, 16), int(b, 16)))
    funcs.sort()
    return funcs


class ClientIndex:
    """maps an address in the client to the function that contains it"""

    def __init__(self, funcs: list[tuple[int, int]]):
        self.funcs = funcs
        self.starts = [f[0] for f in funcs]

    def owner(self, addr: int) -> int:
        import bisect
        i = bisect.bisect_right(self.starts, addr) - 1
        if i < 0:
            return addr
        lo, hi = self.funcs[i]
        return lo if addr < hi else addr


def client_plt_names() -> dict[int, str]:
    """PLT stub address -> dynamic symbol it calls"""
    out = subprocess.run(["llvm-readelf", "-rW", str(CLIENT)],
                         capture_output=True, text=True).stdout
    plt = {}
    current = None
    for line in out.splitlines():
        m = re.search(r"'\.rela\.(.+?)'", line)
        if m:
            current = m.group(1)
            continue
        if current != "plt":
            continue
        parts = line.split()
        if len(parts) < 5 or not re.fullmatch(r"[0-9a-f]{8,}", parts[0]):
            continue
        if "JUMP_SLOT" not in line:
            continue
        plt[int(parts[0], 16)] = parts[4]
    return plt


def call_targets(body, names: dict[int, str] | None = None,
                 index: ClientIndex | None = None,
                 plt: dict[int, str] | None = None) -> list[str]:
    """the functions a handler body calls, in order"""
    out = []
    for addr, mnem, raw, _ in body:
        if mnem != "call":
            continue
        if names is not None:
            name = names.get(addr)
            if name:
                out.append(name)
            continue
        m = re.match(r"(?:0x)?([0-9a-f]+)\s*<", raw) or re.match(r"0x([0-9a-f]+)$", raw)
        if not m:
            continue
        target = int(m.group(1), 16)
        if plt and target in plt:
            out.append(plt[target])
        elif index is not None:
            out.append("f%x" % index.owner(target))
        else:
            out.append("t%x" % target)
    return out


# --------------------------------------------------------------------------
# alignment
# --------------------------------------------------------------------------
def align(sim: list[list[float]], gap: float = -0.25):
    """global alignment of two handler sequences (Needleman-Wunsch).

    `sim[i][j]` is the score of pairing the i-th handler of the first
    sequence with the j-th handler of the second one.  The alignment keeps
    the order of the handlers, which both interpreters share, and only
    inserts gaps for the few handlers that moved.
    """
    n = len(sim)
    m = len(sim[0]) if sim else 0
    score = [[0.0] * (m + 1) for _ in range(n + 1)]
    back = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        score[i][0] = score[i - 1][0] + gap
        back[i][0] = 1
    for j in range(1, m + 1):
        score[0][j] = score[0][j - 1] + gap
        back[0][j] = 2
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            diag = score[i - 1][j - 1] + sim[i - 1][j - 1]
            up = score[i - 1][j] + gap
            left = score[i][j - 1] + gap
            best = max(diag, up, left)
            score[i][j] = best
            back[i][j] = 0 if best == diag else (1 if best == up else 2)
    pairs = []
    i, j = n, m
    while i > 0 or j > 0:
        b = back[i][j]
        if b == 0 and i > 0 and j > 0:
            pairs.append((i - 1, j - 1, sim[i - 1][j - 1]))
            i -= 1
            j -= 1
        elif b == 1 and i > 0:
            i -= 1
        else:
            j -= 1
    pairs.reverse()
    return pairs


def main() -> int:
    names = opcode_names()

    rtab = ref_dispatch()
    ctab = client_dispatch()
    print(f"upstream handlers {len(rtab)}, client handlers {len(ctab)}")

    rins = disasm(REF, 0, 0, elf=True)
    rbodies = handler_bodies(rins, list(rtab.values()))
    cins = disasm(CLIENT, CLIENT_INTERP[0], CLIENT_INTERP[1], elf=False)
    cbodies = handler_bodies(cins, list(ctab.values()))

    ref_names = ref_call_names()
    index = ClientIndex(client_functions())
    plt = client_plt_names()

    # both handler lists in the order the code lays them out
    up_order = sorted(rtab.items(), key=lambda kv: kv[1])
    cl_order = sorted(ctab.items(), key=lambda kv: kv[1])
    up_pos = {op: i for i, (op, _) in enumerate(up_order)}
    cl_pos = {slot: j for j, (slot, _) in enumerate(cl_order)}

    up_shape = [shape(rbodies[addr]) for _, addr in up_order]
    cl_shape = [shape(cbodies[addr]) for _, addr in cl_order]
    up_calls = [call_targets(rbodies[addr], names=ref_names) for _, addr in up_order]
    cl_calls = [call_targets(cbodies[addr], index=index, plt=plt) for _, addr in cl_order]

    shape_sim = [[similarity(a, b) for b in cl_shape] for a in up_shape]

    ident: dict[str, str] = {}

    def callee_sim(i: int, j: int) -> float:
        u, c = up_calls[i], cl_calls[j]
        if not u or not c or not ident:
            return 0.0
        hit = sum(1 for x, y in zip(u, c) if ident.get(x) == y)
        return hit / max(len(u), len(c))

    def score_matrix():
        return [[0.55 * shape_sim[i][j] + 0.45 * callee_sim(i, j)
                 for j in range(len(cl_order))] for i in range(len(up_order))]

    assign: dict[int, int] = {}
    for round_no in range(8):
        pairs = align(score_matrix())
        new_assign = {up_order[i][0]: cl_order[j][0] for i, j, _ in pairs}

        # the few handlers that did not find a partner are the ones the
        # compiler moved to a cold block (NOP and BREAK); if exactly one of
        # each is left over they belong together
        used_up = set(new_assign)
        used_cl = {cl_order[j][0] for _, j, _ in pairs}
        left_up = [op for op, _ in up_order if op not in used_up]
        left_cl = [slot for slot, _ in cl_order if slot not in used_cl]
        if len(left_up) == 1 and len(left_cl) == 1:
            new_assign[left_up[0]] = left_cl[0]
            print(f"   unmatched pair taken from the leftovers: "
                  f"{names[left_up[0]]} -> slot {left_cl[0]}")

        votes: dict[str, Counter] = defaultdict(Counter)
        for op, slot in new_assign.items():
            i, j = up_pos[op], cl_pos[slot]
            for u, c in zip(up_calls[i], cl_calls[j]):
                votes[u][c] += 1
        new_ident = {u: c.most_common(1)[0][0] for u, c in votes.items() if c}

        changed = [(op, assign.get(op), slot) for op, slot in sorted(new_assign.items())
                   if assign.get(op) != slot]
        print(f"round {round_no}: {len(new_assign)} pairs, "
              f"{len(new_ident)} function correspondences, {len(changed)} changed")
        for op, old, new in changed:
            print(f"   {op:3d} {names[op]:22} {old} -> {new}")

        assign, ident = new_assign, new_ident
        if not changed and round_no:
            break

    sim = score_matrix()

    print("\nupstream opcode -> client slot")
    for op in sorted(assign):
        slot = assign[op]
        s = sim[up_pos[op]][cl_pos[slot]]
        flag = "   <-- weak" if s < 0.55 else ""
        print(f"  {op:3d} {names[op]:22} -> {slot:3d}  score={s:.3f}{flag}")

    print(f"\npaired {len(assign)} of {len(rtab)} upstream opcodes")
    weak = [(op, assign[op], sim[up_pos[op]][cl_pos[assign[op]]]) for op in sorted(assign)
            if sim[up_pos[op]][cl_pos[assign[op]]] < 0.55]
    print(f"weak pairs: {len(weak)}")
    for op, slot, s in weak:
        print(f"   {op:3d} {names[op]:22} -> {slot:3d} score={s:.3f}")

    # ---- the wire format the client expects -----------------------------
    #
    # The client numbers its opcodes twice: the bytecode that is handed to
    # it uses one numbering (the "wire" format) and its interpreter uses
    # another one, the scattered slots of the dispatch table.  While the
    # client reads a function it rewrites every opcode with a table, so a
    # chunk has to be written in the wire format.
    found = find_opcode_tables(set(client_dispatch().keys()), assign)
    if found is None:
        print("could not find the opcode tables of the client", file=sys.stderr)
        return 1
    decoder_at, decoder, upstream_of = found
    print(f"\nopcode tables of the client at {decoder_at:#x}")

    # the table of the client says which upstream opcode each of its own
    # opcodes is; it has to agree with the handlers we matched
    agree = all(upstream_of[slot] == op for op, slot in assign.items())
    print(f"the opcode table of the client agrees with the handlers: {agree}")
    if not agree:
        print("could not find the opcode tables of the client", file=sys.stderr)
        return 1

    wire_of: dict[int, int] = {}
    for op, slot in assign.items():
        for w, internal in enumerate(decoder):
            if internal == slot:
                wire_of[op] = w
                break

    missing = [op for op in assign if op not in wire_of]
    if missing:
        print(f"no wire opcode for: {missing}", file=sys.stderr)
        return 1

    # ---- write the table ------------------------------------------------
    out = REPO / "tools" / "opcode_map.txt"
    with out.open("w") as fh:
        fh.write("# upstream Luau opcode -> client slot -> wire opcode\n")
        fh.write("# client sha256 8afce3e695d08fe830d7857752c459de9a06c97390c7365a6660827e5d072e78\n")
        fh.write(f"# client opcode table at {decoder_at:#x}\n")
        for op in sorted(assign):
            fh.write(f"{op:3d} {names[op]:22} {assign[op]:3d} {wire_of[op]:3d}\n")
    print(f"wrote {out}")

    # a header the compiler can include
    lengths = op_lengths()
    header = REPO / "tools" / "opcode_map.h"
    with header.open("w") as fh:
        fh.write("/*\n")
        fh.write(" * The client numbers its opcodes differently from upstream.\n")
        fh.write(" *\n")
        fh.write(" * The bytecode it reads uses the wire numbering, while its\n")
        fh.write(" * interpreter uses the scattered slots of its dispatch table;\n")
        fh.write(" * the client rewrites every opcode while it loads a function.\n")
        fh.write(" * Bytecode compiled by an upstream compiler therefore has to\n")
        fh.write(" * be translated before the client can run it.\n")
        fh.write(" *\n")
        fh.write(" * Generated by tools/opcode_map.py - do not edit.\n")
        fh.write(" * Client sha256 8afce3e695d08fe830d7857752c459de9a06c97390c7365a6660827e5d072e78\n")
        fh.write(" */\n")
        fh.write("#ifndef WIEEN_OPCODE_MAP_H\n#define WIEEN_OPCODE_MAP_H\n\n")
        fh.write("#define WIEEN_OPCODE_COUNT %d\n\n" % len(assign))
        fh.write("/* upstream opcode -> wire opcode */\n")
        fh.write("static const unsigned char kWireOpcode[WIEEN_OPCODE_COUNT] = {\n")
        for op in sorted(assign):
            fh.write("    %3d, /* %s */\n" % (wire_of[op], names[op]))
        fh.write("};\n\n")
        fh.write("/* upstream opcode -> slot of the client's dispatch table */\n")
        fh.write("static const unsigned char kClientOpcode[WIEEN_OPCODE_COUNT] = {\n")
        for op in sorted(assign):
            fh.write("    %3d, /* %s */\n" % (assign[op], names[op]))
        fh.write("};\n\n")
        fh.write("/* words per instruction: 2 when the opcode is followed by an AUX word */\n")
        fh.write("static const unsigned char kOpWords[WIEEN_OPCODE_COUNT] = {\n")
        for op in sorted(assign):
            fh.write("    %d, /* %s */\n" % (lengths[op], names[op]))
        fh.write("};\n\n")
        fh.write("#endif\n")
    print(f"wrote {header}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
