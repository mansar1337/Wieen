#!/usr/bin/env python3
"""Assemble the Wieen bootstrap stub into a single blob.

The blob is written verbatim into a padding hole of the Roblox client
image.  Layout:

    +0x00            code (wieen_boot)
    +DATA_OFFSET     32 byte data block the injector fills in
    +PATH_OFFSET     NUL terminated path of the agent

Usage:
    mkstub.py <object file> <output blob>
"""
import subprocess
import sys

obj, out = sys.argv[1], sys.argv[2]

import tempfile
with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
    tmp_path = tmp.name
subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", obj, tmp_path], check=True)
text = open(tmp_path, "rb").read()

# symbol offsets inside the blob
syms = {}
for line in subprocess.run(["nm", obj], capture_output=True, text=True).stdout.splitlines():
    parts = line.split()
    if len(parts) == 3:
        syms[parts[2]] = int(parts[0], 16)

base = syms.get("wieen_boot", 0)
data_off = syms["wieen_boot_data"] - base
path_off = syms["wieen_boot_path"] - base

blob = bytearray(text)
if len(blob) < data_off + 56:
    blob.extend(b"\0" * (data_off + 32 - len(blob)))
if len(blob) < path_off + 1:
    blob.extend(b"\0" * (path_off + 1 - len(blob)))

open(out, "wb").write(bytes(blob))
import json
with open(out + ".json", "w") as f:
    json.dump({"code": data_off, "data": data_off, "path": path_off, "size": len(blob)}, f)
print(f"{out}: code={data_off} bytes, data@{data_off}, path@{path_off}")
