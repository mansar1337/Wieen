#!/usr/bin/env python3
"""Patch the client APK as soon as Sober (re)downloads it.

Sober fetches the Roblox APKs on every start and spawns the client right
after, so the patch has to land in that window.  This watcher polls the file
and re-applies the patch whenever it changes.
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import patch_apk

SPLIT = patch_apk.SPLIT


def stamp(path: Path):
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def main() -> int:
    last = None
    print(f"[wieen] watching {SPLIT}")
    while True:
        cur = stamp(SPLIT)
        if cur and cur != last:
            last = cur
            try:
                patch_apk.patch()
            except SystemExit:
                pass
            except Exception as exc:  # noqa: BLE001
                print(f"[wieen] patch failed: {exc}")
        time.sleep(0.05)


if __name__ == "__main__":
    sys.exit(main())
