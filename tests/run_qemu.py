#!/usr/bin/env python3
# Developer: Hamdy Abou El Anein
# Contact: hamdy.aea@protonmail.com
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run ESP-IDF QEMU, verify the Scrypt test vector, then exit cleanly."""
from pathlib import Path
import pexpect
import sys

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "qemu-benchmark.log"


def main():
    with LOG.open("w", encoding="utf-8") as stream:
        child = pexpect.spawn(
            "idf.py", ["qemu", "monitor"],
            cwd=str(ROOT), encoding="utf-8", timeout=180,
            logfile=stream,
        )
        try:
            child.expect("PASS: 3 valid hashes", timeout=180)
            child.expect("BENCHMARK_DONE", timeout=20)
            print("ESP32 QEMU firmware: all Scrypt checks passed.")
            print(f"Emulator transcript: {LOG}")
            return 0
        except (pexpect.TIMEOUT, pexpect.EOF) as exc:
            print(f"QEMU run failed: {type(exc).__name__}. See {LOG}", file=sys.stderr)
            return 1
        finally:
            if child.isalive():
                child.sendcontrol("]")
                try:
                    child.expect(pexpect.EOF, timeout=8)
                except (pexpect.TIMEOUT, pexpect.EOF):
                    child.terminate(force=True)


if __name__ == "__main__":
    sys.exit(main())
