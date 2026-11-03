#!/usr/bin/env bash
# Developer: Hamdy Abou El Anein
# Contact: hamdy.aea@protonmail.com
# SPDX-License-Identifier: GPL-3.0-or-later
# One command: host test vectors, ESP32 firmware build, QEMU test vectors.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh >/dev/null
echo "=== Host cryptographic validation ==="
python3 -m unittest discover -s tests -v
echo "=== ESP32 classic firmware build (2 jobs) ==="
ninja -C build -j2
echo "=== ESP32 Xtensa QEMU test ==="
python3 tests/run_qemu.py
echo "SUCCESS: all host and emulated ESP32 Scrypt tests passed."
