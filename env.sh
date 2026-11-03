#!/usr/bin/env bash
# Developer: Hamdy Abou El Anein
# Contact: hamdy.aea@protonmail.com
# SPDX-License-Identifier: GPL-3.0-or-later
# Source this script: source ./env.sh
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Use: source ./env.sh" >&2
    exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export IDF_TOOLS_PATH="$ROOT/tools"
export PATH="$HOME/.local/share/uv/python/cpython-3.12-linux-x86_64-gnu/bin:$PATH"
# Manjaro currently lacks libslirp.so.0, needed by Espressif QEMU.
# Use the locally unpacked distro library, without changing system packages.
export LD_LIBRARY_PATH="$ROOT/compat/usr/lib:${LD_LIBRARY_PATH:-}"
# ESP-IDF's export script sets up the isolated toolchain and Python venv.
source "$ROOT/esp-idf/export.sh"
cd "$ROOT/project"
