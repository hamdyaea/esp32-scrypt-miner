# ESP32 Scrypt PoW — Dogecoin / Litecoin research firmware

Developer: Hamdy Abou El Anein
Contact: hamdy.aea@protonmail.com
License: GPL-3.0-or-later

## Purpose

Develop and validate a real **ESP32 classic (ESP32-WROOM-32 / LX6)** firmware
for the Scrypt proof-of-work used by Litecoin and Dogecoin.

The *same* `main/scrypt.c` is compiled for the Linux test runner and ESP-IDF.
It implements **Scrypt(N=1024, r=1, p=1)**, PBKDF2-HMAC-SHA256, ROMix and
Salsa20/8, with **128 KiB of scratch memory**. The firmware checks a known
test vector and hashes three 80-byte headers, then reports emulated timing
and free internal RAM. It does **not** connect to a mining pool or submit
shares; that would be a later stage.

## Hardware target

- ESP32 classic dual-core Xtensa LX6, configured for **240 MHz**.
- 520 KiB on-chip SRAM (not all available to applications).
- 4 MiB external flash; no PSRAM required.
- Suggested future boards: ESP32 DevKitC / ESP32-WROOM-32E with USB-to-UART
  and accessible GPIO0/EN buttons.
- ESP32-S2/C3/C6 are **different architectures**; do not use this firmware
  without changing the target and testing again.

## Quick start on the configured Manjaro

```sh
cd ~/esp32-scrypt-miner/project
./run.sh
```

This validates host test vectors, rebuilds the firmware with at most two
compiler jobs, launches ESP32 QEMU, and exits after all three emulator
vectors pass. A full transcript is saved as `qemu-benchmark.log`.

## Host tests (Manjaro)

```sh
cd ~/esp32-scrypt-miner/project
python3 -m unittest discover -s tests -v
```

The tests compile the portable C implementation with GCC and OpenSSL,
then compare multiple test vectors against Python's `hashlib.scrypt`.
Native Intel H/s are **not** an ESP32 performance estimate.

## ESP-IDF build and QEMU

ESP-IDF 5.5.1, Xtensa toolchain, Python 3.12, and Espressif QEMU are installed
**locally under** `~/esp32-scrypt-miner/`, without modifying system Python.
Manjaro does not currently provide `libslirp.so.0` on this machine, so a
Manjaro `libslirp` package was extracted into `../compat/usr/lib` and
loaded only for this development environment via `env.sh`.
No system-wide package was installed or replaced.

```sh
cd ~/esp32-scrypt-miner/project
source ./env.sh
idf.py set-target esp32
ninja -C build -j2  # limit compilation to two jobs on this Manjaro
idf.py qemu monitor
```

To exit QEMU monitor use `Ctrl+]` or `Ctrl+C` as supported by the terminal.
The test completes when `BENCHMARK_DONE` appears.

**Important:** QEMU executes Xtensa instructions but does not reproduce
hardware cycle timings, memory stalls, cache, Wi-Fi, power or temperature.
Its reported H/s **cannot be used to predict a real 240 MHz ESP32's H/s**.
For a physical benchmark, flash the same image:

```sh
idf.py -p /dev/ttyUSB0 flash monitor
```

Use the actual serial port for the connected board; access to serial
ports may require group permissions. Do not flash an NM-TV-154 unless
its precise board wiring, bootloader and flash layout are verified first.

## Memory and optimization notes

Scrypt ROMix uses 1024 blocks of 128 bytes, i.e. 131072 bytes of internal
RAM. The firmware allocates this with `heap_caps_malloc` and checks failure
explicitly. A later miner needs extra memory for Stratum, TLS/Wi-Fi, buffers
and FreeRTOS tasks. Test with real hardware before adding networking.

The present code uses a single hashing worker. Dual-core hashing requires
separate 128 KiB scratch buffers, so it may be memory-constrained on the
ESP32 without PSRAM. Benchmark one core first; do not assume a 2x speedup.

## Safety and security

No wallet keys, Wi-Fi credentials, mining pool passwords or account tokens
are embedded in the project. No private data or network traffic is required
for these tests. A future Stratum client should support pool difficulty and
share validation, and should never treat unverified pool responses as hashes.
