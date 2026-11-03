#!/usr/bin/env python3
# Developer: Hamdy Abou El Anein
# Contact: hamdy.aea@protonmail.com
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate the *same C Scrypt implementation* against Python hashlib/OpenSSL."""
import ctypes
import hashlib
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "main" / "scrypt.c"
SCRATCH_BYTES = 1024 * 128


class ScryptPowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(prefix="esp32-scrypt-tests-")
        library = Path(cls.tempdir.name) / "libscrypt.so"
        subprocess.run(
            ["gcc", "-O3", "-Wall", "-Wextra", "-Werror", "-std=c11",
             "-shared", "-fPIC", str(SRC), "-lcrypto", "-o", str(library)],
            check=True,
        )
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.scrypt_pow_80.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
        ]
        cls.lib.scrypt_pow_80.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def calculate(self, header):
        self.assertEqual(len(header), 80)
        src = ctypes.create_string_buffer(header)
        dst = ctypes.create_string_buffer(32)
        scratch = ctypes.create_string_buffer(SCRATCH_BYTES)
        rc = self.lib.scrypt_pow_80(src, dst, scratch, SCRATCH_BYTES)
        self.assertEqual(rc, 0)
        return dst.raw

    def test_known_vectors(self):
        for header in (
            bytes(80),
            bytes(range(80)),
            bytes([0xFF] * 80),
            bytes.fromhex("01000000") + bytes(72) + bytes.fromhex("00000000"),
        ):
            with self.subTest(prefix=header[:8].hex()):
                expected = hashlib.scrypt(
                    header, salt=header, n=1024, r=1, p=1, dklen=32
                )
                self.assertEqual(self.calculate(header), expected)

    def test_invalid_scratch_is_rejected(self):
        header = ctypes.create_string_buffer(bytes(80))
        output = ctypes.create_string_buffer(32)
        scratch = ctypes.create_string_buffer(128)
        self.assertNotEqual(
            self.lib.scrypt_pow_80(header, output, scratch, 128), 0
        )

    def test_host_benchmark_reference_only(self):
        header = bytes(80)
        start = time.perf_counter()
        self.calculate(header)
        elapsed = time.perf_counter() - start
        print(
            f"\nHost C benchmark: {1 / elapsed:.2f} H/s "
            f"({elapsed * 1000:.1f} ms/hash). NOT an ESP32 estimate."
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
