// Developer: Hamdy Abou El Anein
// Contact: hamdy.aea@protonmail.com
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef ESP32_SCRYPT_H
#define ESP32_SCRYPT_H
#include <stddef.h>
#include <stdint.h>

#define SCRYPT_N 1024u
#define SCRYPT_R 1u
#define SCRYPT_P 1u
#define SCRYPT_SCRATCH_BYTES (SCRYPT_N * 128u)

// Litecoin / Dogecoin proof-of-work Scrypt(1024,1,1), 80-byte block header.
// Caller provides 128 KiB aligned scratch (4-byte minimum), not thread-safe
// if the same scratch is shared across concurrent calls.
// Returns 0 on success; nonzero on crypto/allocation/argument failure.
int scrypt_pow_80(const uint8_t header[80], uint8_t output[32],
                  void *scratch, size_t scratch_size);
#endif
