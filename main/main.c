// Developer: Hamdy Abou El Anein
// Contact: hamdy.aea@protonmail.com
// SPDX-License-Identifier: GPL-3.0-or-later
// Benchmark-only firmware: NO mining pool, wallet, or live network activity.
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include "scrypt.h"

static const char *TAG = "ESP32-SCRYPT";
static const uint8_t expected_zero_header[32] = {
    0x16, 0x1d, 0x08, 0x76, 0xf3, 0xb9, 0x3b, 0x10,
    0x48, 0xcd, 0xa1, 0xbd, 0xea, 0xa7, 0x33, 0x2e,
    0xe2, 0x10, 0xf7, 0x13, 0x1b, 0x42, 0x01, 0x3c,
    0xb4, 0x39, 0x13, 0xa6, 0x55, 0x3a, 0x4b, 0x69
};
static const uint8_t expected_nonce_one[32] = {
    0xd0, 0xb4, 0x8e, 0xbe, 0x08, 0xe0, 0x30, 0x86,
    0x5f, 0x4e, 0xe7, 0x1a, 0xff, 0x4e, 0x34, 0xe0,
    0xe4, 0x9c, 0xe8, 0xd3, 0xaa, 0xa6, 0x9d, 0xab,
    0x78, 0xd0, 0xe7, 0x02, 0x75, 0x50, 0xb9, 0x56
};
static const uint8_t expected_nonce_two[32] = {
    0x76, 0xfc, 0xb5, 0x39, 0x63, 0x71, 0x44, 0x1a,
    0x70, 0x93, 0x36, 0xa7, 0x0d, 0x2e, 0x8a, 0x79,
    0xb6, 0x4b, 0xb4, 0x22, 0x18, 0xe4, 0xd4, 0x5b,
    0xa1, 0x97, 0xe7, 0xe7, 0x31, 0x07, 0xfa, 0x81
};

void app_main(void) {
    ESP_LOGI(TAG, "Developer: Hamdy Abou El Anein");
    ESP_LOGI(TAG, "ESP32 classic Xtensa LX6, CPU configured %d MHz",
             CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);
    ESP_LOGI(TAG, "Scrypt PoW N=1024 r=1 p=1, internal scratch=%u bytes",
             (unsigned)SCRYPT_SCRATCH_BYTES);
    ESP_LOGW(TAG, "QEMU time is NOT the real ESP32 hashrate.");
    size_t free_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    ESP_LOGI(TAG, "Free internal RAM before scratch: %u bytes", (unsigned)free_before);
    void *scratch = heap_caps_malloc(
        SCRYPT_SCRATCH_BYTES, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT
    );
    if (!scratch) {
        ESP_LOGE(TAG, "Cannot allocate 128 KiB internal SRAM; test failed.");
        return;
    }
    uint8_t header[80] = {0};
    uint8_t output[32];
    uint64_t total_us = 0;
    const unsigned rounds = 3;
    for (unsigned i = 0; i < rounds; ++i) {
        // Change the nonce only after checking the deterministic test vector.
        if (i > 0) header[76] = (uint8_t)i;
        int64_t start = esp_timer_get_time();
        int result = scrypt_pow_80(header, output, scratch, SCRYPT_SCRATCH_BYTES);
        int64_t duration = esp_timer_get_time() - start;
        const uint8_t *expected = i == 0 ? expected_zero_header :
                                  i == 1 ? expected_nonce_one : expected_nonce_two;
        if (result || memcmp(output, expected, 32) != 0) {
            ESP_LOGE(TAG, "FAIL: Scrypt hash or test vector mismatch (code=%d)", result);
            heap_caps_free(scratch);
            return;
        }
        total_us += (uint64_t)duration;
        ESP_LOGI(TAG, "PASS hash %u/%u, %" PRIi64 " us", i + 1, rounds, duration);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    ESP_LOGI(TAG, "PASS: 3 valid hashes, test vector matches Python hashlib.");
    ESP_LOGI(TAG, "Emulated throughput %.3f H/s (NOT real hardware)",
             (double)rounds * 1000000.0 / (double)total_us);
    ESP_LOGI(TAG, "Free internal RAM while scratch is allocated: %u bytes",
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
    heap_caps_free(scratch);
    ESP_LOGI(TAG, "BENCHMARK_DONE. No mining pool or network connection.");
}
