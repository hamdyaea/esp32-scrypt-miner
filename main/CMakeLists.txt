# Developer: Hamdy Abou El Anein
# Contact: hamdy.aea@protonmail.com
# SPDX-License-Identifier: GPL-3.0-or-later
idf_component_register(SRCS "main.c" "scrypt.c"
                       INCLUDE_DIRS "."
                       REQUIRES mbedtls esp_timer esp_system heap)
