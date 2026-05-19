#pragma once

#include <stdint.h>
#include <stddef.h>

/* Big-endian multi-byte read helpers (mirrors ledger-secure-sdk/include/os_utils.h) */

static inline uint16_t U2BE(const uint8_t *buf, size_t off) {
    return (uint16_t)(((uint16_t)buf[off] << 8) | buf[off + 1]);
}

static inline uint32_t U4BE(const uint8_t *buf, size_t off) {
    return ((uint32_t)buf[off]     << 24) |
           ((uint32_t)buf[off + 1] << 16) |
           ((uint32_t)buf[off + 2] <<  8) |
            (uint32_t)buf[off + 3];
}

static inline uint64_t U8BE(const uint8_t *buf, size_t off) {
    return ((uint64_t)U4BE(buf, off) << 32) | (uint64_t)U4BE(buf, off + 4);
}

/* Big-endian encode helpers */
static inline void U2BE_ENCODE(uint8_t *buf, size_t off, uint32_t value) {
    buf[off]     = (uint8_t)(value >> 8);
    buf[off + 1] = (uint8_t)(value);
}

static inline void U4BE_ENCODE(uint8_t *buf, size_t off, uint32_t value) {
    buf[off]     = (uint8_t)(value >> 24);
    buf[off + 1] = (uint8_t)(value >> 16);
    buf[off + 2] = (uint8_t)(value >>  8);
    buf[off + 3] = (uint8_t)(value);
}

static inline void U8BE_ENCODE(uint8_t *buf, size_t off, uint64_t value) {
    U4BE_ENCODE(buf, off,     (uint32_t)(value >> 32));
    U4BE_ENCODE(buf, off + 4, (uint32_t)(value));
}
