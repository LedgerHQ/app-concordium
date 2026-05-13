#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* buffer_t (mirrors ledger-secure-sdk/lib_standard_app/buffer.h without bip32 deps) */
typedef enum { BE, LE } endianness_t;

typedef struct {
    uint8_t *ptr;
    size_t   size;
    size_t   offset;
} buffer_t;

static inline buffer_t buffer_create(void *ptr, size_t size) {
    buffer_t b = { .ptr = (uint8_t *)ptr, .size = size, .offset = 0 };
    return b;
}
static inline uint8_t *buffer_get_cur(const buffer_t *b) {
    return b->ptr + b->offset;
}
static inline bool buffer_can_read(const buffer_t *b, size_t n) {
    return (b->offset + n) <= b->size;
}
static inline bool buffer_seek_set(buffer_t *b, size_t offset) {
    if (offset > b->size) return false;
    b->offset = offset;
    return true;
}
static inline bool buffer_seek_cur(buffer_t *b, size_t n) {
    if (b->offset + n > b->size) return false;
    b->offset += n;
    return true;
}
static inline bool buffer_seek_end(buffer_t *b, size_t offset) {
    if (offset > b->size) return false;
    b->offset = b->size - offset;
    return true;
}

bool buffer_read_u8(buffer_t *b, uint8_t *value);
bool buffer_read_u16(buffer_t *b, uint16_t *value, endianness_t endianness);
bool buffer_read_u32(buffer_t *b, uint32_t *value, endianness_t endianness);
bool buffer_read_u64(buffer_t *b, uint64_t *value, endianness_t endianness);
bool buffer_read_bytes(buffer_t *b, uint8_t *out, size_t n);
bool buffer_copy(const buffer_t *b, uint8_t *out, size_t out_len);
bool buffer_move(buffer_t *b, uint8_t *out, size_t out_len);
bool buffer_peek(const buffer_t *b, uint8_t *value);
bool buffer_peek_n(const buffer_t *b, size_t n, uint8_t *value);
bool buffer_write_u8(buffer_t *b, uint8_t value);
bool buffer_write_u16(buffer_t *b, uint16_t value, endianness_t endianness);
bool buffer_write_u32(buffer_t *b, uint32_t value, endianness_t endianness);
bool buffer_write_u64(buffer_t *b, uint64_t value, endianness_t endianness);
bool buffer_write_bytes(buffer_t *b, const uint8_t *data, size_t n);
bool buffer_read_varint(buffer_t *b, uint64_t *value);
