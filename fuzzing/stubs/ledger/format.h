#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

bool format_i64(char *dst, size_t dst_len, const int64_t value);
bool format_u64(char *dst, size_t dst_len, uint64_t value);
bool format_fpu64(char *dst, size_t dst_len, const uint64_t value, uint8_t decimals);
bool format_fpu64_trimmed(char *dst, size_t dst_len, const uint64_t value, uint8_t decimals);
int  format_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len);
