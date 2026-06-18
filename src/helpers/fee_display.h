#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Legacy signing: no extra fee field in CDATA. */
#define P2_SIGN_TX_DEFAULT 0x00
/** CDATA ends with 8-byte big-endian µCCD fee for display only (not hashed). */
#define P2_SIGN_TX_FEE_DISPLAY 0x01

#define FEE_DISPLAY_U64_SIZE 8

/** Host may send to skip separate fee line while using P2_FEE_DISPLAY for other reasons. */
#define FEE_DISPLAY_VALUE_OMIT UINT64_MAX

void fee_display_apply_u64(uint8_t *dst_str,
                           size_t dst_str_len,
                           bool *has_fee_display,
                           const uint8_t fee_be[FEE_DISPLAY_U64_SIZE]);
