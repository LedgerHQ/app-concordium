#include "numberHelpers.h"

#include "globals.h"

#include "format.h"

#include <os.h>
#include <string.h>

/** Max decimal digits for uint64_t plus NUL (format_u64). */
#define U64_DEC_BUF_LEN 22

/** format_fpu64 needs more room than the final trimmed string; avoid using tiny caller buffers. */
#define FPU64_TMP_LEN 40

/**
 * Ledger `format_fpu64` does not always write a trailing '\0'. `format_fpu64_trimmed` then uses
 * strlen; zero the buffer first so the numeric part is bounded.
 */
#define FPU64_TMP_ZERO_INIT char tmp[FPU64_TMP_LEN] = {0}

/**
 * Writes decimal digits of @p number to @p dst without a trailing '\0'.
 * Used where callers concatenate multiple segments (date, ratios, export paths).
 */
static size_t u64_to_digits_no_nul(uint8_t *dst, size_t dstLength, uint64_t number) {
    char tmp[U64_DEC_BUF_LEN];
    if (!format_u64(tmp, sizeof(tmp), number)) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    size_t len = strlen(tmp);
    if (dstLength < len) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memmove(dst, tmp, len);
    return len;
}

size_t number_to_text(uint8_t *dst, size_t dstLength, uint64_t number) {
    return u64_to_digits_no_nul(dst, dstLength, number);
}

size_t number_to_text_with_unit(uint8_t *dst,
                                size_t dstLength,
                                uint64_t number,
                                uint8_t *unit,
                                size_t unitLength) {
    size_t len = u64_to_digits_no_nul(dst, dstLength, number);

    if (dstLength - len < unitLength + UNIT_SPACE_AND_NULL_LEN) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memmove(dst + len, " ", 1);
    memmove(dst + len + 1, unit, unitLength);
    memmove(dst + len + 1 + unitLength, "\0", 1);

    return len + unitLength + UNIT_SPACE_AND_NULL_LEN;
}

size_t bin_to_dec(uint8_t *dst, size_t dstLength, uint64_t number) {
    size_t len = u64_to_digits_no_nul(dst, dstLength, number);
    if (dstLength < len + 1) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    dst[len] = '\0';
    return len + 1;
}

size_t fraction_to_percentage_display(uint8_t *dst, size_t dstLength, uint32_t number) {
    if (number > MAX_PERCENTAGE_NUMERATOR) {
        THROW(ERROR_INVALID_TRANSACTION);
    }
    FPU64_TMP_ZERO_INIT;
    if (!format_fpu64_trimmed(tmp, sizeof(tmp), (uint64_t) number, PERCENTAGE_DECIMAL_PLACES)) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    size_t offset = strlen(tmp);
    if (dstLength < offset + PERCENTAGE_SUFFIX_LEN) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memmove(dst, tmp, offset);
    dst[offset] = '%';
    dst[offset + 1] = '\0';
    return offset + PERCENTAGE_SUFFIX_LEN;
}

size_t amount_to_ccd_display(uint8_t *dst, size_t dstLength, uint64_t microCcdAmount) {
    FPU64_TMP_ZERO_INIT;
    if (!format_fpu64_trimmed(tmp, sizeof(tmp), microCcdAmount, CCD_DECIMAL_PLACES)) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    size_t offset = strlen(tmp);
    if (dstLength < offset + CCD_DISPLAY_LENGTH) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memmove(dst, tmp, offset);
    if ((offset >= CCD_LINE_BREAK_MIN_OFFSET) && (offset < CCD_LINE_BREAK_MAX_OFFSET)) {
        memmove(dst + offset, "\nCCD\0", CCD_DISPLAY_LENGTH);
    } else {
        memmove(dst + offset, " CCD\0", CCD_DISPLAY_LENGTH);
    }
    offset += CCD_DISPLAY_LENGTH - 1;  // Exclude null terminator from return
    return offset;
}

void to_paginated_hex(uint8_t *byteArray, const uint64_t len, char *asHex, const size_t asHexSize) {
    if (byteArray == NULL) {
        THROW(ERROR_INVALID_PARAM);
    }

    static uint8_t const hex[] = "0123456789abcdef";

    if (asHexSize < len * 2 + len / HEX_PAGINATION_WIDTH + 1) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }

    uint8_t offset = 0;
    for (uint64_t i = 0; i < len; i++) {
        asHex[2 * i + offset] = hex[(byteArray[i] >> 4) & NIBBLE_MASK];
        asHex[2 * i + (offset + 1)] = hex[(byteArray[i] >> 0) & NIBBLE_MASK];

        // Insert newline to force the Ledger to paginate every HEX_PAGINATION_WIDTH chars.
        if ((2 * (i + 1)) % HEX_PAGINATION_WIDTH == 0 && i != len - 1) {
            asHex[2 * i + (offset + 2)] = '\n';
            offset += 1;
        }
    }
    asHex[2 * len + offset] = '\0';
}
