#include "globals.h"

static size_t lengthOfNumber(uint64_t number) {
    if (number == 0) {
        return 1;
    }
    size_t len = 0;
    for (uint64_t nn = number; nn != 0; nn /= 10) {
        len++;
    }
    return len;
}

size_t numberToText(uint8_t *dst, size_t dstLength, uint64_t number) {
    size_t len = lengthOfNumber(number);

    if (dstLength < len) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }

    // Build the number in big-endian order.
    for (int i = len - 1; i >= 0; i--) {
        dst[i] = (number % 10) + '0';
        number /= 10;
    }
    return len;
}

size_t numberToTextWithUnit(uint8_t *dst,
                            size_t dstLength,
                            uint64_t number,
                            uint8_t *unit,
                            size_t unitLength) {
    size_t len = numberToText(dst, dstLength, number);

    if (dstLength - len < unitLength + UNIT_SPACE_AND_NULL_LEN) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memmove(dst + len, " ", 1);
    memmove(dst + len + 1, unit, unitLength);
    memmove(dst + len + 1 + unitLength, "\0", 1);

    return len + unitLength + UNIT_SPACE_AND_NULL_LEN;
}

size_t bin2dec(uint8_t *dst, size_t dstLength, uint64_t number) {
    size_t characterLength = numberToText(dst, dstLength, number);
    if (dstLength < characterLength + 1) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    dst[characterLength] = '\0';
    return characterLength + 1;
}

static size_t decimalDigitsDisplay(uint8_t *dst,
                                   size_t dstLength,
                                   uint64_t decimalPart,
                                   uint8_t decimalDigitsLength) {
    // Fill with zeroes if the number is less than decimalDigits,
    // so that input like 5304 become 005304 in their display version.
    size_t length = lengthOfNumber(decimalPart);
    int zeroFillLength = decimalDigitsLength - length;

    if (zeroFillLength < 0 || dstLength < (size_t) zeroFillLength) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }

    for (int i = 0; i < zeroFillLength; i++) {
        dst[i] = '0';
    }

    // Remove any non-significant zeroes from the number.
    // This avoids displaying numbers like 5300, as it will
    // instead become 53.
    for (int i = length - 1; i >= 0; i--) {
        uint64_t currentNumber = (decimalPart % 10);
        if (currentNumber != 0) {
            break;
        } else {
            decimalPart /= 10;
        }
    }

    return numberToText(dst + zeroFillLength, dstLength - zeroFillLength, decimalPart) +
           zeroFillLength;
}

size_t decimalNumberToDisplay(uint8_t *dst,
                              size_t dstLength,
                              uint64_t amount,
                              uint32_t resolution,
                              uint8_t decimalDigitsLength) {
    // In every case we need to write at least 2 characters (e.g. "0.")
    if (dstLength < MIN_DECIMAL_DISPLAY_LENGTH) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    // A zero amount should be displayed as a plain '0'.
    if (amount == 0) {
        dst[0] = '0';
        return 1;
    }

    int length = lengthOfNumber(amount);

    // If the amount is less than the resolution, then the
    // amount has to be prefixed by '0.' as it will purely consist
    // of the decimals.
    if (amount < resolution) {
        dst[0] = '0';
        dst[1] = '.';
        return decimalDigitsDisplay(dst + 2,
                                    dstLength - PREFIX_ZERO_DOT_LEN,
                                    amount,
                                    decimalDigitsLength) +
               2;
    }

    size_t offset = 0;

    size_t wholeNumberLength = length - decimalDigitsLength;
    uint64_t wholePart = amount / resolution;

    // We check that the entire number and termination fits,
    // under the assumption that there is no decimalPart
    if (dstLength < wholeNumberLength + 1) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }

    // Write the whole number part of the amount to the output destination.
    for (int i = wholeNumberLength - 1; i >= 0; i--) {
        dst[i] = (wholePart % 10) + '0';
        wholePart /= 10;
    }

    offset = wholeNumberLength;

    // The first decimalDigitsLength digits are the decimal part (no thousand separators).
    // Write the whole number first, then separate with '.'
    uint64_t decimalPart = amount % resolution;
    if (decimalPart != 0) {
        dst[offset] = '.';
        offset += 1;
        offset += decimalDigitsDisplay(dst + offset,
                                       dstLength - offset,
                                       decimalPart,
                                       decimalDigitsLength);
    }

    // We check that we can fit the termination character
    if (dstLength < offset + 1) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }

    return offset;
}

size_t fractionToPercentageDisplay(uint8_t *dst, size_t dstLength, uint32_t number) {
    if (number > MAX_PERCENTAGE_NUMERATOR) {
        THROW(ERROR_INVALID_TRANSACTION);
    }

    size_t offset = decimalNumberToDisplay(dst,
                                           dstLength,
                                           number,
                                           PERCENTAGE_RESOLUTION,
                                           PERCENTAGE_DECIMAL_PLACES);
    if (dstLength < offset + PERCENTAGE_SUFFIX_LEN) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    dst[offset] = '%';
    dst[offset + 1] = '\0';
    return offset + PERCENTAGE_SUFFIX_LEN;
}

/**
 * Constructs a display text version of a micro GTU amount, so that it
 * can displayed as GTU, i.e. not as the micro version, as it is easier
 * to relate to in the GUI.
 */
size_t amountToGtuDisplay(uint8_t *dst, size_t dstLength, uint64_t microGtuAmount) {
    if (dstLength < GTU_DISPLAY_LENGTH) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    size_t offset =
        decimalNumberToDisplay(dst, dstLength, microGtuAmount, GTU_RESOLUTION, GTU_DECIMAL_PLACES);
    if ((offset >= GTU_LINE_BREAK_MIN_OFFSET) && (offset < GTU_LINE_BREAK_MAX_OFFSET)) {
        memmove(dst + offset, "\nCCD\0", GTU_DISPLAY_LENGTH);
    } else {
        memmove(dst + offset, " CCD\0", GTU_DISPLAY_LENGTH);
    }
    offset += GTU_DISPLAY_LENGTH - 1;  // Exclude null terminator from return
    return offset;
}

void toPaginatedHex(uint8_t *byteArray, const uint64_t len, char *asHex, const size_t asHexSize) {
    LEDGER_ASSERT(byteArray != NULL, "NULL byteArray");

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
