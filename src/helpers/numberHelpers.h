#pragma once

#include <stddef.h>
#include <stdint.h>

#define CCD_DISPLAY_LENGTH 5
#define CCD_DECIMAL_PLACES 6
#define CCD_RESOLUTION     1000000

#define PERCENTAGE_RESOLUTION     1000
#define PERCENTAGE_DECIMAL_PLACES 3
#define MAX_PERCENTAGE_NUMERATOR  100000
#define PERCENTAGE_SUFFIX_LEN     2  // "%" + '\0'

#define CCD_LINE_BREAK_MIN_OFFSET 14
#define CCD_LINE_BREAK_MAX_OFFSET 18
#define HEX_PAGINATION_WIDTH      16
#define NIBBLE_MASK               0x0F
#define UNIT_SPACE_AND_NULL_LEN   2

/**
 * Writes the input amount of µCCD to the supplied destination as its value in
 * CCD with thousand separators.
 * @param dst where to write the thousand separated representation of the µCCD
 * @param dstLength the number of bytes that may be written to 'dst'
 * @param number the integer µCCD amount to convert to a CCD display version
 * @return number of bytes written to 'dst'
 */
size_t amount_to_ccd_display(uint8_t *dst, size_t dstLength, uint64_t microCcdAmount);

/**
 * Helper method that writes the input integer to a format that the device
 * can display on screen. The result is not string terminated.
 * @param dst where to write the text representation of the integer
 * @param dstLength the number of bytes that may be written to 'dst'
 * @param number the integer to convert to characters
 * @return number of bytes written to 'dst', i.e. the number of characters in the integer 'number'
 */
size_t number_to_text(uint8_t *dst, size_t dstLength, uint64_t number);

/**
 * Helper methods that writes the input integer to a format that the device
 * can display on screen. The integer is postfixed with a unit and is string terminated.
 * @param dst where to write the text representation of the integer and the unit
 * @param dstLength the number of bytes that may be written to 'dst'
 * @param number the integer to convert to characters
 * @return number of bytes written to 'dst'
 */
size_t number_to_text_with_unit(uint8_t *dst,
                                size_t dstLength,
                                uint64_t number,
                                uint8_t *unit,
                                size_t unitLength);

/**
 * Helper method that writes the input integer to a format that the device can
 * display on the screen.
 * @param dst where to write the text representation of the integer
 * @param dstLength the number of bytes that may be written to 'dst'
 * @param number the integer to convert to characters
 * @return number of bytes written to 'dst', i.e. the number of characters in the integer 'number' +
 * 1 for string termination
 */
size_t bin_to_dec(uint8_t *dst, size_t dstLength, uint64_t number);

/**
 * Writes a fraction of the form "numerator/100000" to the destination formatted
 * as a percentage.
 * @param dst where to write the text representation of the fraction
 * @param dstLength the number of bytes that may be written to 'dst'
 * @param number the numerator of the fraction
 * @return number of bytes written to 'dst'.
 */
size_t fraction_to_percentage_display(uint8_t *dst, size_t dstLength, uint32_t number);

/**
 * Helper method for converting a byte array into a character array, where the bytes
 * are translated into their hexadecimal representation. This is used for getting human-readable
 * representations of e.g. keys and credential ids. The output array is 'paginated' by inserting
 * a space after 16 characters, as this will make the Ledger pagination change page after
 * 16 characters.
 * @param byteArray [in] the bytes to convert to paginated hex
 * @param len the length of 'byteArray', i.e. the number of bytes to convert to paginated hex
 * @param asHex [out] where to write the output hexadecimal characters
 * @param asHexSize the number of characters that may be written to 'asHex'
 */
void to_paginated_hex(uint8_t *byteArray, const uint64_t len, char *asHex, size_t asHexSize);

/**
 * Formats a CIS-7 PLT amount (CBOR decimal-fraction tag 4) as a human-readable string.
 * The exponent must be ≤ 0; its absolute value is the number of decimal places.
 * Result: "<integer>.<fraction> <tokenId>\0", e.g. "1.500000 UPEU".
 * Throws ERROR_BUFFER_OVERFLOW if dst is too small.
 */
void plt_amount_to_display(char *dst,
                            size_t dstLen,
                            uint64_t significand,
                            int8_t exponent,
                            const char *tokenId,
                            uint8_t tokenIdLen);
