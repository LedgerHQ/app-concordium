#ifndef APDU_HELPERS_H
#define APDU_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include <os_utils.h>
#include <exceptions.h>
#include <os_print.h>

/**
 * Read a big-endian uint8 from APDU data and advance the offset.
 *
 * @param data   Buffer containing APDU data
 * @param offset Current read position; incremented by 1 on success
 * @param out    Pointer of an ouput value
 * @return       New offset
 */
static inline size_t read_u8(uint8_t *data, size_t offset, uint8_t *out) {
    *out = data[offset];
    return offset + 1;
}

/**
 * Read a big-endian uint32 from APDU data and advance the offset.
 *
 * @param data   Buffer containing APDU data
 * @param offset Current read position; incremented by 4 on success
 * @param out    Pointer of an ouput value
 * @return       New offset
 */
static inline size_t read_u32_be(uint8_t *data, size_t offset, uint32_t *out) {
    *out = U4BE(data, offset);
    return offset + 4;
}

/**
 * Validate APDU Lc (command data length) against expected value.
 *
 * @param lc       Actual Lc byte from APDU header
 * @param expected Expected command data length in bytes
 *
 * @throws SWO_WRONG_DATA_LENGTH if lc != expected
 */
static inline void check_lc(uint8_t lc, uint8_t expected) {
    if (lc != expected) {
        PRINTF("Wrong data length: expected lc %d, actual lc: %d\n", expected, lc);
        THROW(SWO_WRONG_DATA_LENGTH);
    }
}

#endif  // APDU_HELPERS_H