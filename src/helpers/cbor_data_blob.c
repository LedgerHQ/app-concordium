#include "cbor_data_blob.h"

#include "globals.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <os.h>
#include <cx.h>
#include <io.h>
#include <status_words.h>

#include "concordium_crypto.h"
#include "display_text.h"
#include "numberHelpers.h"

#define UINT64_MAX_DECIMAL_DIGITS 20

// CBOR encoding constants
#define CBOR_SHORT_COUNT_MAX   23  // Values below this are direct length
#define CBOR_ONE_BYTE_LENGTH   24  // Uses 1 additional byte for length
#define CBOR_TWO_BYTE_LENGTH   25  // Uses 2 additional bytes for length
#define CBOR_FOUR_BYTE_LENGTH  26  // Uses 4 additional bytes for length
#define CBOR_EIGHT_BYTE_LENGTH 27  // Uses 8 additional bytes for length
#define CBOR_INDEFINITE_LENGTH 31  // Indicates indefinite length encoding (unsupported)

// Mask and bit shifts
#define CBOR_SHORT_COUNT_MASK 0x1F  // 5 lower bits

static cborContext_t *ctx = &global.withDataBlob.cborContext;

/**
 * Record the CBOR major type for the review.
 *
 * The screen used to show only the decoded value, so canonical unsigned 1 (01) and canonical
 * text "1" (6131) - distinct signed byte strings - produced an identical review.
 */
static void cbor_set_type_label(const char *label) {
    size_t length = strlen(label);
    if (length + 1 > sizeof(ctx->typeLabel)) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    explicit_bzero(ctx->typeLabel, sizeof(ctx->typeLabel));
    memmove(ctx->typeLabel, label, length);
}

/**
 * True when `length` is encoded in the shortest width CBOR allows for it.
 *
 * A short count of 0-23 carries the value inline and is canonical by construction; the wider
 * forms are only canonical when the value does not fit in every smaller one.
 */
static bool cbor_argument_is_canonical(uint8_t shortCount, uint64_t length) {
    switch (shortCount) {
        case CBOR_ONE_BYTE_LENGTH:
            return length > CBOR_SHORT_COUNT_MAX;
        case CBOR_TWO_BYTE_LENGTH:
            return length > UINT8_MAX;
        case CBOR_FOUR_BYTE_LENGTH:
            return length > UINT16_MAX;
        case CBOR_EIGHT_BYTE_LENGTH:
            return length > UINT32_MAX;
        default:
            // 0-23 inline, or a short count this parser already refuses elsewhere.
            return true;
    }
}

uint16_t readCborInitial(uint8_t *cdata, uint8_t dataLength) {
    uint8_t remainingDataLength = dataLength;
    /* remainingDataLength guards the physical APDU buffer; cborLength guards the
     * protocol-declared stream total (set from a prior APDU) — both must have
     * at least one byte before consuming the CBOR header. */
    if (remainingDataLength < 1 || ctx->cborLength < 1) {
        THROW(SWO_INCORRECT_DATA);
    }
    uint8_t header = cdata[0];
    cdata += 1;
    remainingDataLength -= 1;
    ctx->cborLength -= 1;
    // the first byte of an cbor encoding contains the type (3 high bits) and the shortCount (5
    // lower bits);
    ctx->majorType = header >> 5;
    uint8_t shortCount = header & CBOR_SHORT_COUNT_MASK;

    // Calculate length of cbor payload
    // sizeLength: number of bytes (beside the header) used to indicate the payload length
    uint8_t sizeLength = 0;
    // length: payload byte size.
    uint64_t length = 0;

    ctx->displayUsed = 0;

    if (shortCount <= CBOR_SHORT_COUNT_MAX) {
        // shortCount is the length, no extra bytes are used.
        length = shortCount;
    } else if (shortCount == CBOR_ONE_BYTE_LENGTH) {
        if (remainingDataLength < 1) {
            THROW(SWO_INCORRECT_DATA);
        }
        length = cdata[0];
        sizeLength = 1;
    } else if (shortCount == CBOR_TWO_BYTE_LENGTH) {
        if (remainingDataLength < 2) {
            THROW(SWO_INCORRECT_DATA);
        }
        length = U2BE(cdata, 0);
        sizeLength = 2;
    } else if (shortCount == CBOR_FOUR_BYTE_LENGTH) {
        if (remainingDataLength < 4) {
            THROW(SWO_INCORRECT_DATA);
        }
        length = U4BE(cdata, 0);
        sizeLength = 4;
    } else if (shortCount == CBOR_EIGHT_BYTE_LENGTH) {
        if (remainingDataLength < 8) {
            THROW(SWO_INCORRECT_DATA);
        }
        length = U8BE(cdata, 0);
        sizeLength = 8;
    } else if (shortCount == CBOR_INDEFINITE_LENGTH) {
        THROW(ERROR_UNSUPPORTED_CBOR);
    } else {
        THROW(ERROR_INVALID_PARAM);
    }
    cdata += sizeLength;
    if (ctx->cborLength < sizeLength) {
        THROW(SWO_INCORRECT_DATA);
    }
    ctx->cborLength -= sizeLength;

    // Deterministic CBOR requires the argument in its shortest form. Without this, 1 could
    // arrive as 01, 1801, 190001, 1a00000001 or 1b0000000000000001 - five distinct byte
    // strings that are all signed but review identically, so the screen cannot tell the user
    // which one they are authorising.
    if (!cbor_argument_is_canonical(shortCount, length)) {
        return ERROR_INVALID_TRANSACTION;
    }
    // An integer is complete once its argument is read, so no APDU byte may follow it. Only the
    // protocol-declared counter was checked before, letting a host append bytes that stayed in
    // the transaction hash while the review showed just the integer.
    bool integerType = (ctx->majorType == 0 || ctx->majorType == 1);
    if (integerType && remainingDataLength != sizeLength) {
        return ERROR_INVALID_TRANSACTION;
    }

    switch (ctx->majorType) {
        case 0:
            // non-negative integer
            cbor_set_type_label("Unsigned integer");
            bin_to_dec(ctx->display, sizeof(ctx->display), length);
            if (ctx->cborLength != 0) {
                THROW(ERROR_INVALID_STATE);
            }
            break;
        case 1:
            // negative integer
            cbor_set_type_label("Negative integer");
            memmove(ctx->display, "-", 1);
            if (length == UINT64_MAX) {
                bin_to_dec(ctx->display + 1, sizeof(ctx->display) - 1, length);
                memmove(ctx->display + 1 + UINT64_MAX_DECIMAL_DIGITS, " - 1", 4);
            } else {
                bin_to_dec(ctx->display + 1, sizeof(ctx->display) - 1, 1 + length);
            }
            if (ctx->cborLength != 0) {
                THROW(ERROR_INVALID_STATE);
            }
            break;
        case 3:
            // utf-8 string
            cbor_set_type_label("Text");
            if (ctx->cborLength != length) {
                THROW(ERROR_INVALID_STATE);
            }
            return readCborContent(cdata, dataLength - 1 - sizeLength);
        default:
            THROW(ERROR_UNSUPPORTED_CBOR);
    }
    return SWO_SUCCESS;
}

uint16_t readCborContent(uint8_t *cdata, uint8_t contentLength) {
    if (ctx->cborLength < contentLength) {
        THROW(SWO_INCORRECT_DATA);
    }
    ctx->cborLength -= contentLength;
    switch (ctx->majorType) {
        case 3:
            // Reserve space for NUL terminator
            if (ctx->displayUsed + contentLength >= sizeof(ctx->display)) {
                THROW(ERROR_BUFFER_OVERFLOW);
            }
            // The memo is hashed in full but shown as a C string, so bytes that cannot be
            // rendered are refused instead of being signed unseen.
            if (!is_displayable_text(cdata, contentLength)) {
                return ERROR_INVALID_TRANSACTION;
            }
            memmove(ctx->display + ctx->displayUsed, cdata, contentLength);
            ctx->displayUsed += contentLength;
            ctx->display[ctx->displayUsed] = '\0';
            break;
        case 0:
        case 1:
            // Type 0 and 1 fails, because we don't support integers that can't fit in the initial
            // payload.
            THROW(ERROR_UNSUPPORTED_CBOR);
            break;
        default:
            THROW(ERROR_INVALID_STATE);
    }
    return SWO_SUCCESS;
}
