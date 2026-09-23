#include "cbor_data_blob.h"
#include "globals.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <os.h>
#include <status_words.h>

#include "cbor.h"
#include "display_text.h"
#include "numberHelpers.h"

#define UINT64_MAX_DECIMAL_DIGITS 20

// Short-count encodings of the CBOR argument (RFC 8949 section 3). tinycbor decodes these for
// us, but it does not police *which* width was used, so the raw header byte is still needed to
// enforce the shortest form below.
#define CBOR_SHORT_COUNT_MASK  0x1F
#define CBOR_SHORT_COUNT_MAX   23
#define CBOR_ONE_BYTE_LENGTH   24
#define CBOR_TWO_BYTE_LENGTH   25
#define CBOR_FOUR_BYTE_LENGTH  26
#define CBOR_EIGHT_BYTE_LENGTH 27

_Static_assert(MAX_CBOR_STRING_SIZE <= UINT8_MAX,
               "MAX_CBOR_STRING_SIZE exceeds UINT8_MAX: widen cborContext_t.displayLen");

// A single APDU chunk is at most 255 bytes (uint8_t limit); the buffer must be larger so
// accumulation across chunks can never overflow on the very first chunk alone.
_Static_assert(MAX_CBOR_BLOB_SIZE > 255,
               "MAX_CBOR_BLOB_SIZE must exceed 255 to safely accumulate multi-chunk payloads");

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
 * True when the accumulated item's argument is encoded in the shortest width CBOR allows.
 *
 * A short count of 0-23 carries the value inline and is canonical by construction; the wider
 * forms are only canonical when the value does not fit in every smaller one. tinycbor accepts
 * every width, so this reads the short count back off the header byte of the buffer it parsed.
 */
static bool cbor_argument_is_canonical(uint64_t argument) {
    uint8_t shortCount = ctx->cborBuf[0] & CBOR_SHORT_COUNT_MASK;
    switch (shortCount) {
        case CBOR_ONE_BYTE_LENGTH:
            return argument > CBOR_SHORT_COUNT_MAX;
        case CBOR_TWO_BYTE_LENGTH:
            return argument > UINT8_MAX;
        case CBOR_FOUR_BYTE_LENGTH:
            return argument > UINT16_MAX;
        case CBOR_EIGHT_BYTE_LENGTH:
            return argument > UINT32_MAX;
        default:
            // 0-23 inline, or a short count tinycbor already refused.
            return true;
    }
}

/**
 * Parse the fully-accumulated cborBuf and populate ctx->display / displayLen / typeLabel.
 * Supports major types 0 (unsigned), 1 (negative) and 3 (text string).
 *
 * @return SWO_SUCCESS, or the status word to refuse the transaction with.
 */
static uint16_t parse_complete_cbor(void) {
    CborParser parser;
    CborValue value;
    const uint8_t *end = ctx->cborBuf + ctx->cborBufLen;

    CborError err = cbor_parser_init(ctx->cborBuf, ctx->cborBufLen, 0, &parser, &value);
    if (err != CborNoError) {
        return ERROR_INVALID_TRANSACTION;
    }

    ctx->displayLen = 0;

    // After advance_fixed, cbor_value_get_next_byte returns source.ptr positioned just past
    // the item's encoded bytes. Comparing it to the buffer end detects trailing bytes: an
    // integer is complete once its argument is read, so no byte may follow it. Without this a
    // host could append bytes that stayed in the transaction hash while the review showed
    // just the integer. (cbor_value_at_end checks remaining==0, which is always true for a
    // top-level item, so it cannot serve here.)
    if (cbor_value_is_unsigned_integer(&value)) {
        uint64_t n;
        err = cbor_value_get_uint64(&value, &n);
        if (err != CborNoError) {
            return ERROR_INVALID_TRANSACTION;
        }
        err = cbor_value_advance_fixed(&value);
        if (err != CborNoError) {
            return ERROR_INVALID_TRANSACTION;
        }
        if (cbor_value_get_next_byte(&value) != end) {
            return ERROR_INVALID_TRANSACTION;
        }
        if (!cbor_argument_is_canonical(n)) {
            return ERROR_INVALID_TRANSACTION;
        }
        cbor_set_type_label("Unsigned integer");
        bin_to_dec(ctx->display, sizeof(ctx->display), n);

    } else if (cbor_value_is_negative_integer(&value)) {
        // The encoded argument is n, and the value it denotes is -1 - n.
        uint64_t n;
        err = cbor_value_get_raw_integer(&value, &n);
        if (err != CborNoError) {
            return ERROR_INVALID_TRANSACTION;
        }
        err = cbor_value_advance_fixed(&value);
        if (err != CborNoError) {
            return ERROR_INVALID_TRANSACTION;
        }
        if (cbor_value_get_next_byte(&value) != end) {
            return ERROR_INVALID_TRANSACTION;
        }
        if (!cbor_argument_is_canonical(n)) {
            return ERROR_INVALID_TRANSACTION;
        }
        cbor_set_type_label("Negative integer");
        ctx->display[0] = '-';
        if (n == UINT64_MAX) {
            // -(UINT64_MAX+1) overflows uint64; render as "-18446744073709551615 - 1".
            bin_to_dec(ctx->display + 1, sizeof(ctx->display) - 1, n);
            memmove(ctx->display + 1 + UINT64_MAX_DECIMAL_DIGITS, " - 1", 4);
            ctx->display[1 + UINT64_MAX_DECIMAL_DIGITS + 4] = '\0';
        } else {
            bin_to_dec(ctx->display + 1, sizeof(ctx->display) - 1, n + 1);
        }

    } else if (cbor_value_is_text_string(&value)) {
        // An indefinite-length string is a sequence of chunks with no single canonical form,
        // so the review could not name one byte string the user is authorising.
        if (!cbor_value_is_length_known(&value)) {
            return ERROR_UNSUPPORTED_CBOR;
        }

        err = cbor_value_begin_string_iteration(&value);
        if (err != CborNoError) {
            return ERROR_INVALID_TRANSACTION;
        }

        const char *ptr;
        size_t len;
        CborValue next;
        err = cbor_value_get_text_string_chunk(&value, &ptr, &len, &next);
        if (err != CborNoError) {
            return ERROR_INVALID_TRANSACTION;
        }
        // next.source.ptr is positioned just past the string bytes; compare to buffer end.
        if (cbor_value_get_next_byte(&next) != end) {
            return ERROR_INVALID_TRANSACTION;
        }
        if (!cbor_argument_is_canonical(len)) {
            return ERROR_INVALID_TRANSACTION;
        }
        // Refused rather than trimmed: the blob is hashed in full, so showing a prefix would
        // have the user approve bytes the screen never rendered. Unreachable while callers cap
        // the blob at MAX_CBOR_BLOB_SIZE, kept for callers that do not.
        if (len > MAX_CBOR_STRING_SIZE) {
            return ERROR_INVALID_TRANSACTION;
        }
        // The text is hashed in full but shown as a C string, so bytes that cannot be
        // rendered are refused instead of being signed unseen.
        if (!is_displayable_text((const uint8_t *) ptr, len)) {
            return ERROR_INVALID_TRANSACTION;
        }
        cbor_set_type_label("Text");
        if (len > 0) {
            memmove(ctx->display, ptr, len);
        }
        ctx->display[len] = '\0';
        ctx->displayLen = (uint8_t) len;

    } else {
        return ERROR_UNSUPPORTED_CBOR;
    }

    return SWO_SUCCESS;
}

uint16_t readCborInitial(uint8_t *cdata, uint8_t dataLength) {
    /* dataLength guards the physical APDU buffer; cborLength guards the protocol-declared
     * stream total (set from a prior APDU) - both must have at least one byte, and the chunk
     * must not claim more than the stream declared. */
    if (dataLength < 1 || ctx->cborLength < 1) {
        THROW(SWO_INCORRECT_DATA);
    }
    if (dataLength > ctx->cborLength) {
        THROW(SWO_INCORRECT_DATA);
    }

    ctx->cborBufLen = 0;
    memmove(ctx->cborBuf, cdata, dataLength);
    ctx->cborBufLen = dataLength;
    ctx->cborLength -= dataLength;

    if (ctx->cborLength == 0) {
        return parse_complete_cbor();
    }
    return SWO_SUCCESS;
}

uint16_t readCborContent(uint8_t *cdata, uint8_t contentLength) {
    if (contentLength > ctx->cborLength) {
        THROW(SWO_INCORRECT_DATA);
    }
    // Defence-in-depth: callers already verify cborLength <= MAX_CBOR_BLOB_SIZE before
    // calling readCborInitial, so this guard is not reachable in current flows, but it
    // protects against future callers that omit the upfront length check.
    if (ctx->cborBufLen + contentLength > MAX_CBOR_BLOB_SIZE) {
        THROW(SWO_INCORRECT_DATA);
    }

    memmove(ctx->cborBuf + ctx->cborBufLen, cdata, contentLength);
    ctx->cborBufLen += contentLength;
    ctx->cborLength -= contentLength;

    if (ctx->cborLength == 0) {
        return parse_complete_cbor();
    }
    return SWO_SUCCESS;
}
