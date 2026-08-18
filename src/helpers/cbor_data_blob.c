#include "cbor_data_blob.h"
#include "globals.h"

#include <string.h>
#include <os.h>
#include <status_words.h>

#include "cbor.h"
#include "numberHelpers.h"

#define UINT64_MAX_DECIMAL_DIGITS 20

_Static_assert(MAX_CBOR_STRING_SIZE <= UINT8_MAX,
               "MAX_CBOR_STRING_SIZE exceeds UINT8_MAX: widen cborContext_t.displayLen");

// A single APDU chunk is at most 255 bytes (uint8_t limit); the buffer must be larger so
// accumulation across chunks can never overflow on the very first chunk alone.
_Static_assert(MAX_CBOR_BLOB_SIZE > 255,
               "MAX_CBOR_BLOB_SIZE must exceed 255 to safely accumulate multi-chunk payloads");

static cborContext_t *ctx = &global.withDataBlob.cborContext;

// Parse the fully-accumulated cborBuf via tinycbor and populate ctx->display/displayLen.
// Supports major types 0 (uint), 1 (negint), 3 (text string, trimmed to MAX_CBOR_STRING_SIZE).
static void parse_complete_cbor(void) {
    CborParser parser;
    CborValue value;
    CborError err = cbor_parser_init(ctx->cborBuf, ctx->cborBufLen, 0, &parser, &value);
    if (err != CborNoError) THROW(SWO_INCORRECT_DATA);

    ctx->displayLen = 0;

    // After advance_fixed, cbor_value_get_next_byte returns source.ptr positioned just past
    // the integer's encoded bytes. Comparing it to the buffer end detects trailing bytes.
    // (cbor_value_at_end checks remaining==0 which is always true for a top-level item.)
    if (cbor_value_is_unsigned_integer(&value)) {
        uint64_t n;
        err = cbor_value_get_uint64(&value, &n);
        if (err != CborNoError) THROW(SWO_INCORRECT_DATA);
        err = cbor_value_advance_fixed(&value);
        if (err != CborNoError) THROW(SWO_INCORRECT_DATA);
        if (cbor_value_get_next_byte(&value) != ctx->cborBuf + ctx->cborBufLen)
            THROW(SWO_INCORRECT_DATA);
        bin_to_dec(ctx->display, sizeof(ctx->display), n);

    } else if (cbor_value_is_negative_integer(&value)) {
        uint64_t n;
        err = cbor_value_get_raw_integer(&value, &n);
        if (err != CborNoError) THROW(SWO_INCORRECT_DATA);
        err = cbor_value_advance_fixed(&value);
        if (err != CborNoError) THROW(SWO_INCORRECT_DATA);
        if (cbor_value_get_next_byte(&value) != ctx->cborBuf + ctx->cborBufLen)
            THROW(SWO_INCORRECT_DATA);
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
        if (!cbor_value_is_length_known(&value)) THROW(ERROR_UNSUPPORTED_CBOR);

        err = cbor_value_begin_string_iteration(&value);
        if (err != CborNoError) THROW(SWO_INCORRECT_DATA);

        const char *ptr;
        size_t len;
        CborValue next;
        err = cbor_value_get_text_string_chunk(&value, &ptr, &len, &next);
        if (err != CborNoError) THROW(SWO_INCORRECT_DATA);
        // next.source.ptr is positioned just past the string bytes; compare to buffer end.
        if (cbor_value_get_next_byte(&next) != ctx->cborBuf + ctx->cborBufLen)
            THROW(SWO_INCORRECT_DATA);

        size_t copy_len = (len > MAX_CBOR_STRING_SIZE) ? MAX_CBOR_STRING_SIZE : len;
        if (copy_len > 0) memmove(ctx->display, ptr, copy_len);
        ctx->display[copy_len] = '\0';
        ctx->displayLen = (uint8_t) copy_len;

    } else {
        THROW(ERROR_UNSUPPORTED_CBOR);
    }
}

void readCborInitial(uint8_t *cdata, uint8_t dataLength) {
    if (dataLength < 1 || ctx->cborLength < 1) THROW(SWO_INCORRECT_DATA);
    if (dataLength > ctx->cborLength) THROW(SWO_INCORRECT_DATA);

    ctx->cborBufLen = 0;
    memmove(ctx->cborBuf, cdata, dataLength);
    ctx->cborBufLen = dataLength;
    ctx->cborLength -= dataLength;

    if (ctx->cborLength == 0) parse_complete_cbor();
}

void readCborContent(uint8_t *cdata, uint8_t contentLength) {
    if (contentLength > ctx->cborLength) THROW(SWO_INCORRECT_DATA);
    // Defence-in-depth: callers already verify cborLength <= MAX_CBOR_BLOB_SIZE before
    // calling readCborInitial, so this guard is not reachable in current flows, but it
    // protects against future callers that omit the upfront length check.
    if (ctx->cborBufLen + contentLength > MAX_CBOR_BLOB_SIZE) THROW(SWO_INCORRECT_DATA);

    memmove(ctx->cborBuf + ctx->cborBufLen, cdata, contentLength);
    ctx->cborBufLen += contentLength;
    ctx->cborLength -= contentLength;

    if (ctx->cborLength == 0) parse_complete_cbor();
}
