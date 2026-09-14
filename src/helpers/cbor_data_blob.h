#pragma once

#include <stdint.h>

#ifdef HAVE_BAGL
#include <ux.h>

extern const ux_flow_step_t ux_sign_flow_shared_sign;
extern const ux_flow_step_t ux_sign_flow_shared_decline;
extern const ux_flow_step_t *const ux_sign_flow_shared[];

#endif

/**
 * Accumulate the first APDU chunk of a CBOR-encoded data blob into cborContext.cborBuf.
 * The caller must have set cborContext.cborLength to the total declared wire length before
 * this call. Supports major types 0, 1, and 3 (unsigned int, negative int, UTF-8 string).
 * When cborLength reaches 0 after this call, tinycbor parses the complete buffer and
 * cborContext.display / .typeLabel are ready for review.
 *
 * The parse refuses, rather than trims or redraws, anything the screen cannot show faithfully:
 * a non-shortest-form argument, bytes trailing a complete item, an indefinite-length string,
 * text beyond MAX_CBOR_STRING_SIZE, and non-displayable bytes. The blob is hashed in full, so
 * every one of those would have the user approve bytes the review never rendered.
 */
/** @return SWO_SUCCESS, or the status word to refuse the transaction with. */
uint16_t readCborInitial(uint8_t *cdata, uint8_t dataLength);
/**
 * Accumulate a subsequent APDU chunk into cborContext.cborBuf. Must follow readCborInitial.
 * May be called any number of times until cborLength reaches 0. When cborLength reaches 0,
 * tinycbor parses the complete accumulated buffer, applying the same refusals as
 * readCborInitial. Hashing is the caller's responsibility.
 */
/** @return SWO_SUCCESS, or the status word to refuse the transaction with. */
uint16_t readCborContent(uint8_t *cdata, uint8_t dataLength);

// MAX_CBOR_BLOB_SIZE / MAX_DATA_SIZE are defined in app_sizes.h (included via globals.h)
