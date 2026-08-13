#pragma once

#include <stdint.h>

#ifdef HAVE_BAGL
#include <ux.h>

extern const ux_flow_step_t ux_sign_flow_shared_review;
extern const ux_flow_step_t ux_sign_flow_shared_sign;
extern const ux_flow_step_t ux_sign_flow_shared_decline;
extern const ux_flow_step_t *const ux_sign_flow_shared[];

#endif

/**
 * Accumulate the first APDU chunk of a CBOR-encoded data blob into cborContext.cborBuf.
 * The caller must have set cborContext.cborLength to the total declared wire length before
 * this call. Supports major types 0, 1, and 3 (unsigned int, negative int, UTF-8 string).
 * Text longer than MAX_CBOR_STRING_SIZE is trimmed. When cborLength reaches 0 after this call,
 * tinycbor parses the complete buffer and cborContext.display is ready for display.
 */
void readCborInitial(uint8_t *cdata, uint8_t dataLength);
/**
 * Accumulate a subsequent APDU chunk into cborContext.cborBuf. Must follow readCborInitial.
 * May be called any number of times until cborLength reaches 0. When cborLength reaches 0,
 * tinycbor parses the complete accumulated buffer and cborContext.display is ready for display.
 * Hashing is the caller's responsibility and is unaffected by any text trimming.
 */
void readCborContent(uint8_t *cdata, uint8_t dataLength);

// MAX_CBOR_BLOB_SIZE / MAX_DATA_SIZE are defined in app_sizes.h (included via globals.h)
