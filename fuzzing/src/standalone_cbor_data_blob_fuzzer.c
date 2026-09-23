/*
 * Fuzzer for readCborInitial / readCborContent (cbor_data_blob.c).
 *
 * Input: [control:1][declared_cbor_length:2 BE][data...]
 *   control bit 0 → keep feeding the remaining bytes through readCborContent
 *
 * declared_cbor_length seeds cborContext.cborLength, the protocol-declared total that a signing
 * handler sets before it starts parsing. The parser rejects cborLength < 1 on entry, so leaving
 * it at zero - as this harness used to - made every single input throw immediately and the
 * target covered nothing at all. Seeding it from the input also lets the fuzzer explore the
 * declared-length / physical-length mismatches that finding V-077 was about.
 *
 * The seed is two bytes because the blob is now accumulated whole and parsed once at the end:
 * MAX_CBOR_BLOB_SIZE does not fit in a uint8, and a one-byte seed could never reach the
 * multi-chunk accumulation path where the parse actually runs.
 */
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "../stubs/ledger/status_words.h"
#include "fuzz_state.h"
#include "helpers/cbor_data_blob.h"
#include "instruction_context.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    if (setjmp(g_fuzzer_jmp_buf) != 0) return 0;

    fuzz_reset_app_state();

    uint8_t control = data[0];
    uint16_t declared = ((uint16_t) data[1] << 8) | data[2];
    if (declared > MAX_CBOR_BLOB_SIZE) declared = MAX_CBOR_BLOB_SIZE;
    global.withDataBlob.cborContext.cborLength = declared;

    uint8_t *payload = (uint8_t *) (data + 3);
    size_t remaining = size - 3;
    uint8_t chunk = (uint8_t) (remaining > UINT8_MAX ? UINT8_MAX : remaining);

    // Both entry points now report refusal by status word rather than throwing, so a rejected
    // header must stop the sequence here exactly as the handlers do.
    if (readCborInitial(payload, chunk) != SWO_SUCCESS) {
        return 0;
    }
    payload += chunk;
    remaining -= chunk;

    // The buffer is parsed only once cborLength reaches 0, so keep feeding chunks the way a
    // handler does; a single call could never reach the parse on a multi-packet payload.
    while ((control & 1) != 0 && remaining > 0 && global.withDataBlob.cborContext.cborLength > 0) {
        chunk = (uint8_t) (remaining > UINT8_MAX ? UINT8_MAX : remaining);
        if (readCborContent(payload, chunk) != SWO_SUCCESS) {
            return 0;
        }
        payload += chunk;
        remaining -= chunk;
    }

    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
