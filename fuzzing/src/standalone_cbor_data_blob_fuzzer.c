/*
 * Fuzzer for readCborInitial / readCborContent (cbor_data_blob.c).
 * Input: [cborLength:2][p1:1][data...]
 *   cborLength (BE uint16, clamped to MAX_CBOR_BLOB_SIZE) — primes ctx->cborLength
 *   to mirror what the real APDU handler does before calling readCborInitial.
 *   p1 == 0 → call readCborInitial only
 *   p1 != 0 → call readCborInitial then readCborContent with the rest
 */
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "helpers/cbor_data_blob.h"
#include "instruction_context.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    if (setjmp(g_fuzzer_jmp_buf) != 0) return 0;

    uint16_t cbor_len = ((uint16_t) data[0] << 8) | data[1];
    if (cbor_len > MAX_CBOR_BLOB_SIZE) cbor_len = MAX_CBOR_BLOB_SIZE;

    // Prime the CBOR context — mirrors what the real APDU handler sets before
    // calling readCborInitial (without this, cborLength==0 and the guard throws
    // on every input, making the fuzzer completely inert).
    // readCborInitial resets all other streaming state fields internally.
    global.withDataBlob.cborContext.cborLength = cbor_len;

    uint8_t p1 = data[2];
    uint8_t *payload = (uint8_t *) (data + 3);
    uint8_t payload_len = (uint8_t) ((size - 3) > 255 ? 255 : (size - 3));

    readCborInitial(payload, payload_len);

    if (p1 != 0 && payload_len > 0) {
        readCborContent(payload, payload_len);
    }

    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
