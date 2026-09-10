/*
 * Fuzzer for readCborInitial / readCborContent (cbor_data_blob.c).
 * Input: [control:1][declared_cbor_length:1][data...]
 *   control bit 0 → also call readCborContent with the remaining bytes
 *
 * declared_cbor_length seeds cborContext.cborLength, the protocol-declared total that a signing
 * handler sets before it starts parsing. The parser rejects cborLength < 1 on entry, so leaving
 * it at zero - as this harness used to - made every single input throw immediately and the
 * target covered nothing at all. Seeding it from the input also lets the fuzzer explore the
 * declared-length / physical-length mismatches that finding V-077 was about.
 */
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "../stubs/ledger/status_words.h"
#include "fuzz_state.h"
#include "helpers/cbor_data_blob.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    if (setjmp(g_fuzzer_jmp_buf) != 0) return 0;

    fuzz_reset_app_state();

    uint8_t control = data[0];
    global.withDataBlob.cborContext.cborLength = data[1];

    uint8_t *payload = (uint8_t *) (data + 2);
    uint8_t payload_len = (uint8_t) ((size - 2) > UINT8_MAX ? UINT8_MAX : (size - 2));

    // Both entry points now report refusal by status word rather than throwing, so a rejected
    // header must stop the sequence here exactly as the handlers do.
    if (readCborInitial(payload, payload_len) != SWO_SUCCESS) {
        return 0;
    }

    if ((control & 1) != 0 && payload_len > 0) {
        readCborContent(payload, payload_len);
    }

    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
