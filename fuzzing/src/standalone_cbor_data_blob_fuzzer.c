/*
 * Fuzzer for readCborInitial / readCborContent (cbor_data_blob.c).
 * Input: [p1:1][data...]
 *   p1 == 0 → call readCborInitial only
 *   p1 != 0 → call readCborInitial then readCborContent with the rest
 */
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "helpers/cbor_data_blob.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    if (setjmp(g_fuzzer_jmp_buf) != 0) return 0;

    uint8_t p1 = data[0];
    uint8_t *payload = (uint8_t *) (data + 1);
    uint8_t payload_len = (uint8_t) ((size - 1) > 255 ? 255 : (size - 1));

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
