/*
 * Fuzzer for handle_sign_public_information_for_ip.
 * Input: [p1:1][p2:1][command data...]
 */
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "../stubs/ledger/parser.h"
#include "handler/sign_public_information_for_ip.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    if (setjmp(g_fuzzer_jmp_buf) != 0) return 0;

    volatile unsigned int flags = 0;
    command_t cmd;
    cmd.p1 = data[0];
    cmd.p2 = data[1];
    cmd.lc = (uint8_t) ((size - 2) > 255 ? 255 : (size - 2));
    cmd.data = (uint8_t *) (data + 2);

    handle_sign_public_information_for_ip(&cmd, &flags, /*isInitialCall=*/true);
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
