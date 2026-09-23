/*
 * Fuzzer for handle_init_contract.
 * Input: [p1:1][p2:1][control:1][command data...]
 *   control bit 0 -> isInitialCall
 *   control bit 1 -> approve the review screen the handler parks, rather than reject it.
 *                    Answering it runs the production continuation - hash finalisation and
 *                    signing, a key release, the next scheduled pair - which no harness
 *                    reached while the UI stubs were empty (finding V-102).
 */
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "../stubs/ledger/parser.h"
#include "fuzz_state.h"
#include "fuzz_ui.h"
#include "handler/init_contract.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    if (setjmp(g_fuzzer_jmp_buf) != 0) return 0;

    fuzz_reset_app_state();

    command_t cmd = fuzz_make_command(INS_INIT_CONTRACT, data[0], data[1], data + 3, size - 3);
    // Bit 0 of the control byte drives isInitialCall, so the harness can also enter a
    // handler as a continuation packet rather than always as the first one.
    bool isInitialCall = (data[2] & 1) != 0;

    handle_init_contract(&cmd, isInitialCall);
    /* Answer the review screen as the user would (finding V-102). */
    fuzz_answer_pending_ui((data[2] & 2) != 0);

    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
