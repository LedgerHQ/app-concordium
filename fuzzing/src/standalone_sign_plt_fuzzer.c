/*
 * Fuzzer for handle_sign_plt (INS 0x27 — PLT signing).
 *
 * Two-invocation structure to exercise both the INIT path and the CBOR CONT
 * path in a single fuzzer run:
 *   1. Call with isInitialCall=true and fuzz data (exercises INIT parsing).
 *   2. If INIT succeeded (state == TX_PLT_CBOR), call again with P1=CONT and
 *      the remaining fuzz bytes (exercises CBOR accumulation and parse_plt_cbor).
 *
 * Input layout: [p1:1][p2:1][init_lc:1][init_data: init_lc bytes][cont_data: rest]
 * Keeping P1/P2 fuzzable lets the fuzzer also hit the error paths (wrong P1,
 * wrong P2, CONT-before-INIT).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "../stubs/ledger/parser.h"
#include "instruction_context.h"
#include "handler/sign_plt.h"
#include "tx_state.h"

extern instructionContext global;
extern tx_state_t global_tx_state;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;

    volatile unsigned int flags = 0;
    command_t cmd;

    /* Reset all global state before each run. */
    memset(&global, 0, sizeof(global));
    memset(&global_tx_state, 0, sizeof(global_tx_state));

    /* --- First call: always starts fresh (isInitialCall = true) --- */
    uint8_t p1 = data[0];
    uint8_t p2 = data[1];
    uint8_t init_lc = data[2];

    size_t init_data_end = 3u + (size_t) init_lc;
    if (init_data_end > size) init_data_end = size;

    cmd.p1 = p1;
    cmd.p2 = p2;
    cmd.lc = (uint8_t) (init_data_end - 3u);
    cmd.data = (uint8_t *) (data + 3);

    if (setjmp(g_fuzzer_jmp_buf) == 0) {
        handle_sign_plt(&cmd, &flags, /*isInitialCall=*/true);
    }

    /* --- Second call: CONT, only if INIT set state to TX_PLT_CBOR --- */
    if (global.signPlt.state != TX_PLT_CBOR) return 0;
    if (init_data_end >= size) return 0;

    size_t cont_avail = size - init_data_end;
    cmd.p1 = 0x01; /* PLT_P1_CONT */
    cmd.p2 = 0x00;
    cmd.lc = (uint8_t) (cont_avail > 255u ? 255u : cont_avail);
    cmd.data = (uint8_t *) (data + init_data_end);

    if (setjmp(g_fuzzer_jmp_buf) == 0) {
        handle_sign_plt(&cmd, &flags, /*isInitialCall=*/false);
    }

    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
