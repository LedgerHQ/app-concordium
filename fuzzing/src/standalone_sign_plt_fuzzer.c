/*
 * Fuzzer for handle_sign_plt (INS 0x27 — PLT signing).
 *
 * Structure of a run:
 *   1. Call with isInitialCall=true and fuzz data (exercises INIT parsing).
 *   2. If INIT succeeded (state == TX_PLT_CBOR), feed the remaining fuzz bytes as a
 *      sequence of CONT frames (exercises CBOR accumulation and parse_plt_cbor).
 *
 * The CONT calls have to loop. A single frame is capped at 255 bytes by the APDU Lc, while
 * APP_PLT_CBOR_MAX is 512, so one call left every payload above 255 bytes unreachable --
 * parse_plt_cbor only runs once cborReceived == cborTotalLength -- and the accumulating
 * memmove in the handler never ran at a non-zero offset.
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

    /* --- CONT frames, only if INIT set state to TX_PLT_CBOR ---
     *
     * volatile because they are modified between one iteration's setjmp and the next
     * longjmp; a non-volatile local would be indeterminate after the jump.
     *
     * The loop ends when the handler refuses (any refusal resets state to TX_PLT_INITIAL) or
     * the input runs out. It always advances: chunk is at least 1 while offset < size. Frames
     * past a completed payload are deliberately still sent -- the handler refuses them, which
     * is the "extra data after the declared total" path. */
    volatile size_t offset = init_data_end;

    while (offset < size && global.signPlt.state == TX_PLT_CBOR) {
        size_t cont_avail = size - offset;
        volatile uint8_t chunk = (uint8_t) (cont_avail > MAX_CDATA_LENGTH ? MAX_CDATA_LENGTH
                                                                          : cont_avail);

        cmd.p1 = 0x01; /* PLT_P1_CONT */
        cmd.p2 = 0x00;
        cmd.lc = chunk;
        cmd.data = (uint8_t *) (data + offset);

        if (setjmp(g_fuzzer_jmp_buf) == 0) {
            handle_sign_plt(&cmd, &flags, /*isInitialCall=*/false);
        }

        offset += chunk;
    }

    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
