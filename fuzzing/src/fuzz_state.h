#pragma once

/*
 * Shared per-input setup for the standalone fuzz harnesses.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "globals.h"
#include "apdu/dispatcher.h"
#include "handler/set_trusted_name.h"

/* Instruction class of the Concordium application (mirrors app_main.c). */
#define FUZZ_CLA 0xE0

/*
 * Put the app's globals back to the state app_main() guarantees before a first APDU.
 *
 * libFuzzer reuses one process for every input, and a handler that threw part-way through a
 * multi-packet flow leaves its context, its state enum and the transaction hash populated. The
 * harnesses used to reset nothing, so each input inherited whatever the previous one left
 * behind: coverage depended on execution order and a reported crash could not be reproduced
 * from the single input libFuzzer saved. app_main() zeroes `global` when it starts a new
 * instruction, so doing the same here is what the device actually does.
 */
static inline void fuzz_reset_app_state(void) {
    memset(&global, 0, sizeof(global));
    memset(&global_tx_state, 0, sizeof(global_tx_state));
    memset(&global_derivation_path, 0, sizeof(global_derivation_path));
    memset(&global_account_sender, 0, sizeof(global_account_sender));
    memset(&global_compare_public_key, 0, sizeof(global_compare_public_key));

    global_tx_state.currentInstruction = INSTRUCTION_NONE;

    /* The trusted-name binding is volatile, single-use state in production. */
    g_trusted_name_valid = false;
    g_trusted_address_len = 0;
    g_trusted_chain_id = 0;
    memset(g_trusted_name, 0, sizeof(g_trusted_name));
    memset(g_trusted_address, 0, sizeof(g_trusted_address));
}

/*
 * Build a command_t the way apdu_parser() would.
 *
 * The harnesses used to leave `cla` and `ins` uninitialised, which is both an uninitialised
 * stack read in its own right and a silent divergence from production, where apdu_dispatcher()
 * only ever sees a command whose CLA was already validated and whose INS selected the handler.
 * `lc == 0` yields a NULL data pointer, matching the production parser's contract.
 */
/*
 * The BOLOS flags word handlers set to request an asynchronous reply. Harnesses that drive a
 * sequence need one that outlives a single call, so it lives here rather than on each stack.
 */
static volatile unsigned int g_fuzz_flags;

/*
 * What app_main() does when a frame opens a new instruction: clear the context union, then
 * claim the instruction. Kept separate from fuzz_reset_app_state() because a continuation
 * frame must NOT do this - preserving that state across frames is the whole point of the
 * dispatcher's instruction-switching guard.
 */
static inline void fuzz_reset_instruction_context(uint8_t ins) {
    memset(&global, 0, sizeof(global));
    global_tx_state.currentInstruction = ins;
}

static inline command_t fuzz_make_command(uint8_t ins,
                                          uint8_t p1,
                                          uint8_t p2,
                                          const uint8_t *data,
                                          size_t size) {
    command_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cla = FUZZ_CLA;
    cmd.ins = ins;
    cmd.p1 = p1;
    cmd.p2 = p2;
    cmd.lc = (uint8_t) (size > UINT8_MAX ? UINT8_MAX : size);
    cmd.data = (cmd.lc == 0) ? NULL : (uint8_t *) data;
    return cmd;
}
