/*******************************************************************************
 *
 *   (c) 2016 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "globals.h"

#include <string.h>

#include <io.h>
#include <os.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/dispatcher.h"
#include "menu.h"

/**
 * Instruction class of the Concordium application.
 */
#define CLA 0xE0

/**
 * Run one dispatch, converting a thrown status word into a reply instead of an app exit.
 *
 * Handlers report attacker-controlled input errors with THROW(...) - an unknown instruction,
 * a bad path, a length that does not add up. THROW is os_longjmp, and the only handler above
 * this point is the SDK's own in standalone_app_main(), which *exits the application*. So a
 * single malformed APDU used to drop the user to the dashboard, and repeating it kept the app
 * unavailable and aborted any signing flow in progress (finding V-006).
 *
 * Catching here rather than converting each THROW is deliberate: a fuzz run over the real
 * parser and dispatcher reached 70 distinct THROW sites in 20 files within 90 seconds, out of
 * 282 in the tree, so no per-site conversion closes this while any THROW remains reachable.
 * This guard closes it for every THROW reachable from a dispatch at once.
 *
 * SCOPE: dispatch only. This wraps apdu_dispatcher() and nothing else, so it does not cover the
 * UI approval callbacks - those are invoked from the BOLOS UX loop, long after END_TRY below has
 * popped this context, and a THROW from one of them unwinds straight to the SDK handler in
 * standalone_app_main() and exits the app, the same failure reached from the approve button
 * instead of from an APDU. Nearly every continuation can get there, so the two display backends
 * run them through ux_run_guarded() (helpers/ux_guard.c), which is this function's counterpart
 * for that side and ends a caught flow the same way. Between the two the guarantee is global:
 * no status word thrown anywhere in the app exits it.
 *
 * Converting a THROW at its site stays the preferred style for new code where the answer is
 * local - readCborInitial, readCborContent, send_rejection, and
 * exportNewPathPrivateKeysForPurpose(), which returns the status word its derivation threw
 * rather than leaning on the catch above it.
 *
 * A caught exception ends the flow: the instruction is released and the context union wiped, so
 * a host cannot resume a half-parsed transaction with the next packet, and no partially parsed
 * material stays in RAM. That mirrors what send_rejection() does for a handler-level refusal.
 */
static void dispatch_guarded(const command_t *cmd,
                             volatile unsigned int *flags,
                             bool isInitialCall) {
    /* Written inside TRY and read after it, so both must survive the longjmp. */
    volatile uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            (void) apdu_dispatcher(cmd, flags, isInitialCall);
        }
        CATCH_OTHER(e) {
            if ((unsigned int) e <= MAX_SYSTEM_EXCEPTION) {
                /* EXCEPTION_IO_RESET and friends: the SDK has to see these. */
                THROW(e);
            }
            sw = (uint16_t) e;
        }
        FINALLY {
        }
    }
    END_TRY;

    if (sw != 0) {
        PRINTF("=> handler threw %04X, replying instead of exiting\n", sw);
        explicit_bzero(&global, sizeof(global));
        global_tx_state.currentInstruction = INSTRUCTION_NONE;
        *flags = 0;
        io_send_sw(sw);
    }
}

// Main entry of application that listens for APDU commands that will be received from the
// computer. The APDU commands control what flow is activated, i.e. which control flow is initiated.
void app_main() {
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;
    volatile unsigned int flags = 0;

    // Structured APDU command
    command_t cmd;
    io_init();
    explicit_bzero(&global_tx_state, sizeof(global_tx_state));
    ui_menu_main();

    for (;;) {
        // Receive command bytes in G_io_apdu_buffer
        if ((input_len = io_recv_command()) < 0) {
            PRINTF("=> io_recv_command failure\n");
            return;
        }

        // Parse APDU command from G_io_apdu_buffer
        if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
            PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
            io_send_sw(SWO_WRONG_DATA_LENGTH);
            continue;
        }

        PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
               cmd.cla,
               cmd.ins,
               cmd.p1,
               cmd.p2,
               cmd.lc,
               cmd.lc,
               cmd.data);

        if (cmd.cla != CLA) {
            io_send_sw(SWO_INVALID_CLA);
            continue;
        }

        bool isInitialCall = false;
        if (global_tx_state.currentInstruction == INSTRUCTION_NONE) {
            explicit_bzero(&global, sizeof(global));
            global_tx_state.currentInstruction = cmd.ins;
            isInitialCall = true;
        }

        // Dispatch structured APDU command. A thrown status word is answered and the loop
        // continues; only a BOLOS system exception still leaves this function.
        dispatch_guarded(&cmd, &flags, isInitialCall);
    }
}
