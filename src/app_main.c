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
    global_tx_state.currentInstruction = INSTRUCTION_NONE;
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

        // Dispatch structured APDU command
        BEGIN_TRY {
            TRY {
                if (apdu_dispatcher(&cmd, &flags, isInitialCall) < 0) {
                    PRINTF("=> apdu_dispatcher failure\n");
                    return;
                }
            }
            CATCH_OTHER(e) {
                global_tx_state.currentInstruction = INSTRUCTION_NONE;
                io_send_sw(e);
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}
