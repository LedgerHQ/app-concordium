#include "globals.h"

#include <string.h>

#include <os.h>
#include <io.h>

#include "menu.h"
#include "ux_guard.h"

void ux_run_guarded(void (*continuation)(void)) {
    if (!continuation) {
        return;
    }

    /* Written inside TRY and read after it, so both must survive the longjmp. */
    volatile uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            continuation();
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
        PRINTF("=> approval callback threw %04X, replying instead of exiting\n", sw);
        explicit_bzero(&global, sizeof(global));
        global_tx_state.currentInstruction = INSTRUCTION_NONE;
        io_send_sw(sw);
        /* The review this continuation belonged to is dead, so do not leave it on screen. */
        ui_menu_main();
    }
}
