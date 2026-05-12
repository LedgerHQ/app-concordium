#include "get_challenge.h"
#include "globals.h"

#include <string.h>

#include <io.h>
#include <os.h>
#include <status_words.h>
#include <lcx_rng.h>

/** Random challenge size in bytes (uint64_t) returned by GET_CHALLENGE. */
#define CHALLENGE_SIZE 8

void handle_get_challenge(void) {
    uint8_t buf[CHALLENGE_SIZE];
    cx_rng_no_throw(buf, sizeof(buf));

    /* Overwrites any previous challenge. Interleaved flows that reuse instructionContext
     * `global` can also wipe stored_challenge — see globals.h / trustedNamePkiContext_t. */
    memcpy(&global.trustedNamePki.stored_challenge, buf, CHALLENGE_SIZE);

    memcpy(G_io_apdu_buffer, buf, CHALLENGE_SIZE); /* big-endian output */
    global_tx_state.currentInstruction = INSTRUCTION_NONE;
    io_send_response_pointer(G_io_apdu_buffer, CHALLENGE_SIZE, SWO_SUCCESS);
}
