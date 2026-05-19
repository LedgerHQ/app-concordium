#include "get_challenge.h"
#include "globals.h"
#include "set_trusted_name.h"

#include <io.h>
#include <os.h>
#include <os_utils.h>
#include <status_words.h>
#include <lcx_rng.h>

/** Random challenge size in bytes (uint64_t) returned by GET_CHALLENGE. */
#define CHALLENGE_SIZE 8

void handle_get_challenge(void) {
    uint8_t buf[CHALLENGE_SIZE];
    cx_rng_no_throw(buf, sizeof(buf));

    g_stored_challenge = U8BE(buf, 0);

    memcpy(G_io_apdu_buffer, buf, CHALLENGE_SIZE);
    global_tx_state.currentInstruction = INSTRUCTION_NONE;
    io_send_response_pointer(G_io_apdu_buffer, CHALLENGE_SIZE, SWO_SUCCESS);
}
