#include "challenge.h"
#include "globals.h"
#include <lcx_rng.h>

void eraseChallenge(void) {
    explicit_bzero(&global.trustedNamePki.stored_challenge, sizeof(uint64_t));
}

uint64_t getStoredChallenge(void) {
    return U8BE((const uint8_t *) &global.trustedNamePki.stored_challenge, 0);
}

void handleGetChallenge(void) {
    uint8_t buf[CHALLENGE_SIZE];
    cx_rng_no_throw(buf, sizeof(buf));

    /* Overwrites any previous challenge. Interleaved flows that reuse instructionContext
     * `global` can also wipe stored_challenge — see trustedNamePki.h (stored_challenge). */
    memcpy(&global.trustedNamePki.stored_challenge, buf, CHALLENGE_SIZE);

    memcpy(G_io_apdu_buffer, buf, CHALLENGE_SIZE); /* big-endian output */
    io_send_response_pointer(G_io_apdu_buffer, CHALLENGE_SIZE, SWO_SUCCESS);
}
