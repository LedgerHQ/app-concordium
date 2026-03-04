#include "challenge.h"
#include "globals.h"
#include <lcx_rng.h>

static uint64_t *challenge = &global.exportPublicKeyContext.random_challenge;

void eraseChallenge(void) {
    explicit_bzero(challenge, sizeof(*challenge));
}

void handleGetChallenge(void) {
    uint8_t buf[CHALLENGE_SIZE];
    cx_rng_no_throw(buf, sizeof(buf));

    memcpy(challenge, buf, CHALLENGE_SIZE);        /* persist for later use */
    memcpy(G_io_apdu_buffer, buf, CHALLENGE_SIZE); /* big-endian output */
    io_send_response_pointer(G_io_apdu_buffer, CHALLENGE_SIZE, SWO_SUCCESS);
}
