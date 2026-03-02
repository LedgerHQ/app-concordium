#include "challenge.h"
#include "globals.h"
#include <lcx_rng.h>

static uint64_t g_challenge;

void eraseChallenge(void) {
    explicit_bzero(&g_challenge, sizeof(g_challenge));
}

void handleGetChallenge(void) {
    uint8_t buf[CHALLENGE_SIZE];
    cx_rng_no_throw(buf, sizeof(buf));

    g_challenge = ((uint64_t) buf[0] << 56) | ((uint64_t) buf[1] << 48) |
                  ((uint64_t) buf[2] << 40) | ((uint64_t) buf[3] << 32) |
                  ((uint64_t) buf[4] << 24) | ((uint64_t) buf[5] << 16) |
                  ((uint64_t) buf[6] << 8) | (uint64_t) buf[7];

    G_io_apdu_buffer[0] = (g_challenge >> 56) & 0xFF;
    G_io_apdu_buffer[1] = (g_challenge >> 48) & 0xFF;
    G_io_apdu_buffer[2] = (g_challenge >> 40) & 0xFF;
    G_io_apdu_buffer[3] = (g_challenge >> 32) & 0xFF;
    G_io_apdu_buffer[4] = (g_challenge >> 24) & 0xFF;
    G_io_apdu_buffer[5] = (g_challenge >> 16) & 0xFF;
    G_io_apdu_buffer[6] = (g_challenge >> 8) & 0xFF;
    G_io_apdu_buffer[7] = g_challenge & 0xFF;

    io_send_response_pointer(G_io_apdu_buffer, CHALLENGE_SIZE, SUCCESS);
}
