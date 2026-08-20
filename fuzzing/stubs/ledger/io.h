#pragma once

#include <stdint.h>

/* APDU I/O buffer (mirrors Ledger SDK G_io_apdu_buffer) */
#define IO_APDU_BUFFER_SIZE 260
extern uint8_t G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define IO_ASYNCH_REPLY 0

/* Stub for Ledger SDK io_send_sw (normally sends a status-word APDU response).
 * sign_plt.c calls this directly; all other fuzzed handlers go through the
 * apdu_response.c wrappers which are already no-op'd in stubs.c. */
static inline int io_send_sw(uint16_t sw) {
    (void)sw;
    return 0;
}
