#pragma once

#include <stddef.h>
#include <stdint.h>

/* APDU I/O buffer (mirrors Ledger SDK G_io_apdu_buffer) */
#define IO_APDU_BUFFER_SIZE 260
extern uint8_t G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define IO_ASYNCH_REPLY 0

/*
 * The two transport entry points reached through the real dispatcher: apdu_dispatcher() answers
 * its own validation failures with io_send_sw(), and the query handlers it routes to reply with
 * io_send_response_pointer(). Everything else in the app goes through src/apdu/apdu_response.c,
 * which is stubbed as a whole.
 *
 * The pointer is typed void so that APPNAME - a plain char array - does not trip -Wpointer-sign
 * here. The device build has the same char/uint8_t mismatch and simply does not enable that
 * warning; keeping the fuzz build clean is worth more than mirroring the SDK prototype exactly.
 */
int io_send_sw(uint16_t sw);
int io_send_response_pointer(const void *ptr, size_t len, uint16_t sw);
