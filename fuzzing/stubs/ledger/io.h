#pragma once

#include <stdint.h>

/* APDU I/O buffer (mirrors Ledger SDK G_io_apdu_buffer) */
#define IO_APDU_BUFFER_SIZE 260
extern uint8_t G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define IO_ASYNCH_REPLY 0
