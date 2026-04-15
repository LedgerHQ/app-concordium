#pragma once

#include <parser.h>

#include "instruction_context.h"

/**
 * Scheduled-transfer-with-schedule context (lives in `instructionContext`) and parsing helpers.
 * Used by `handler/sign_transfer_with_schedule.c` and `sign_transfer_with_schedule_and_memo.c`.
 */

void processNextScheduledAmount(uint8_t *buffer);
void handle_transfer_pairs(uint8_t *cdata, uint8_t dataLength, volatile unsigned int *flags);
void finish_memo_scheduled(volatile unsigned int *flags);
