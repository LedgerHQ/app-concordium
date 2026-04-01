#pragma once

#include <parser.h>

/**
 * Handles the signing flow for the transfer with schedule account transaction.
 * Command data: see /doc/ins_transfer_with_schedule.md. P1: 0x00 for the initial packet containing
 * key derivation path, account transaction header, transaction kind, recipient address and the
 * number of scheduled transfers to make, 0x01 when sending pairs of scheduled amounts.
 */
void handleSignTransferWithSchedule(const command_t *cmd,
                                    volatile unsigned int *flags,
                                    bool isInitialCall);

void handleSignTransferWithScheduleAndMemo(const command_t *cmd,
                                           volatile unsigned int *flags,
                                           bool isInitialCall);

typedef enum {
    TX_TRANSFER_WITH_SCHEDULE_INITIAL = 28,
    TX_TRANSFER_WITH_SCHEDULE_TRANSFER_PAIRS = 29,
    TX_TRANSFER_WITH_SCHEDULE_MEMO_START = 55,
    TX_TRANSFER_WITH_SCHEDULE_MEMO = 56,
} transferWithScheduleState_t;

typedef struct {
    uint8_t transactionType;
    transferWithScheduleState_t state;

    unsigned char displayStr[57];
    uint8_t remainingNumberOfScheduledAmounts;
    uint8_t scheduledAmountsInCurrentPacket;

    uint8_t displayAmount[30];
    uint8_t energy_amount_str[30];
    uint8_t displayTimestamp[25];

    tm time;

    // Buffer to hold the incoming databuffer so that we can iterate over it.
    uint8_t buffer[255];
    uint8_t pos;
} signTransferWithScheduleContext_t;

void processNextScheduledAmount(uint8_t *buffer);