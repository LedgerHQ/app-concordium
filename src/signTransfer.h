#pragma once

#include <parser.h>

/**
 * Handles the signing flow, including updating the display, for the 'simple transfer'
 * account transaction. Command data: see /doc/ins_transfer.md.
 */
void handleSignTransfer(const command_t *cmd, volatile unsigned int *flags);

/**
 * Handles the signing flow, including updating the display, for the 'simple transfer with memo'
 * account transaction. Command data: see /doc/ins_transfer.md.
 */
void handleSignTransferWithMemo(const command_t *cmd,
                                volatile unsigned int *flags,
                                bool isInitialCall);

typedef enum {
    TX_TRANSFER_INITIAL = 49,
    TX_TRANSFER_MEMO_INITIAL = 50,
    TX_TRANSFER_MEMO = 51,
    TX_TRANSFER_AMOUNT = 52
} simpleTransferState_t;

typedef struct {
    unsigned char displayStr[57];
    uint8_t displayAmount[30];
    uint8_t energy_amount_str[30];
    simpleTransferState_t state;
} signTransferContext_t;
