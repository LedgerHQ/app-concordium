#pragma once

#include <parser.h>

/**
 * Handles the signing flow, including updating the display, for the 'transfer to public'
 * account transaction. Command data: see /doc/ins_transfer_to_public.md.
 */
void handleSignTransferToPublic(const command_t *cmd,
                                volatile unsigned int *flags,
                                bool isInitialCall);

typedef enum {
    TX_TRANSFER_TO_PUBLIC_INITIAL = 25,
    TX_TRANSFER_TO_PUBLIC_REMAINING_AMOUNT = 26,
    TX_TRANSFER_TO_PUBLIC_PROOF = 27
} transferToPublicState_t;

typedef struct {
    uint8_t amount[30];
    uint8_t recipientAddress[57];
    uint16_t proofSize;
    transferToPublicState_t state;
} signTransferToPublic_t;
