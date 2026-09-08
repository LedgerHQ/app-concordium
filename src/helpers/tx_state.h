#pragma once

#include <cx.h>

#include "app_sizes.h"

/** Hashing + multi-step APDU flow state (not part of `instructionContext` union). */
typedef struct {
    cx_sha256_t hash;
    uint8_t transactionHash[COMMON_HASH_SIZE];
    int currentInstruction;
} tx_state_t;

/** Account fields from parsed transaction header (UI). */
typedef struct {
    uint8_t sender[COMMON_ADDRESS_SIZE];
    /**
     * Signed `energy_amount` as decimal text. This cost ceiling is covered by the transaction
     * hash, unlike the host-supplied fee estimate, so every account-transaction review shows it.
     */
    uint8_t energyDisplay[ENERGY_DISPLAY_SIZE];
} accountSender_t;

extern accountSender_t global_account_sender;
