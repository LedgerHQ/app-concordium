#pragma once

#include <cx.h>

#include "app_sizes.h"

/** Hashing + multi-step APDU flow state (not part of `instructionContext` union). */
typedef struct {
    cx_sha256_t hash;
    uint8_t transactionHash[COMMON_HASH_SIZE];
    int currentInstruction;
} tx_state_t;

/** Account sender from parsed transaction header (UI). */
typedef struct {
    uint8_t sender[COMMON_ADDRESS_SIZE];
} accountSender_t;

extern accountSender_t global_account_sender;
