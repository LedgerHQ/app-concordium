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
    /**
     * Network implied by the host-supplied signing path ("Mainnet", "Testnet", ...). Mainnet and
     * testnet prefixes are both authorized and Concordium addresses look identical on the two
     * networks, so without this row nothing on screen distinguishes them.
     */
    uint8_t network[NETWORK_DISPLAY_SIZE];
} accountSender_t;

extern accountSender_t global_account_sender;

/**
 * Text shown on the public-key comparison screen, held outside `instructionContext`.
 *
 * That screen appears after the response has already been sent, and the app deliberately keeps
 * accepting instructions while it is up — which zeroes and reuses the instruction union. Drawing
 * the screen straight from the union would let a host swap the key the user is comparing against,
 * so the values are copied here first and stay put until the user leaves the screen.
 */
typedef struct {
    uint8_t display[COMPARE_IDENTITY_DISPLAY_SIZE];
    char publicKey[COMPARE_PUBLIC_KEY_HEX_SIZE];
} comparePublicKey_t;

extern comparePublicKey_t global_compare_public_key;
