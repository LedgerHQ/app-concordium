#pragma once

#include <stdbool.h>

#include <cx.h>

#include "app_sizes.h"
#include "derivation_path.h"

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

/**
 * The derivation path GET_PUBLIC_KEY is reviewing, pinned for the lifetime of that review.
 *
 * `global_derivation_path` is rewritten by every parse, so it cannot be what an approval derives
 * from: the key would be whatever the last writer put there rather than what the screen showed.
 * handle_get_public_key() copies the parsed path here once, and both the key drawn on screen and
 * the key sent on Accept come from this copy - so the reviewed path and the derived path are the
 * same object, not two reads of a mutable global.
 *
 * Being outside `instructionContext` is necessary but not sufficient on its own: unlike the
 * union, this is never zeroed, so the flag below is what stops a second request replacing the
 * pin while its review is still on screen.
 */
extern derivation_path_t global_reviewed_path;

/**
 * A GET_PUBLIC_KEY review is on screen and has not been answered.
 *
 * Set before the review is drawn and cleared once it is answered, so a second GET_PUBLIC_KEY
 * cannot re-enter the handler and swap the path under the user's finger. Without it the pin
 * above keeps display and signature consistent, but the host still chooses which of two paths
 * the user ends up consenting to.
 *
 * Deliberately not set for the public-key *comparison* screen: that one is shown after its reply
 * has gone out, and the app accepts further instructions while it is up by design.
 */
extern bool global_public_key_review_pending;
