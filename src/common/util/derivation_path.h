#ifndef UTIL_DERIVATION_PATH_H
#define UTIL_DERIVATION_PATH_H

#include <stdint.h>
#include <stdbool.h>

#define KEY_PATH_NODE_BYTES        4
#define MIN_KEY_PATH_LENGTH        4
#define MAX_KEY_PATH_LENGTH        8
#define DERIVATION_PATH_NEW_LEN    5
#define DERIVATION_PATH_LEGACY_LEN 6
#define BYTES_PER_PATH_ELEMENT     4

#define LEGACY_PURPOSE        1105
#define LEGACY_COIN_TYPE      0
#define NEW_PURPOSE           44
#define NEW_MAINNET_COIN_TYPE 919
#define NEW_TESTNET_COIN_TYPE 1

#define LEGACY_ACCOUNT_SUBTREE 0
#define LEGACY_NORMAL_ACCOUNTS 0

/** Mask for the hardened bit (bit 31) */
#define HARDENED_BIT 0x80000000U

typedef enum {
    DERIVATION_PATH_VARIANT_LEGACY,
    DERIVATION_PATH_VARIANT_NEW,
    DERIVATION_PATH_VARIANT_FULL,
    DERIVATION_PATH_VARIANT_INVALID
} derivation_path_variant_t;

typedef struct derivation_path {
    uint8_t len;
    uint32_t nodes[MAX_KEY_PATH_LENGTH];
    derivation_path_variant_t variant;
} derivation_path_t;

typedef enum {
    LEGACY_ID_CRED_SEC = 0,
    LEGACY_PRF_KEY = 1,
    // New path
    NEW_ID_CRED_SEC = 2,
    NEW_PRF_KEY = 3,
    NEW_SIGNATURE_BLINDING_RANDOMNESS = 4,
    NEW_COMMITMENT_RANDOMNESS = 5,
} derivation_path_keys_t;

static inline derivation_path_t init_derivation_path() {
    derivation_path_t derivation_path = {.len = 0,
                                         .nodes = {0},
                                         .variant = DERIVATION_PATH_VARIANT_INVALID};
    return derivation_path;
}

static inline uint32_t cred_counter(derivation_path_t *derivation_path) {
    return derivation_path->nodes[derivation_path->len];
}

static inline void trim_last_node(derivation_path_t *derivation_path) {
    derivation_path->len -= 1;
}

void parse_derivation_path_full(uint8_t lc, uint8_t *cdata, derivation_path_t *derivation_path_out);

/**
 * Parse new path format: identityProvider[uint32] identity[uint32] credCounter[uint32].
 *
 * Builds PRF path 44/coinType/identityProvider/identity/3.
 *
 * @param lc               Length of cdata (must be 12)
 * @param cdata            APDU command data
 * @param mainnet          true for mainnet (919), false for testnet (1)
 * @param path_out         Output buffer for the 5-element PRF derivation path, not hardened
 * @param cred_counter_out Output credential counter / account index
 *
 * @throws SWO_WRONG_DATA_LENGTH if lc != 12
 */
void parse_derivation_path_new(uint8_t lc,
                               uint8_t *cdata,
                               bool mainnet,
                               derivation_path_t *path_out,
                               uint32_t *cred_counter_out);

/**
 * Parse legacy path format: identity[uint32] credCounter[uint32].
 *
 * Builds PRF path 1105'/0'/0'/0'/identity'/1'.
 *
 * @param lc           Length of cdata (must be 8)
 * @param cdata        APDU command data
 * @param prf_key_path Output buffer for the 6-element PRF derivation path, not hardened
 * @param cred_counter Output credential counter / account index
 *
 * @throws SWO_WRONG_DATA_LENGTH if lc != 8
 */
void parse_derivation_path_legacy(uint8_t lc,
                                  uint8_t *cdata,
                                  derivation_path_t *path_out,
                                  uint32_t *cred_counter_out);

void harden_derivation_path(derivation_path_t *path);

#endif  // UTIL_DERIVATION_PATH_H
