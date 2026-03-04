/**
 * @file derivation_path.h
 * @brief BIP-32 style derivation path parsing and representation for Concordium.
 */
#ifndef UTIL_DERIVATION_PATH_H
#define UTIL_DERIVATION_PATH_H

#include <stdint.h>
#include <stdbool.h>

/** Bytes per path node (big-endian uint32) */
#define KEY_PATH_NODE_BYTES 4
/** Minimum path length (nodes) */
#define MIN_KEY_PATH_LENGTH 4
/** Maximum path length (nodes) */
#define MAX_KEY_PATH_LENGTH 8
/** New path format length (44'/coinType'/idp'/id'/3') */
#define DERIVATION_PATH_NEW_LEN 5
/** Legacy path format length (1105'/0'/0'/0'/identity'/1') */
#define DERIVATION_PATH_LEGACY_LEN 6
/** Bytes per path element in serialized form */
#define BYTES_PER_PATH_ELEMENT 4

/** Legacy purpose (BIP-43) */
#define LEGACY_PURPOSE 1105
/** Legacy coin type */
#define LEGACY_COIN_TYPE 0
/** New path purpose (BIP-44) */
#define NEW_PURPOSE 44
/** Mainnet coin type */
#define NEW_MAINNET_COIN_TYPE 919
/** Testnet coin type */
#define NEW_TESTNET_COIN_TYPE 1

/** Legacy account subtree index */
#define LEGACY_ACCOUNT_SUBTREE 0
/** Legacy normal accounts index */
#define LEGACY_NORMAL_ACCOUNTS 0

/** Mask for the hardened bit (bit 31) */
#define HARDENED_BIT 0x80000000U

/** Derivation path format variant */
typedef enum {
    DERIVATION_PATH_VARIANT_LEGACY,
    DERIVATION_PATH_VARIANT_NEW,
    DERIVATION_PATH_VARIANT_FULL,
    DERIVATION_PATH_VARIANT_INVALID
} derivation_path_variant_t;

/** Derivation path with variable-length nodes and variant */
typedef struct derivation_path {
    uint8_t len;
    uint32_t nodes[MAX_KEY_PATH_LENGTH];
    derivation_path_variant_t variant;
} derivation_path_t;

/** Key indices within derivation path (legacy vs new) */
typedef enum {
    LEGACY_ID_CRED_SEC = 0,
    LEGACY_PRF_KEY = 1,
    // New path
    NEW_ID_CRED_SEC = 2,
    NEW_PRF_KEY = 3,
    NEW_SIGNATURE_BLINDING_RANDOMNESS = 4,
    NEW_COMMITMENT_RANDOMNESS = 5,
} derivation_path_key_idx_t;

/** Initialize an empty derivation path with invalid variant */
static inline derivation_path_t init_derivation_path() {
    derivation_path_t derivation_path = {.len = 0,
                                         .nodes = {0},
                                         .variant = DERIVATION_PATH_VARIANT_INVALID};
    return derivation_path;
}

/** Get cred counter from path (last node, stored at nodes[len]) */
static inline uint32_t cred_counter(derivation_path_t *derivation_path) {
    return derivation_path->nodes[derivation_path->len];
}

/** Remove the last node from the path */
static inline void trim_last_node(derivation_path_t *derivation_path) {
    derivation_path->len -= 1;
}

/**
 * Parse full derivation-path format: n path nodes (4 bytes each), last node is cred counter.
 *
 * CDATA is n*4 bytes. PRF path = path[0..n-2] with last element replaced by NEW_PRF_KEY.
 *
 * @param lc                   Length of cdata (multiple of 4, at most 24)
 * @param cdata                APDU command data
 * @param derivation_path_out  Output derivation path and cred counter
 *
 * @throws SWO_WRONG_DATA_LENGTH if lc invalid
 */
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
 * @param lc               Length of cdata (must be 8)
 * @param cdata            APDU command data
 * @param path_out         Output buffer for the 6-element PRF derivation path, not hardened
 * @param cred_counter_out Output credential counter / account index
 *
 * @throws SWO_WRONG_DATA_LENGTH if lc != 8
 */
void parse_derivation_path_legacy(uint8_t lc,
                                  uint8_t *cdata,
                                  derivation_path_t *path_out,
                                  uint32_t *cred_counter_out);

/**
 * Apply HARDENED_BIT (0x80000000) to all nodes in the path.
 *
 * Parsers output unhardened nodes; getBlsPrivateKey expects hardened form.
 *
 * @param path Derivation path to harden (modified in place)
 */
void harden_derivation_path(derivation_path_t *path);

#endif  // UTIL_DERIVATION_PATH_H
