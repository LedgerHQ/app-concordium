/**
 * @file derivation_path.h
 * @brief BIP-32 style derivation path parsing and representation for Concordium.
 */
#ifndef UTIL_DERIVATION_PATH_H
#define UTIL_DERIVATION_PATH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/** Maximum path length (nodes) */
#define DERIVATION_PATH_NODES_MAX 8
/** New path format length (44'/coinType'/idp'/id'/3') */
#define DERIVATION_PATH_NEW_LEN 5
/** Legacy path format length (1105'/0'/0'/0'/identity'/1') */
#define DERIVATION_PATH_LEGACY_LEN 6
/** Bytes per path element in serialized form */
#define BYTES_PER_PATH_ELEMENT U32_BYTES

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
    uint32_t nodes[DERIVATION_PATH_NODES_MAX];
    uint8_t len;
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

/** Initialize an empty derivation path with invalid variant by pointer*/
static inline void init_derivation_path(derivation_path_t *derivation_path) {
    derivation_path->len = 0;
    for (size_t i = 0; i < DERIVATION_PATH_NODES_MAX; i++) {
        derivation_path->nodes[i] = 0;
    }
    derivation_path->variant = DERIVATION_PATH_VARIANT_INVALID;
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
 * Parse full derivation-path format: <n> <node 1> ... <node n>.
 *
 * Byte 0 is depth n, then n nodes (4 bytes each). Last node is cred counter.
 * PRF path = path[0..n-2] with last element replaced by NEW_PRF_KEY.
 *
 * @param lc                   Length of cdata (1 + n*4)
 * @param cdata                APDU command data
 * @param derivation_path_out  Output derivation path (PRF path with NEW_PRF_KEY)
 *
 * @throws SWO_WRONG_DATA_LENGTH if lc invalid
 */
void parse_derivation_path_full(uint8_t lc, uint8_t *cdata, derivation_path_t *derivation_path_out);

/**
 * Parse new path format: identityProvider[uint32] identity[uint32] credCounter[uint32].
 *
 * Builds PRF path 44/coinType/identityProvider/identity/3.
 *
 * @param lc                  Length of cdata (must be 12)
 * @param cdata               APDU command data
 * @param mainnet             true for mainnet (919), false for testnet (1)
 * @param derivation_path_out Output buffer for the 5-element PRF derivation path, not hardened
 * @param cred_counter_out    Output credential counter / account index
 *
 * @throws SWO_WRONG_DATA_LENGTH if lc != 12
 */
void parse_derivation_path_new(uint8_t lc,
                               uint8_t *cdata,
                               bool mainnet,
                               derivation_path_t *derivation_path_out,
                               uint32_t *cred_counter_out);

/**
 * Parse legacy path format: identity[uint32] credCounter[uint32].
 *
 * Builds PRF path 1105'/0'/0'/0'/identity'/1'.
 *
 * @param lc                  Length of cdata (must be 8)
 * @param cdata               APDU command data
 * @param derivation_path_out Output buffer for the 6-element PRF derivation path, not hardened
 * @param cred_counter_out    Output credential counter / account index
 *
 * @throws SWO_WRONG_DATA_LENGTH if lc != 8
 */
void parse_derivation_path_legacy(uint8_t lc,
                                  uint8_t *cdata,
                                  derivation_path_t *derivation_path_out,
                                  uint32_t *cred_counter_out);

/**
 * Apply HARDENED_BIT (0x80000000) to all nodes in the path.
 *
 * Parsers output unhardened nodes; getBlsPrivateKey expects hardened form.
 *
 * @param path Derivation path to harden (modified in place)
 */
static inline void harden_derivation_path(derivation_path_t *derivation_path) {
    for (size_t i = 0; i < derivation_path->len; i++) {
        derivation_path->nodes[i] |= HARDENED_BIT;
    }
}

static inline void unharden_derivation_path(derivation_path_t *derivation_path) {
    for (size_t i = 0; i < derivation_path->len; i++) {
        derivation_path->nodes[i] &= ~HARDENED_BIT;
    }
}

#endif  // UTIL_DERIVATION_PATH_H
