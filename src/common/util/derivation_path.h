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
/** Last node of 6-segment legacy export path: PRF key vs ID cred sec (values in derivation_path_key_idx_t) */
#define PATH_INDEX_LEGACY_EXPORT_KEY (DERIVATION_PATH_LEGACY_LEN - 1U)
/** Bytes per path element in serialized form (uint32 big-endian) */
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

/** Path indices for full serialized account paths (GET_PUBLIC_KEY / signing) */
#define PATH_INDEX_IDENTITY_PROVIDER 2
#define PATH_INDEX_IDENTITY            3
/** Last node of 5-segment new path: m/44'/coin'/idp'/identity'/account' */
#define PATH_INDEX_ACCOUNT_NEW         4
#define PATH_INDEX_IDENTITY_LEGACY     4
#define PATH_INDEX_ACCOUNT_LEGACY      6

/** Governance subtree (legacy purpose, 5-node path) */
#define GOVERNANCE_KEY_PATH_LENGTH 5
#define GOVERNANCE_IDENTITY_INDEX  1
#define GOVERNANCE_DISPLAY_MIN_LEN   13
#define GOV_ROOT_LEN  10
#define GOV_LEVEL_LEN 13

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
/** Remove the last node from the path */
static inline void trim_last_node(derivation_path_t *derivation_path) {
    derivation_path->len -= 1;
}

/**
 * Parse wire format <depth:u8> <node1:u32be> ... <nodeN:u32be> from a buffer prefix.
 *
 * Validates depth <= DERIVATION_PATH_NODES_MAX and that at least (1 + depth*4) bytes are available.
 * Does not require the buffer to end at the path (use when path is followed by more APDU data).
 *
 * @param max_len              Bytes available starting at cdata
 * @param derivation_path_out  Filled with unhardened nodes; variant set to DERIVATION_PATH_VARIANT_FULL.
 *                             Call detect_derivation_path_variant() after if you need legacy/new classification.
 * @return                     Bytes consumed (1 + depth*4)
 *
 * @throws ERROR_INVALID_PATH if depth or length is invalid
 */
size_t parse_derivation_path_from_buffer(uint8_t *cdata,
                                        size_t max_len,
                                        derivation_path_t *derivation_path_out);

/**
 * Parse full derivation-path format when CDATA is path-only (INS verify address P1_FULL_PATH).
 *
 * Same wire as parse_derivation_path_from_buffer, but enforces lc == bytes consumed (no trailing
 * bytes). Prefer parse_derivation_path_from_buffer when path is only a prefix of cdata.
 *
 * @param lc                   Must equal 1 + n*4 for depth n
 * @throws SWO_WRONG_DATA_LENGTH if lc does not match consumed path length
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
 * Classify a path parsed in full wire format (depth-prefixed BE uint32 nodes, unhardened).
 * Sets variant from the first node's purpose (legacy 1105, new 44, else full/custom).
 */
void detect_derivation_path_variant(derivation_path_t *derivation_path);

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

/** Current-command path buffer; defined in app_main.c (parse / get public key / sign). */
extern derivation_path_t global_derivation_path;

#endif  // UTIL_DERIVATION_PATH_H
