#pragma once

#include <stddef.h>
#include <stdint.h>

#include <cx.h>
#include <lcx_hash.h>

#include "derivation_path.h"

/** BLS12-381 subgroup G1's order */
extern const uint8_t BLS_G1_ORDER[32];

/** G1 compressed coordinate / credential id size. */
#define BLS_G1_COORD_SIZE 48

#define ED25519_SIGNATURE_LENGTH      64
#define ED25519_SEED_LENGTH           12
#define ED25519_PUBLIC_KEY_CURVE_SIZE 64
#define ED25519_SIGN_COMPRESSED_BIT   0x80

#define ED25519_EXTENDED_PRIVATE_KEY_LENGTH (2 * KEY_LENGTH)

/** HKDF salt prefix length for BLS keygen ("BLS-SIG-KEYGEN-SALT-" …). */
#define BLS_SALT_INITIAL_LENGTH 20

void get_private_key(const derivation_path_t *path, cx_ecfp_private_key_t *privateKey);

/** Ed25519 private key and chain code for a SLIP-10 path. */
void get_extended_private_key(const derivation_path_t *path,
                              uint8_t *privateKey,
                              size_t privateKeySize,
                              uint8_t *chainCode,
                              size_t chainCodeSize);

/*
 * These two used to read global_derivation_path themselves, which meant an operation could not
 * be bound to a particular path: whoever wrote that global last decided which key was used, and
 * nothing at the call site said so. The path is a parameter so a caller that has shown a path to
 * the user can derive against exactly that one - see global_reviewed_path in tx_state.h.
 */

/**
 * Public key for `path` (32 bytes, Concordium format).
 */
void get_public_key(const derivation_path_t *path, uint8_t *publicKeyArray);

/** Ed25519 sign over a KEY_LENGTH-byte message with the key at `path`. */
void sign(const derivation_path_t *path, uint8_t *input, uint8_t *signatureOnInput);

void hash(cx_hash_t *hash,
          uint32_t mode,
          const unsigned char *in,
          unsigned int len,
          unsigned char *out,
          unsigned int out_len);

void update_hash(cx_hash_t *hash, const unsigned char *in, unsigned int len);

/** BLS12-381 private key from Ed25519 seed at path (HKDF keygen). */
void get_bls_private_key(const derivation_path_t *path, uint8_t *privateKey, size_t privateKeySize);
