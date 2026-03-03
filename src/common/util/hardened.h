/**
 * @file hardened.h
 * @brief Helper functions for setting and clearing the hardened bit
 *        in 32-bit hierarchical deterministic (HD) key derivation indices.
 */

#ifndef HARDENED_H
#define HARDENED_H

#include <stdint.h>

/** Mask for the hardened bit (bit 31) */
#define HARDENED_BIT 0x80000000U

/** Mask for clearing the hardened bit */
#define HARDENED_BIT_CLEAR (~HARDENED_BIT)

/**
 * @brief Set the hardened bit on a 32-bit derivation path part in-place.
 *
 * In BIP32/HD key derivation, the hardened bit indicates that
 * the child key cannot be derived from the parent public key.
 *
 * @param path_part Pointer to the 32-bit value representing a part of the derivation path.
 */
static inline void set_hardened(uint32_t *path_part) {
    *path_part |= HARDENED_BIT;
}

#endif  // HARDENED_H