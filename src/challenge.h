#pragma once

#include <stdint.h>

/** Size of challenge in bytes (uint64_t) */
#define CHALLENGE_SIZE 8

/**
 * Handles GET_CHALLENGE APDU (INS 0x23).
 * Generates a random uint64_t, stores it in memory, and returns it.
 * The challenge can be used only once; each call generates a new challenge.
 * P1=0, P2=0, LC=0. No command data.
 *
 * Output: 8 bytes (random uint64_t, big-endian) + status word.
 */
void handleGetChallenge(void);

/**
 * Erases the stored challenge from memory.
 * MUST be called when the trusted name is loaded.
 */
void eraseChallenge(void);
