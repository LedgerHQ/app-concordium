#pragma once

#include <parser.h>

#define P1_SKIP_DISPLAY    0x01
#define P2_SIGN_PUBLIC_KEY 0x01

/**
 * Handles the derivation and export of account and governance public keys.
 * Command data: see /doc/ins_public_key.md. P1: use 0x00 to let the user validate the export on
 * the screen, and P1_SKIP_DISPLAY to silently export the public-key without user interaction.
 * P2: use 0x00 to only export the public-key, and P2_SIGN_PUBLIC_KEY to also export the signature
 * on the public-key signed with the corresponding private-key.
 */
void handleGetPublicKey(const command_t *cmd, volatile unsigned int *flags);
void sendPublicKey(bool compare);

typedef struct {
    uint8_t display[21];
    char publicKey[68];
    bool signPublicKey;
} exportPublicKeyContext_t;
