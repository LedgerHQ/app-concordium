#pragma once

#define P1_SKIP_DISPLAY    0x01
#define P2_SIGN_PUBLIC_KEY 0x01

#define GOVERNANCE_KEY_PATH_LENGTH 5
#define GOVERNANCE_IDENTITY_INDEX  1
#define GOVERNANCE_DISPLAY_MIN_LEN 13

#define PATH_INDEX_IDENTITY_PROVIDER 2
#define PATH_INDEX_IDENTITY          3
#define PATH_INDEX_PURPOSE           3
#define PATH_INDEX_ACCOUNT_NEW      5

#define PATH_INDEX_IDENTITY_LEGACY  4
#define PATH_INDEX_ACCOUNT_LEGACY  6

#define GOV_ROOT_LEN    10
#define GOV_LEVEL_LEN   13

/**
 * Handles the derivation and export of account and governance public keys.
 * @param cdata please see /doc/ins_public_key.md for details
 * @param p1 use 0x00 to let the user validate the export on the screen, and P1_SKIP_DISPLAY
 * to silently export the public-key without user interaction.
 * @param p2 use 0x00 to only export the public-key, and P2_SIGN_PUBLIC_KEY to also
 * export the signature on the public-key signed with the corresponding private-key.
 */
void handleGetPublicKey(uint8_t *cdata,
                        uint8_t p1,
                        uint8_t p2,
                        uint8_t lc,
                        volatile unsigned int *flags);
void sendPublicKey(bool compare);

typedef struct {
    uint8_t display[21];
    char publicKey[68];
    bool signPublicKey;
} exportPublicKeyContext_t;
